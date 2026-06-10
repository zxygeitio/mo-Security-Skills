# GPT-5.5 直接API调用模式 (2026-06-02)

## 问题
delegate_task的model override参数不生效，总是用默认provider。
hermes chat -m "custom:gpt-5.5" 也报错(OpenRouter key缺失)。

## 解决方案
直接用Python urllib调用custom provider API。

## 调用模板
```python
import yaml, json, urllib.request, ssl, time

with open('/root/.hermes/config.yaml') as f:
    cfg = yaml.safe_load(f)

gpt = [p for p in cfg.get('custom_providers', []) if p.get('name') == 'gpt-5.5'][0]
api_url = gpt['base_url'] + '/chat/completions'
key = gpt['api_key']
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def ask_gpt(prompt, max_tokens=8000, retries=3):
    for attempt in range(retries):
        try:
            data = json.dumps({
                'model': 'gpt-5.5',
                'messages': [{'role': 'user', 'content': prompt}],
                'max_tokens': max_tokens,
                'temperature': 0.2
            }).encode()
            req = urllib.request.Request(api_url, data=data, headers={
                'Authorization': f'Bearer {key}',
                'Content-Type': 'application/json'
            })
            resp = urllib.request.urlopen(req, context=ctx, timeout=120)
            return json.loads(resp.read())['choices'][0]['message']['content']
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(5)
            else:
                raise

def extract_code(reply):
    if '```python' in reply:
        return reply.split('```python')[1].split('```')[0]
    elif '```' in reply:
        return reply.split('```')[1].split('```')[0]
    return reply
```

## 并行模式
```python
import threading
results = {}
errors = {}

def gen_module(name, prompt, filename):
    try:
        reply = ask_gpt(prompt, 10000)
        code = extract_code(reply)
        compile(code, '<string>', 'exec')
        with open(filename, 'w') as f:
            f.write(code.strip() + '\n')
        results[name] = f'OK ({len(code)} chars)'
    except Exception as e:
        errors[name] = str(e)

threads = [
    threading.Thread(target=gen_module, args=('task1', prompt1, 'output1.py')),
    threading.Thread(target=gen_module, args=('task2', prompt2, 'output2.py')),
]
for t in threads: t.start()
for t in threads: t.join(timeout=200)
```

## 注意事项
- API连接不稳定，必须加重试(retries=3, sleep=5)
- 代码生成后必须compile()验证语法
- GPT生成的正则表达式可能有引号转义问题，需要人工检查
- 并行3-5个任务是上限，太多会API限流
