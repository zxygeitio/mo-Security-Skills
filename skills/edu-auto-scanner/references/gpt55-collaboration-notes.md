# GPT-5.5协作升级记录 (2026-06-02)

## 协作方式
通过Python直连GPT-5.5 API (https://moxinggang.cn/v1) 并行生成升级组件。
delegate_task的model override不生效，需直接用Python调用API。

## 新增组件

### 1. extra-fingerprints.json (10产品×4路径=40漏洞路径)
- 用友U8/NC, 金蝶云星空, 蓝凌OA, 通达OA, 浪潮GS
- 正方教务, 强智教务, 青果教务, 金智教育Wisedu, 树维教务

### 2. extra-js-rules.json (10条高价值规则)
- 阿里云AccessKey(LTAI), 腾讯云SecretId(AKID), 华为云AK
- 钉钉Webhook, 企业微信Webhook
- SMTP密码, MySQL/Redis/MongoDB连接串, JWT签名密钥

### 3. edu-batch-probe-v2.py (高性能版本)
- socket.getaddrinfo替代dig
- http.client替代curl子进程
- JSON结果缓存

## GPT-5.5调用模板
```python
import yaml, json, urllib.request, ssl
with open('/root/.hermes/config.yaml') as f:
    cfg = yaml.safe_load(f)
gpt = [p for p in cfg.get('custom_providers', []) if p.get('name') == 'gpt-5.5'][0]
url = gpt['base_url'] + '/chat/completions'
key = gpt['api_key']
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
data = json.dumps({'model': 'gpt-5.5', 'messages': [{'role': 'user', 'content': prompt}], 'max_tokens': 4000}).encode()
req = urllib.request.Request(url, data=data, headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'})
resp = urllib.request.urlopen(req, context=ctx, timeout=120)
result = json.loads(resp.read())
reply = result['choices'][0]['message']['content']
```
