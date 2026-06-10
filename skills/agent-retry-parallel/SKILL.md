---
name: agent-retry-parallel
description: 通用Agent重试和并行执行框架 - 指数退避重试、并发控制、任务队列
---

# Agent Retry & Parallel Framework

通用Agent重试和并行执行框架，适用于任何Python Agent系统。

## 核心组件

### 1. @retry 装饰器
指数退避重试机制，防止Agent执行时因瞬时故障失败。

```python
from functools import wraps
import time

def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """重试装饰器 - 指数退避"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            current_delay = delay
            last_error = None
            
            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    attempt += 1
                    if attempt < max_attempts:
                        time.sleep(current_delay)
                        current_delay *= backoff
            raise last_error
        return wrapper
    return decorator

# 使用示例
@retry(max_attempts=3, delay=1.0)
def fetch_data(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.json()
```

### 2. ParallelExecutor 并行执行器
批量任务并行执行，限制并发数避免资源耗尽。

```python
import threading
import queue

class ParallelExecutor:
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
    
    def execute(self, tasks: list, func: callable) -> list:
        results = []
        task_queue = queue.Queue()
        result_queue = queue.Queue()
        
        for task in tasks:
            task_queue.put(task)
        
        def worker():
            while True:
                try:
                    task = task_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    result = func(task)
                    result_queue.put(('success', result))
                except Exception as e:
                    result_queue.put(('error', str(e)))
                finally:
                    task_queue.task_done()
        
        threads = []
        for _ in range(min(self.max_workers, len(tasks))):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        while not result_queue.empty():
            status, data = result_queue.get()
            if status == 'success':
                results.append(data)
        
        return results

# 使用示例
executor = ParallelExecutor(max_workers=4)
tasks = [{'host': f'10.0.0.{i}'} for i in range(100)]
results = executor.execute(tasks, scan_port)
```

### 3. AgentBase 基类
整合重试和并行能力的Agent基类。

```python
class AgentBase:
    def __init__(self, name: str, config: dict = None):
        self.name = name
        self.config = config or {}
        self.results = {}
        self.max_retries = self.config.get('max_retries', 3)
    
    @retry(max_attempts=3, delay=1.0)
    def run_command(self, cmd: list, timeout: int = 60) -> dict:
        import subprocess
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return {
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    
    def execute(self, task: dict) -> dict:
        raise NotImplementedError
```

## 完整示例

```python
#!/usr/bin/env python3
"""通用Agent框架示例"""
import threading
import queue
import time
from functools import wraps

def retry(max_attempts=3, delay=1.0, backoff=2.0):
    decorator = lambda f: (lambda func: wraps(func)(lambda *a, **k: _retry_impl(func, max_attempts, delay, backoff)))
    return decorator

def _retry_impl(func, max_attempts, delay, backoff):
    def wrapper(*args, **kwargs):
        attempt, current_delay = 0, delay
        while attempt < max_attempts:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                attempt += 1
                if attempt >= max_attempts:
                    raise
                time.sleep(current_delay)
                current_delay *= backoff
    return wrapper

class ParallelExecutor:
    def __init__(self, max_workers=4):
        self.max_workers = max_workers
    
    def execute(self, tasks, func):
        results, tq, rq = [], queue.Queue(), queue.Queue()
        for t in tasks: tq.put(t)
        
        def worker():
            while True:
                try:
                    task = tq.get_nowait()
                except queue.Empty:
                    break
                try:
                    rq.put(('ok', func(task)))
                except Exception as e:
                    rq.put(('err', str(e)))
                finally:
                    tq.task_done()
        
        threads = [threading.Thread(target=worker) for _ in range(min(self.max_workers, len(tasks)))]
        for t in threads: t.start()
        for t in threads: t.join()
        
        while not rq.empty():
            status, data = rq.get()
            if status == 'ok': results.append(data)
        return results

# 使用
executor = ParallelExecutor(max_workers=4)
results = executor.execute([{'i': i} for i in range(10)], lambda t: t['i']**2)
print(results)  # [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]
```

## 适用场景
- 网络请求不稳定时的数据采集
- 大批量端口扫描
- 多目标漏洞检测
- 任何可能瞬时失败的IO操作

## 注意事项
- max_workers不宜过大，建议4-8
- timeout要合理设置
- 重试次数过多可能影响性能
