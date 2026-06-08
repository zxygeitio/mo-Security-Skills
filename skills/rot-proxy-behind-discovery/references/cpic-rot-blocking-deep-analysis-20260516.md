# ROT代理443端口完全阻断深度分析 (2026-05-16)

## 现象描述

新IP段(101.204/101.207/103.144/103.230/182.150)的ROT代理443端口表现与58段/116段不同：

| 行为 | 58段ROT | 新段ROT |
|------|---------|---------|
| TCP连接 | ✅ 建立 | ✅ 建立 |
| TLS握手 | ✅ 成功 | ✅ 成功 |
| 证书获取 | ✅ 正常 | ✅ 正常 |
| HTTP响应 | ❌ 超时 | ❌ 超时 |
| 响应时间 | <1s | >10s超时 |

## curl行为对比

### 101段ROT (mcdsit.cdgslb.cpic.com.cn)
```bash
$ curl -skI --resolve "mcdsit.cdgslb.cpic.com.cn:443:101.204.252.25" \
  "https://mcdsit.cdgslb.cpic.com.cn/"
# TLS握手成功，发送请求后挂起10秒，0字节响应，超时
```

### 103段ROT (activityflatform.gtm.cpic.com.cn)
```bash
$ curl -skI "https://activityflatform.gtm.cpic.com.cn/"
# 相同行为：TLS握手成功，HTTP请求无响应
```

### 58段ROT (service.cpic.com.cn) - 对比
```bash
$ curl -skI "https://58.246.171.102/"
# HTTP/1.1 302/403/502 等正常响应
```

## OpenSSL行为

```bash
# 新段ROT - 证书读取成功但无HTTP响应
$ openssl s_client -connect 101.204.252.25:443 \
  -servername mcdsit.cdgslb.cpic.com.cn
CONNECTED(00000003)
Certificate chain
 0 s:O=ROT Proxy, CN=mcdsit.cdgslb.cpic.com.cn
   i:C=ROT Proxy, CN=rot.proxy
# 发送GET /后：无声，无响应，连接保持

# 58段ROT - 正常HTTP响应
$ openssl s_client -connect 58.246.171.102:443 -servername service.cpic.com.cn
CONNECTED(00000003)
# 正常HTTP/1.1响应
```

## 证书有效期异常

101段的ROT证书有效期仅2小时（动态签发）：
```
NotBefore: May 16 08:00:35 2026 GMT
NotAfter:  May 16 10:00:35 2026 GMT  ← 2小时有效期
```

58段ROT证书通常是长期证书（数年）。

## nmap服务探测

```bash
$ nmap -Pn -sT -sV -p 443 101.204.252.25
PORT    STATE  SERVICE
443/tcp open   https

# -sV 版本探测超时，无法确定服务
```

TCP SYN扫描能发现443开放，但TLS应用层探测全部超时。

## 可能的解释

1. **后端服务器离线**：ROT代理节点正常，但指向的后端服务未运行
2. **代理配置错误**：新段ROT配置了但未激活后端路由
3. **连接限流**：新段ROT对VPN连接有连接数限制
4. **证书吊销/过期**：动态证书在签发后迅速失效

## 探测脚本

```python
#!/usr/bin/env python3
"""探测ROT代理443端口后端是否在线"""
import socket, ssl, sys

def probe_rot_backend(ip, hostname, timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.create_connection((ip, 443), timeout=timeout)
        ss = ctx.wrap_socket(s, server_hostname=hostname)
        ss.sendall(f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        ss.settimeout(timeout)
        while True:
            try:
                chunk = ss.recv(4096)
                if not chunk: break
                data += chunk
            except socket.timeout: break
        ss.close()
        return len(data), data[:200]
    except Exception as e:
        return -1, str(e)

# 使用
size, resp = probe_rot_backend("101.204.252.25", "mcdsit.cdgslb.cpic.com.cn")
if size == 0:
    print("⚠️ ROT代理后端无响应（可能离线或配置错误）")
elif size > 0:
    print(f"✅ 获取到响应: {size} bytes")
else:
    print(f"❌ 连接失败: {resp}")
```

## 结论

新IP段ROT代理443端口被完全阻断，无任何HTTP响应。这与58段ROT能返回502/403等正常HTTP响应形成鲜明对比。

**攻击价值**：无响应 = 无法进行漏洞测试。需要寻找非443端口或使用其他接入方式（如VPN客户端证书）。
