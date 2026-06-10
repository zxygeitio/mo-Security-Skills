# NJMU IP泄露深度验证 (2026-06-09)

## 泄露IP真相

泄露IP 109.122.3.227 **不是**真实服务器IP，而是CDN/WAF的DNS服务器。

### 验证过程
```
# 1. 域名解析对比
nslookup kdc.njmu.edu.cn → 198.18.0.205 (CDN IP)
泄露IP: 109.122.3.227 (不匹配)

# 2. DNS服务器测试
dig @109.122.3.227 kdc.njmu.edu.cn → 198.18.0.205 ✓ (是DNS服务器)
dig @109.122.3.227 google.com → 198.18.1.198 (支持递归查询)

# 3. IP地理位置
curl -sk "http://ip-api.com/json/109.122.3.227"
→ 香港, Alice Networks LTD, AS214661

# 4. Web服务测试
curl -sk http://109.122.3.227/ → 301 (WAF响应)
curl -sk https://109.122.3.227/ → 空响应
```

### 结论
- 109.122.3.227 是CDN/WAF的DNS服务器，不是真实服务器
- 攻击者无法通过该IP直接访问服务器
- IP泄露漏洞从中危降为低危
- 该IP支持DNS递归查询，放大系数约10.5倍（低危）

### DNS服务特征
- 支持递归查询（可查询外部域名）
- 不支持DNS区域传输
- 不支持DNS动态更新
- 无版本信息泄露
- TTL=1（缓存时间极短）
- 放大系数: ANY查询 48字节→506字节 (约10.5倍)

## 所有域名解析到CDN网段
```
kdc.njmu.edu.cn → 198.18.0.205
www.njmu.edu.cn → 198.18.1.159
mail.njmu.edu.cn → 198.18.1.160
oa.njmu.edu.cn → 198.18.1.161
webvpn.njmu.edu.cn → 198.18.1.162
authserver.nmukd.edu.cn → 198.18.0.210
ehall.nmukd.edu.cn → 198.18.0.209
```
所有域名都解析到198.18.x.x网段，这是CDN/WAF的IP网段。

## 教训
IP泄露漏洞必须验证IP身份，不能直接假设是真实服务器IP。
验证步骤: nslookup对比 → DNS服务器测试 → whois查询 → Web服务测试
