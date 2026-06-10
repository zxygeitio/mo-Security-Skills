# IP泄露验证方法论

## 背景

在SRC/渗透测试中，经常发现Web应用泄露IP地址的情况。但泄露的IP不一定是真实服务器IP，可能是CDN/WAF基础设施的IP。错误报告CDN IP会被审核员拒绝。

## 验证流程

### Step 1: DNS解析对比
```bash
nslookup <domain>
# 或
dig <domain> A +short
```
- 如果域名解析到198.18.x.x、198.19.x.x等网段，通常是CDN
- 如果泄露IP与解析IP在同一网段，可能是真实IP
- 如果泄露IP与解析IP完全不同，需要进一步验证

### Step 2: IP地理位置和ISP查询
```bash
curl -sk "http://ip-api.com/json/<IP>"
```
- CDN提供商特征：Alice Networks、Cloudflare、Akamai、Fastly等
- 香港/海外IP通常是CDN节点
- 国内教育网IP更可能是真实服务器

### Step 3: 直接访问验证
```bash
curl -sk -H "Host: <domain>" http://<IP>/
curl -sk -H "Host: <domain>" https://<IP>/
```
- 如果返回真实网站内容，可能是真实IP
- 如果返回空、错误页面或WAF拦截页面，可能是CDN IP

### Step 4: 端口服务分析
```bash
nmap -sT -p 1-1000 <IP>
# 或
for port in 53 1080 3128 8080 8118 9050; do
  timeout 3 bash -c "echo '' > /dev/tcp/<IP>/$port" 2>/dev/null && echo "$port 开放"
done
```
- DNS(53)端口开放：可能是CDN DNS服务器
- 代理端口(1080/3128/8080/8118/9050)开放：可能是CDN代理节点
- Web端口(80/443)开放且返回真实内容：可能是真实IP

### Step 5: DNS服务器测试
```bash
dig @<泄露IP> <domain> A +short
dig @<泄露IP> <domain> NS
```
- 如果泄露IP是DNS服务器且返回CDN网段IP，确认为CDN基础设施

## 判断标准

### 真实服务器IP特征
- 域名解析IP与泄露IP在同一网段
- 直接访问返回真实网站内容
- 没有CDN/WAF特征端口
- ISP为教育网/国内IDC

### CDN/WAF IP特征
- 域名解析到CDN网段(198.18.x.x等)
- 泄露IP位于香港/海外
- ISP为CDN提供商
- 开放DNS/代理端口
- 直接访问返回空或WAF拦截

## 报告处理

- 确认为真实服务器IP：正常报告，中危
- 确认为CDN/WAF IP：降级为低危或信息，注明"非真实服务器IP"
- 无法确认：报告为"待验证"，提供验证步骤供审核员确认

## 实战案例

### NJMU KDC (2026-06-09)
- SUDY CMS泄露IP: 109.122.3.227
- DNS解析: kdc.njmu.edu.cn → 198.18.0.205 (CDN网段)
- IP查询: 香港Alice Networks LTD
- 端口扫描: 开放53(DNS)/1080(SOCKS)/3128(HTTP)/8080(HTTP)/8118(HTTP)/9050(TOR)
- 结论: CDN DNS服务器IP，非真实服务器IP
- 处理: 降级为低危，报告中注明
