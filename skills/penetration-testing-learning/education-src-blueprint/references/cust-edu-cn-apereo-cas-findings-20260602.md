# cust.edu.cn (长春理工大学) Apereo CAS + PAC4J 测试记录

## 测试日期: 2026-06-02

## 目标概况
- 主站: www.cust.edu.cn (nginx, jQuery 3.7.1)
- CAS: mysso.cust.edu.cn/cas/login (Apereo CAS + PAC4J)
- 致远OA: 121.37.5.226:8090 (A6 V8.0SP2, Server: SY8045)
- VPN: vpn.cust.edu.cn (Astraeus VPN)
- WebVPN: wwwn.cust.edu.cn (网瑞达)
- ehall: ehall.cust.edu.cn (金智教育, behind wengine-auth)
- 200+子域(subfinder)

## 关键发现

### 1. CAS Open Redirect (中危, 已提交)
- mysso.cust.edu.cn/cas/serviceValidate 返回 INVALID_TICKET (公开)
- service参数无白名单校验，接受任意外部域名
- 登录后用户被重定向到攻击者域名并携带CAS ticket
- **对比**: 金智CAS有service白名单校验，Apereo+PAC4J无白名单

### 2. WeChat AppID泄露 (低危)
- wxeded6858b612a557 (WeChat Public)
- wx9d23c9b82a4ba0a9 (WeChat)

### 3. 致远OA暴露 (低危)
- 121.37.5.226:8090, V8.0SP2
- CORS: Access-Control-Allow-Origin: * + Credentials: true
- REST API需认证(返回 "被迫下线，原因：与服务器失去连接")
- JSESSIONID URL泄露

### 4. 内网IP泄露 (低危)
- test.cust.edu.cn -> 192.168.230.117
- ecard.cust.edu.cn -> 192.168.222.176

### 5. 博达CMS (ic.cust.edu.cn)
- 搜索/DWR接口返回404
- jQuery 1.7.2 (ai.cust.edu.cn)

## 不建议提交
- CAS JSESSIONID URL泄露 (黑名单)
- 致远OA CORS (API需认证)
- WeChat AppID泄露 (公开设计)
- 内网IP泄露 (低价值)

## 测试命令
```bash
# CAS Open Redirect验证
curl -sk "https://mysso.cust.edu.cn/cas/login?service=https://evil.com/" | grep -oE 'service=[^"'"'"' ]+evil[^"'"'"' ]*'

# CAS serviceValidate
curl -sk "https://mysso.cust.edu.cn/cas/serviceValidate?service=https://portal.cust.edu.cn/custp/shiro-cas&ticket=ST-FAKE"

# 致远OA CORS
curl -sk -D- "http://121.37.5.226:8090/seeyon/rest/session/invalid" -H "Origin: https://evil.com" | grep -i access-control
```
