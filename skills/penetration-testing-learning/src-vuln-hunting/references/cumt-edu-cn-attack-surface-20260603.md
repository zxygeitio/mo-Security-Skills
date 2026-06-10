# cumt.edu.cn 中国矿业大学 攻击面与安全态势

## 测试日期: 2026-06-03

## 基本信息
- 域名: cumt.edu.cn
- 子域名: ~200个 (subfinder)
- 关键存活子域: authserver, portal, lib, mail, ai, iot, faculty, nic, zs, xxgk, ctf, jwb, jw, gms等
- 负载均衡: F5 BigIP (authserver, portal, background)
- WAF: 通用WAF检测(连接层阻断)
- DNS: 198.18.0.217/220 (CDN/Proxy)

## 技术栈
| 子域 | 技术 |
|------|------|
| www.cumt.edu.cn | VWebServer/6.0.0 (博达CMS), CustomerNO: 77656262657232307764475c50515742000000034e56 |
| authserver.cumt.edu.cn | wisedu CAS (金智教育), cumtcusTheme_20250616 |
| portal.cumt.edu.cn | Drupal 10 + PHP/8.1.6 |
| lib.cumt.edu.cn | VWebServer/6.0.0 (博达CMS) + DWR |
| mail.cumt.edu.cn | Wwebsvr (腾讯企业邮箱) |
| faculty.cumt.edu.cn | China Webber /1.1 |
| ctf.cumt.edu.cn | nginx/1.26.3 + SolidJS SPA (Reverier-Xu CTF平台) |
| iot.cumt.edu.cn | nginx + SUDY CMS (矿山物联网) |
| ai.cumt.edu.cn | VWebServer/6.0.0 (博达CMS, 静态站) |
| gms.cumt.edu.cn | nginx (默认页, CSP: connect-src *) |
| background.cumt.edu.cn | nginx + BigIP (/taskcenter任务管理系统) |
| app.cumt.edu.cn | nginx (403 Forbidden) |
| sudy.cumt.edu.cn | nginx (404) |

## 已确认漏洞
1. **portal.cumt.edu.cn CORS配置错误(中危)**: 全站反射任意Origin + Credentials:true。Drupal 10 cors.config误配。所有端点(/admin, /jsonapi, /node/*, /user/*)均受影响。
2. **lib.cumt.edu.cn DWR文件泄露(低危)**: /_dwr/engine.js + util.js可访问，暴露技术栈。DWR servlet端点不可用。
3. **www.cumt.edu.cn CSP泄露内网IP(低危)**: CSP头中包含 219.219.51.168:8422、iknow.cumt.edu.cn、ssfwrx.cumt.edu.cn。

## CAS安全态势(加固良好)
- 3次错误密码后锁定 (_badCredentialsCount=3)
- 验证码强制开启 (captchaSwitch=1)
- FIDO认证支持 (_fidoEnabled=true)
- 动态码登录 (is_dynamicLogin=true)
- QR码登录 (isQrLoginEnabled=true)
- Service参数白名单校验 (未注册应用返回"应用未注册"200页面)
- 无pwdDefaultEncryptSalt泄露
- CAPTCHA接口返回HTML而非图片(可能需要session)

## 负面验证结果(不建议提交)
- CAS开放重定向: service参数白名单校验，evil.com被拒绝
- CAS用户枚举: 所有用户名均触发验证码，无差异响应
- background.cumt.edu.cn swagger-ui.html: SPA fallback假阳性(200→404)
- datainput.jsp: 返回空响应(200:0)，无SQL注入证据
- 博达CMS已知漏洞路径: 均返回404，系统已加固
- Drupal install.php: 仅显示"Drupal已安装完毕"，无可利用功能
- Drupal settings.php备份: 全部000(连接失败)
- Drupal JSONAPI: 需CAS认证，未认证时302重定向
- lib.cumt.edu.cn DWR servlet: 全部404
- 其他子域CORS: 仅portal有CORS反射

## CSP信息
```
Content-Security-Policy: default-src 'self' data: blob: *.conac.cn *.jiathis.com *.baidu.com *.bshare.cn *.edu.cn *.qq.com *.kaipuyun.cn 'unsafe-inline' 'unsafe-eval';
frame-ancestors 'self' http://219.219.51.168:8422 https://iknow.cumt.edu.cn https://ssfwrx.cumt.edu.cn
```

## CAS JS变量(来自authserver登录页)
```javascript
var serverPrefix = "https://authserver.cumt.edu.cn/authserver";
var captchaSwitch = "1";
var _badCredentialsCount = "3";
var isQrLoginEnabled = "true";
var _fidoEnabled = "true";
var is_dynamicLogin = "true";
var is_userNameLogin = "true";
var contextPath = "/authserver";
```
