# 教育系统指纹识别补充 (2026-06-09)

## 长春理工大学 (cust.edu.cn) 技术栈

### 认证系统
- **CAS**: mysso.cust.edu.cn/cas/login — 自研CAS，非金智/联奕
- **wengine-auth**: wwun.cust.edu.cn/wengine-auth/login — 网瑞达资源访问控制系统
  - 指纹: Server: none, Set-Cookie: wengine_new_ticket, 关键词"网瑞达/WEBVPN/资源访问控制系统"
  - 认证流程: wengine-auth → CAS → wengine-auth callback → 业务系统
  - 保护的系统: ehall(jwgl.id=104), 教务(id=15), 图书馆等

### 子域名布局 (150个)
- mysso.cust.edu.cn — CAS统一认证
- ehall.cust.edu.cn — 办事大厅 (wengine-auth保护)
- jwgl.cust.edu.cn — 教务管理 (wengine-auth保护, 路径: /jwgl/, /jwglxt/, /jsxsd/, /eams/)
- mail.cust.edu.cn — 腾讯企业邮箱 (Server: Wwebsvr)
- lib.cust.edu.cn — 图书馆 (SUDY CMS)
- job.cust.edu.cn — 就业信息网 (JEECMS v9, /r/cms/)
- yzb.cust.edu.cn — 研究生招生网 (自研, 有成绩查询)
- ecard.cust.edu.cn — 一卡通
- rsc.cust.edu.cn — 人事处 (博达网站群)

### 微信集成
- CAS登录页面嵌入微信OAuth: appid=wx9d23c9b82a4ba0a9
- 微信登录重定向: clientredirect;jsessionid=xxx?client_name=WeChatPublic&service=...

## 广西师范大学 (gxnu.edu.cn) 技术栈

### 认证系统
- **CAS**: sso.gxnu.edu.cn/cas/login — 自研CAS（非金智教育）
  - 特征: 统一身份认证平台, execution token, 验证码
  - 速率限制: "请求过于频繁，请稍后再试" (too_many_requests)
  - 错误消息: "用户名或密码错误" (统一，无用户枚举)

### ehall
- ehall.gxnu.edu.cn — 金智教育(wisedu)平台
- schoolId: 10602, authserverUrl: http://authlab.wisedu.com/authserver/index.do
- 未授权API: /jsonp/appInfo.json?appId=xxx (泄露密钥/域ID/内部路径)

### 子域名布局 (108个)
- sso/ehall/webvpn/mail/office/hr/idp/rczp(Tomcat7.0.100)/ydjk(ECMS)/dms(学工)/aieval(AI测评)/daly(远程利用)/gxnulb(图书馆)/csxy/jwjx(超星教务)

## wengine-auth (网瑞达) 指纹
- Server: none, Cookie: wengine_new_ticket
- 关键词: WEBVPN, 网瑞达, 北京网瑞达科技有限公司, 资源访问控制系统
- 登录: /wengine-auth/login?id=N&path=/&from=TARGET_URL
- 错误页面: /wengine-auth-failed.png

## JEECMS v9指纹
- 路径: /r/cms/, 管理后台: /admin/login
- 版本泄露: jeecmsv9f, 404页面含data-genuitec-path
