# 广西师范大学 (gxnu.edu.cn) 测试模式 — 2026-06-09

## 目标概况

- 域名：gxnu.edu.cn
- 地址：广西壮族自治区桂林市七星区育才路15号
- 子域名数量：108+

## 关键系统

| 子域名 | 系统 | 技术栈 | 认证方式 |
|--------|------|--------|----------|
| sso.gxnu.edu.cn | CAS统一认证 | 自研CAS（非金智） | - |
| ehall.gxnu.edu.cn | 办事大厅 | 金智教育(wisedu) amp | CAS→amp-auth-adapter |
| webvpn.gxnu.edu.cn | WebVPN | 自研 | 独立 |
| mail.gxnu.edu.cn | 邮箱 | 网易企业邮箱 | 独立 |
| office.gxnu.edu.cn | 校长办公室 | SUDY CMS | CAS |
| hr.gxnu.edu.cn | 人事处 | SUDY CMS | CAS |
| idp.gxnu.edu.cn | IdP | Shibboleth | 独立 |
| yzcx.gxnu.edu.cn | 研究生招生网 | ASP.NET Core | 独立 |
| dms.gxnu.edu.cn | 学工平台 | Angular | 独立 |
| ydjk.gxnu.edu.cn | 一卡通 | ECMS v3.1.0 | 独立 |
| aieval.gxnu.edu.cn | AI测评系统 | Vue.js | 独立 |
| daly.gxnu.edu.cn | 远程利用 | Vue.js | 独立 |

## 已验证漏洞

### 1. ehall应用配置信息未授权访问（中危）

**漏洞位置**：http://ehall.gxnu.edu.cn/jsonp/appInfo.json

**泄露内容**：
- 应用ID：4834312099124186
- 应用密钥：4834312099124186-4.0.11_TR1
- 域ID：8888429c-73bd-4c3d-b8cb-a74c18a9e376
- 部署路径：http://ehall.gxnu.edu.cn/xsfw
- 供应商：金智教育
- 版本：4.0.11_TR1

**PoC**：
```bash
curl -sk 'http://ehall.gxnu.edu.cn/jsonp/appInfo.json?appId=4834312099124186'
curl -sk 'http://ehall.gxnu.edu.cn/jsonp/appIntroduction.json?appId=4834312099124186'
```

### 2. CAS CORS配置不当（中危）

**漏洞位置**：https://sso.gxnu.edu.cn/cas/login

**问题**：access-control-allow-origin: * + access-control-allow-credentials: true

**PoC**：
```bash
curl -sk -D- 'https://sso.gxnu.edu.cn/cas/login' | grep -i access-control
```

**受影响端点**：
- /cas/login
- /cas/logout
- /cas/serviceValidate

### 3. Shibboleth IdP SAML元数据泄露（低危）

**泄露内容**：entityID、X.509证书、Scope

**PoC**：
```bash
curl -sk 'https://idp.gxnu.edu.cn/idp/shibboleth'
```

### 4. 研究生招生网错误信息泄露（低危）

**漏洞位置**：https://yzcx.gxnu.edu.cn/noteInfo?id=1

**泄露内容**：.NET错误堆栈信息

**PoC**：
```bash
curl -sk 'https://yzcx.gxnu.edu.cn/noteInfo?id=1'
```

## ehall金智教育平台

- schoolId：10602
- authserverUrl：http://authlab.wisedu.com/authserver/index.do
- 认证流程：CAS→amp-auth-adapter→ehall
- sessionToken：随机生成，32位hex

**API端点（需认证）**：
- /publicapp/userInfoApp/getUserInfo.do
- /publicapp/scoreApp/getScore.do
- /publicapp/examApp/getExam.do
- /publicapp/libraryApp/getBorrowInfo.do
- /publicapp/cardApp/getCardInfo.do

**JSONP端点（无需认证）**：
- /jsonp/school.json
- /jsonp/userInfo.json
- /jsonp/serviceCenterData.json
- /jsonp/appInfo.json?appId=xxx

## 研究生招生网 (yzcx.gxnu.edu.cn)

- 技术栈：ASP.NET Core + Layui
- 功能：登录、注册、成绩查询、密码找回、通知公告
- 验证码：图片验证码
- 注册条件：准考证号+姓名+身份证号

**端点**：
- /Login - 登录
- /Register/Index - 非推免生注册
- /Register/forgetPwd - 密码找回
- /Search/ScoreInfo - 成绩查询
- /noteInfo?id=1-14 - 通知公告

## 学工平台 (dms.gxnu.edu.cn)

- 技术栈：Angular
- JS文件中包含password:"123456"（可能是默认密码）

## SUDY CMS网站群

多个部门网站使用SUDY CMS：
- office.gxnu.edu.cn（校长办公室）
- hr.gxnu.edu.cn（人事处）
- jjc.gxnu.edu.cn（基建处）
- tzb.gxnu.edu.cn（统战部）
- bwc.gxnu.edu.cn（保卫处）

**管理后台**：/_wp3services/general498/index.jsp（需CAS认证）

## 安全防护

- WAF：拦截敏感路径（Actuator/Swagger/Druid等）
- CAS：service参数白名单验证（接受包含gxnu.edu.cn的域名）
- 验证码：图片验证码防自动化
- 速率限制：CAS登录接口限制请求频率

## 测试建议

1. 使用OCR识别验证码后进行研究生招生网用户枚举
2. 测试CAS认证逻辑漏洞
3. 测试SUDY CMS已知漏洞
4. 测试学工平台默认密码
5. 测试一卡通系统API接口
