# ABP Framework (ASP.NET Boilerplate) Vulnerability Testing

## Fingerprinting

ABP Framework apps expose specific JS/CSS paths:
```
/lib/abp-web-resources/Abp/Framework/scripts/abp.min.js
/lib/abp-web-resources/Abp/Framework/scripts/abp.js
```

Check for version info in the JS file:
```bash
curl -s https://target/lib/abp-web-resources/Abp/Framework/scripts/abp.min.js | grep -oE 'version[" ":=]+["\x27][^\"]*'
```

## API Endpoint Discovery

ABP exposes structured API endpoints under `/api/services/app/{ServiceName}/{MethodName}`.

### Standard ABP Endpoints
```
/api/abp/application-configuration    # App config (may leak settings, auth config)
/api/abp/application-localization     # Localization data
/AbpUserConfiguration/GetAll          # User configuration
/AbpServiceProxies/GetAll             # Service proxy definitions (lists ALL API methods)
/AbpServiceProxyScript/GetAll         # Service proxy JS
/TenantCustomization/GetActiveThemeCss # Theme config
/swagger/index.html                    # Swagger UI
/swagger/v1/swagger.json               # OpenAPI spec
```

### Finding API Endpoints from Frontend JS
ABP apps typically have per-view JS files under:
```
/view-resources/Views/{Controller}/{Action}.min.js
/view-resources/Views/{Controller}/{Action}.js
```

Extract API calls:
```bash
curl -s https://target/view-resources/Views/Home/Index.min.js | grep -oE 'api/services/app/[A-Za-z/]+'
```

## Unauthenticated API Access Detection

ABP API responses explicitly indicate auth status:
```json
{"result":null,"targetUrl":null,"success":false,"error":{"code":0,"message":"..."},"unAuthorizedRequest":false,"__abp":true}
```

Key fields:
- `"unAuthorizedRequest":false` → Endpoint does NOT require authentication
- `"unAuthorizedRequest":true` → Endpoint requires auth
- `"__abp":true` → Confirms ABP Framework

Test with POST + JSON body (some WAFs block GET but allow POST):
```bash
curl -k -X POST https://target/api/services/app/{Service}/{Method} \
  -H "Content-Type: application/json" \
  -d '{"Param1":"value1"}'
```

## Parameter Name Sensitivity

ABP apps are case-sensitive on parameter names. Test both CamelCase and snake_case:
```json
{"ParkNo":"MC","SearchFilter":"test"}   // May work
{"Park_No":"MC","SearchFilter":"test"}  // May also work (different behavior)
```

## WAF Bypass for ABP APIs

Tengine WAF may block GET requests but allow POST with JSON body:
```bash
# GET blocked by WAF (405)
curl -k https://target/api/services/app/ScanPay/LicensePlateQuery?ParkNo=MC

# POST with JSON body passes through
curl -k -X POST https://target/api/services/app/ScanPay/LicensePlateQuery \
  -H "Content-Type: application/json" \
  -d '{"ParkNo":"MC","SearchFilter":"test"}'
```

## Common Vulnerabilities

### 1. ABP Configuration Exposure
If `/api/abp/application-configuration` is accessible without auth, it may leak:
- Auth configuration (token endpoints, OAuth settings)
- Feature flags
- Current user info
- Permission definitions
- Setting values

### 2. Input Reflection in HTML Attributes
ABP MVC apps often pass server-side data to hidden fields for JS consumption:
```html
<input type="hidden" id="HidePageData" data-park-no="USER_INPUT" ...>
```
Check if parameters are HTML-encoded before output. If not → Reflected XSS.
JS reads via `container.getAttribute('data-park-no')` → stores in `window.PageData`.

### 3. SQL Injection in Search/Filter Parameters
ABP apps using raw SQL or poorly-parameterized queries in `AppService` methods.
Test parameters that feed into database queries (search filters, IDs, codes).
Note: WAF may block single quotes in URL params but NOT in POST JSON body.

### 4. Missing Security Headers
ABP Framework does NOT add security headers by default. Apps must explicitly configure:
- HSTS
- X-Frame-Options
- Content-Security-Policy
- X-Content-Type-Options

## Testing Checklist

```bash
# 1. Check ABP JS availability
curl -s -o /dev/null -w "%{http_code}" https://target/lib/abp-web-resources/Abp/Framework/scripts/abp.min.js

# 2. Check ABP config endpoint
curl -s https://target/api/abp/application-configuration | python3 -c "import json,sys; d=json.load(sys.stdin); print(list(d.keys()))"

# 3. Check service proxies (lists all API methods)
curl -s https://target/AbpServiceProxies/GetAll

# 4. Check Swagger
curl -s https://target/swagger/v1/swagger.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(list(d.get('paths',{}).keys())[:30])"

# 5. Find frontend JS files
curl -s https://target/ | grep -oE 'view-resources/[^"]+\.js' | sort -u

# 6. Extract API endpoints from JS
for js in $(curl -s https://target/ | grep -oE 'view-resources/[^"]+\.js'); do
  echo "=== $js ==="
  curl -s "https://target/$js" | grep -oE 'api/services/app/[A-Za-z/]+'
done

# 7. Test unauthenticated access (POST JSON)
curl -k -X POST https://target/api/services/app/{Service}/{Method} \
  -H "Content-Type: application/json" -d '{}' | python3 -c "import json,sys; d=json.load(sys.stdin); print('unAuthorizedRequest:', d.get('unAuthorizedRequest'))"

# 8. Test security headers
curl -sI https://target/ | grep -iE '(strict-transport|x-frame|content-security|x-content-type)'
```

## Real-World Example: carpark.mgm.mo (MGM SRC 2026-06-05)

- ABP Framework with F5 BIG-IP
- XSS in ParkNo parameter (reflected to `data-park-no` attribute without encoding)
- Missing ALL security headers (HSTS/XFO/CSP/XCTO)
- API endpoints exposed in Index.min.js:
  - `api/services/app/ScanPay/LicensePlateQuery` (车牌查询, unAuthorizedRequest=false)
  - `api/services/app/ScanPay/GetQRCodeCoupon` (优惠券验证, requires Park_No+ticketNo+CouponNo+CardNo)
  - `ParkingLot/ParkingInfo?ParkNo=`
- Parameters: Park_No, CardNo, CouponNo, SearchFilter, VehicleTypeNo
- WAF bypass: POST JSON body passes Tengine WAF that blocks GET requests
- API error messages reveal validation rules: "The SearchFilter field is required", "Input ticket number or car plate number!"
- GetQRCodeCoupon with CardNo returns "優惠券不存在" (coupon doesn't exist) — confirms endpoint processes requests
