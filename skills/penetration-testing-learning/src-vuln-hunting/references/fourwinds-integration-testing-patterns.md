# FourWindsIntegration Gaming Loyalty System Testing

## Overview

FourWinds International (FWI) provides gaming loyalty management systems for casinos.
Their integration endpoints are sometimes exposed on production sites with DEV connections.

## Fingerprinting

Look for FourWindsIntegration paths in frontend JS:
```bash
curl -s https://target/js/fwimobile.min.js | grep -oE 'FourWindsIntegration[^"'\'']*' | sort -u
```

Common JS filenames:
- `fwimobile.min.js`
- `fwimobile.js`
- `fourwinds*.js`

## Endpoint Structure

```
/FourWindsIntegration/GamingLoyaltySystem/{Handler}.ashx?Connection={ENV}&ModuleName={MODULE}&CultureCode={LANG}
```

### Known Handlers
- `GetModuleInfo.ashx` — Returns module data (XML format)
- `RefreshSessions.ashx` — Refreshes session data

### Connection Values
- `DEV` — Development environment (often accessible!)
- `PROD` — Production (may fail with null reference)
- `STAGING` — Staging (may fail)

### Response Format (XML)
```xml
<?xml version="1.0" encoding="utf-8"?>
<ModuleInfoResponse>
  <StatusCode>OK</StatusCode>
  <StatusId>FWI0000</StatusId>
  <StatusDescription>Success</StatusDescription>
  <StatusException/>
  <StatusCookie>Module info was refreshed from data source</StatusCookie>
  <StatusTimeStamp>2026-06-05T13:55:37.8731357+08:00</StatusTimeStamp>
  <Name>["2049"]</Name>
  <Description>["config/images/Content/MobileFeatureItems/66_1.jpg"]</Description>
  <Link>["#ticketEvent;Id=3"]</Link>
</ModuleInfoResponse>
```

StatusId codes:
- `FWI0000` = Success
- `FWI0001` = Fail (with error description)

## Testing Steps

```bash
# 1. Check if DEV connection works
curl -k -s "https://target/FourWindsIntegration/GamingLoyaltySystem/GetModuleInfo.ashx?Connection=DEV&ModuleName=slider&CultureCode=en"

# 2. Compare with PROD/STAGING
curl -k -s "https://target/FourWindsIntegration/GamingLoyaltySystem/GetModuleInfo.ashx?Connection=PROD&ModuleName=slider&CultureCode=en"
curl -k -s "https://target/FourWindsIntegration/GamingLoyaltySystem/GetModuleInfo.ashx?Connection=STAGING&ModuleName=slider&CultureCode=en"

# 3. Test RefreshSessions
curl -k -s "https://target/FourWindsIntegration/GamingLoyaltySystem/RefreshSessions.ashx?Connection=DEV"

# 4. Test different ModuleName values
for module in slider home main login register member loyalty gaming casino; do
  echo "=== $module ==="
  curl -k -s "https://target/FourWindsIntegration/GamingLoyaltySystem/GetModuleInfo.ashx?Connection=DEV&ModuleName=$module&CultureCode=en" | grep -oE '<StatusCode>[^<]*</StatusCode>'
done

# 5. Test different CultureCode values
for culture in en zh zh-cn zh-tw pt ja ko; do
  curl -k -s "https://target/FourWindsIntegration/GamingLoyaltySystem/GetModuleInfo.ashx?Connection=DEV&ModuleName=slider&CultureCode=$culture" | grep -oE '<StatusCode>[^<]*</StatusCode>'
done
```

## Severity Assessment

- **DEV connection accessible on production site** → Medium (information disclosure + DEV environment exposure)
- **RefreshSessions accessible** → Medium (can modify DEV session state)
- **Module data leaks business info** → Low-Medium (activity names, resource paths, event IDs)
- **SQL injection in parameters** → Blocked by Alibaba Cloud WAF (single quotes rejected)

## Real-World Example: mlife.mo (MGM SRC 2026-06-05)

- FourWindsIntegration Gaming Loyalty System on production mlife.mo
- `Connection=DEV` returns SUCCESS; `Connection=PROD`/`STAGING` return FAIL
- Only `slider` module returns data; other modules (config/dashboard/admin/user/points/rewards/profile) return "System failed"
- RefreshSessions.ashx?Connection=DEV returns SUCCESS
- Slider data: Name=["2049"], Description=["config/images/Content/MobileFeatureItems/66_1.jpg"], Link=["#ticketEvent;Id=3"]
- Frontend JS hardcodes: `FourWindsIntegration/GamingLoyaltySystem/GetModuleInfo.ashx?Connection=DEV&ModuleName=slider&CultureCode=`
- No CORS headers on the endpoint (not vulnerable to CORS)
- SQL injection blocked by Alibaba Cloud WAF (Request Rejected)

## Mitigation

1. Remove DEV environment endpoints from production sites
2. Remove hardcoded Connection=DEV from frontend JS
3. Add authentication to all FourWindsIntegration endpoints
4. Verify PROD/STAGING configurations (currently returning null reference errors)
