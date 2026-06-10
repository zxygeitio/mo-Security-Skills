# CORS Origin Reflection Testing Pattern

## When to Use
When testing CORS on SRC targets. Distinguish between static ACAO=* (low) and origin reflection (high).

## Key Distinction
- **ACAO=\*** (static): Browser blocks credentialed reads. Low impact unless sensitive public data exists.
- **Origin Reflection** (server echoes Origin): Browser allows credentialed reads. HIGH impact — full session hijack.

## Test Command
```bash
# Test 1: Custom origin reflection
curl -sk -H 'Origin: https://evil.com' 'https://target/' -D - | grep -i 'access-control'

# Test 2: null origin (iframe sandbox triggerable)
curl -sk -H 'Origin: null' 'https://target/' -D - | grep -i 'access-control'

# Test 3: With credentials cookie
curl -sk -H 'Origin: https://evil.com' -H 'Cookie: SESSION=test' 'https://target/' -D - | grep -i 'access-control'
```

## Vulnerability Confirmation Criteria
ALL three must be true for HIGH severity:
1. `Access-Control-Allow-Origin` reflects the attacker's Origin (not static *)
2. `Access-Control-Allow-Credentials: true`
3. There exists at least one endpoint that returns sensitive data

## Impact Chain
```
Attacker page (evil.com) → XMLHttpRequest with withCredentials=true
→ Browser sends victim's SESSION cookie to target
→ Target reflects Origin + ACAC=true
→ Attacker reads response (user data, tokens, PII)
```

## Common Chinese Platform Patterns
- **Spring Boot + Kong**: Often sets ACAO=* globally but some paths reflect Origin
- **蓝凌OA (Landray EKP)**: All responses reflect Origin + ACAC=true by default
- **腾讯云WAF (stgw)**: Blocks requests with suspicious Origin headers (returns HTTP 218); test with benign origins first
- **Nginx proxy**: May pass Origin through to backend which reflects it

## WAF Bypass for CORS Testing
If the WAF blocks Origin: evil.com:
1. Try with Referer header instead (some servers check Referer)
2. Try with benign-looking origins (https://www.target.com)
3. Try OPTIONS preflight (some WAFs don't inspect OPTIONS)
4. Check if non-browser User-Agent bypasses WAF

## T3SRC Specific: oa.jx-ams.cn Example
蓝凌OA V15 reflects ANY origin including null:
```bash
curl -sk -H 'Origin: https://evil.com' 'https://oa.jx-ams.cn/' -D -
# Returns: Access-Control-Allow-Origin: https://evil.com
# Returns: Access-Control-Allow-Credentials: true
# Returns: X-Auth-Token: <uuid>
```

## Report Template
Title: [domain] CORS配置错误可窃取用户会话和数据
Severity: High (if ACAC=true + data endpoints), Low (if ACAO=* only)
