# 360 ZGCBank follow-up findings: edge script injection and version leaks (2026-05-20)

Use this when continuing 360/ZGCBank work after the PMS registration/login/forgot-password issues have already been reported. It records non-PMS, non-verification-code findings and verification patterns.

## VPN/routing notes
- Keep 360 OpenVPN split tunnel active (`tun0`, historically `10.9.235.78/16`).
- Some ZGCBank public-looking hosts only responded reliably after adding host routes through the VPN gateway. Re-resolve before testing; IPs changed during the session.
- Safe pattern:
  - Resolve with `getent ahostsv4 <host>`.
  - For in-scope ZGCBank hosts, route the resolved IP via `10.9.0.1 dev tun0` when testing inside the 360 VPN scope.
  - Verify with `curl -w '%{http_code} size=%{size_download} ip=%{remote_ip} err=%{errormsg}\n'`.

## Confirmed reportable findings from this follow-up

### 1. `wx.zgcbank.com` abnormal JavaScript appended to health-check page
- URL: `https://wx.zgcbank.com/`
- Normal page body is a health-check page containing:
  - `Send:GET /health.html`
  - `Receive:Service is Running`
  - `Interval:5`
- At least one validated response appended an abnormal script after the HTML:
  - `function c_venus()`
  - `E_venus()`
  - `brmidyrvj.php?url=...&localurl=...`
- The script enumerates `SCRIPT`, `IFRAME`, `FRAME`, `IMG`, `EMBED`, and stylesheet `LINK` resources, then sends a GET request to `brmidyrvj.php` with the current page URL.
- Report as abnormal JavaScript injection / suspected page tampering. Do not overstate as stored XSS or account takeover.

Minimal evidence command:
```bash
curl -sk --http1.1 --connect-timeout 8 --max-time 20 -D /tmp/wx_zgcbank_hdr.txt -o /tmp/wx_zgcbank_body.html 'https://wx.zgcbank.com/'
head -1 /tmp/wx_zgcbank_hdr.txt
wc -c /tmp/wx_zgcbank_body.html
grep -aoE 'Send:GET /health.html|Service is Running|brmidyrvj\.php|function c_venus|E_venus|localurl' /tmp/wx_zgcbank_body.html | sort -u
```

### 2. `www.zgcbank.com/robots.txt` abnormal JavaScript appended to fallback page
- URL: `https://www.zgcbank.com/robots.txt`
- `/robots.txt` returned HTTP 200 and a homepage/fallback body containing `北京中关村银行`.
- Compared with `/`, the `/robots.txt` response was larger and contained the same abnormal `brmidyrvj.php`/`c_venus` script.
- Report the abnormal script injection/tampering aspect. Do not submit SPA fallback alone as a vulnerability.

Minimal evidence command:
```bash
curl -sk --http1.1 --connect-timeout 8 --max-time 20 -D /tmp/www_zgcbank_robots_hdr.txt -o /tmp/www_zgcbank_robots_body.html 'https://www.zgcbank.com/robots.txt'
head -1 /tmp/www_zgcbank_robots_hdr.txt
wc -c /tmp/www_zgcbank_robots_body.html
grep -aoE '北京中关村银行|brmidyrvj\.php|function c_venus|E_venus|localurl' /tmp/www_zgcbank_robots_body.html | sort -u
```

### 3. `wx.zgcbank.com` Tomcat version leakage
- URLs: `https://wx.zgcbank.com/robots.txt`, `https://wx.zgcbank.com/no_such_360_probe`
- Default error page disclosed `Apache Tomcat/10.0.27`.
- Low severity information disclosure.

Minimal evidence command:
```bash
curl -sk --http1.1 --connect-timeout 8 --max-time 20 -D /tmp/wx_tomcat_hdr.txt -o /tmp/wx_tomcat_body.html 'https://wx.zgcbank.com/no_such_360_probe'
head -1 /tmp/wx_tomcat_hdr.txt
grep -aoE 'HTTP Status 404|Apache Tomcat/[0-9.]+|The requested resource \[[^]]+\] is not available' /tmp/wx_tomcat_body.html | sort -u
```

### 4. `app.zgcbank.com` Tomcat version leakage
- URLs: `https://app.zgcbank.com/robots.txt`, `https://app.zgcbank.com/isec/keyAgreement.do`
- Default 404/405 error pages disclosed `Apache Tomcat/9.0.107`.
- Low severity information disclosure.

Minimal evidence command:
```bash
curl -sk --http1.1 --connect-timeout 8 --max-time 20 -D /tmp/app_tomcat_robots_hdr.txt -o /tmp/app_tomcat_robots_body.html 'https://app.zgcbank.com/robots.txt'
head -1 /tmp/app_tomcat_robots_hdr.txt
grep -aoE 'HTTP Status 404|Apache Tomcat/[0-9.]+|The requested resource \[[^]]+\] is not available' /tmp/app_tomcat_robots_body.html | sort -u
```

## Candidate findings that should not be overreported
- `www.zgcbank.com` returning homepage content for many unknown paths is likely fallback behavior; only report when paired with abnormal injected script evidence.
- `pms.zgcbank.com` CORS header `Access-Control-Allow-Origin: *zgcbank.com` is malformed/ineffective by itself; do not submit as high-risk CORS unless arbitrary-origin credentialed read is proven.
- `h5/wx/app /isec/getServerRandom.do` returning public key material without auth appears to be a handshake endpoint; do not report unless a concrete cryptographic bypass, replay, or downstream data access is proven.
- PMS anonymous file endpoints tested with dummy IDs returned 403, generic system exception pages, or login timeout; do not submit without actual file/list data access.

## Reporting boundary
- Keep previously submitted PMS registration, login SMS, and forgot-password findings out of the new set.
- For script-injection/tampering reports, emphasize: abnormal script appended, resource enumeration, current URL callback, and banking domain risk. Avoid claiming user data theft unless proven.
- For Tomcat version leaks, mark low severity and keep the report concise.
