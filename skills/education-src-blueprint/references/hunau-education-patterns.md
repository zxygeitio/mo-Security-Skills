# HUNAU-style education asset notes: epxing-frame, CAS/CIMS, WebVPN, and low-impact verification

This reference captures reusable observations from a low-impact public-surface review of a university target using similar patterns. Use it as a pattern library, not as a report by itself.

## Scope and safety
- Keep checks low-impact and unauthenticated: GET/HEAD, static JS review, CORS header probes, and a few known public API endpoints.
- Do not brute-force, upload files, bypass login, or submit forms unless the user has explicit authorization and the test needs that proof.
- Education SRC reporting threshold remains: only submit if there is real impact such as unauthorized PII/business data, IDOR, auth bypass, SQLi/RCE, or exploitable upload.

## Practical workflow when DNS/HTTP is slow
1. Resolve once with `dig +short host A`.
2. For repeated curl probes against the same virtual host, pin the host/IP mapping with:
   `curl --resolve host:443:IP https://host/path ...`
3. Keep `--connect-timeout` and `--max-time` short. This avoids losing the whole run to slow DNS or long redirects while preserving the Host header/SNI.
4. Prefer per-host/per-path one-shot probes over large loops when the target is slow.

## CAS/CIMS pattern
Some schools use CAS under `/cas/login`, not `/authserver/login`.

Low-impact probes:
- `/cas/login`
- `/portal` and `/portal/`
- `/cas/js/jquery-*.js`
- `/cas/js/cims/CIMS-Web-Frame-v2.js`

Signals:
- Login page may include `execution`, `_eventId`, `geolocation`, `username`.
- CIMS config may expose `host: https://sso.example.edu.cn/authn`, `postaction: https://sso.example.edu.cn/cas/login`, and `sig_request`.
- Old jQuery (for example 1.12.x) is only a weak finding by itself. Do not report unless combined with a target-specific exploitable XSS/data impact chain.
- If `/authserver/*` returns a custom 404/inner-resource page, switch to `/cas/*` rather than assuming no SSO.

## epxing-frame / recruitment portal pattern
A recruitment portal may expose a Vue SPA such as `epx-frame` with `/js/config.js` and bundled JS.

Static indicators:
- `window.BASE_PROJECT_NAME = 'epxing-frame'`
- `window.BASE_AUTH_NAME = 'epx-auth'`
- `window.BASE_CLIENT_ID = 'frame'`
- `window.BASE_SYSTEM_ID = 'epxing-frame-manage'`
- `window.BASE_APP_ID = 'FM_SERVICE_PLATFORM'`
- routes like `#/app/<client>/<system>/<app>/RECRUIT` or `recruit/register`

Useful static-review targets:
- `/js/config.js`
- `/js/app.*.js`
- `/js/frame.*.js`

Common strings to extract from bundled JS:
- `/api/v1`, `/process/v1`, `/rule/v1`
- `validLogin`, `getSystemInfo`, `getMenuTreeData`, `getUserMenuTreeData`
- `getShortUrl`, `getLongUrl`
- `FM_USER`, `FM_SYSTEM`, `FM_MODULE`, `FM_URL_MAP`

Testing guidance:
- Simple GET requests to guessed `/api/v1/...` paths may return only a custom “inner resource/error” page. That is not a vulnerability.
- Continue only if the JS reveals the actual request method/body/RPC format or a public route returns real data.
- For SRC, only report if unauthenticated APIs expose/modify recruitment positions, applications, resumes, identities, contact data, or URL mapping can be abused with demonstrable impact.

## CORS interpretation
- `Access-Control-Allow-Origin: <attacker-origin>` with `Access-Control-Allow-Credentials: false` is not enough for a high-impact report.
- Treat it as a lead only. To submit, prove a sensitive unauthenticated API response or a credentialed read path (`Credentials:true` plus sensitive data) with a browser PoC.

## WebVPN and internal DNS leads
- WebVPN login redirect and secure ticket cookies alone are not vulnerabilities.
- Internal DNS records such as `jwxt.example.edu.cn -> 10.x.x.x` or `old.example.edu.cn -> 10.x.x.x` are usually low-value information disclosure only.
- Pivot value exists only if WebVPN/SSO exposes unauthorized access to internal systems or public config/resource lists.

## Reportability gate
Do not submit:
- Internal IP/DNS exposure alone.
- Old jQuery alone.
- CORS reflection with credentials disabled and no sensitive API proof.
- JSONP/public endpoint that redirects to login or returns only a shell page.
- Custom 404/inner-resource pages.

Submit only after proving:
- Unauthenticated sensitive data access (PII, student/staff/application data).
- IDOR with multiple records.
- Auth bypass or arbitrary account/session impact.
- Upload leading to executable or impactful hosted content.
- SQLi/RCE with controlled, safe proof.
