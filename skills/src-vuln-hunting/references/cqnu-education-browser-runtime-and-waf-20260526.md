# CQNU-style education portal runtime recon and false-positive gate (2026-05-26)

## Trigger

Use this pattern for Chinese university targets where main public sites are static/VSB-like, high-value systems are behind CAS/WebVPN/service hall, and terminal curl/probing may hang or get WAF-filtered while a browser session can still reveal runtime links and JS.

## Practical workflow

1. Start from the public main site in browser, not only DNS/path probes.
   - Extract top-nav and quick-entry links from DOM: portal, WebVPN, mail, zsb/zsxt, jwc, library, service hall.
   - Use `document.querySelectorAll('a')` and `document.scripts` to find runtime assets and hidden systems.

2. For CAS/service hall targets, inspect the redirected login page and linked JS.
   - Password reset JS often discloses exact Spring endpoints such as `spring:acp/zhzx/mmzh/checkFindType`.
   - Decode frontend URL helper logic; `spring:foo/bar` may map directly to `/mng/foo/bar?...`.
   - Low-impact account-enum validation requires several random/nonexistent controls and common placeholders. If all return the same standard message, classify as negative evidence.

3. For ZFSoft enrollment/admission systems, prefer browser runtime JS extraction.
   - Common JS: `/zsxt/js/tzgl/xslqcx/xslqcx.js`, `/xslqcxPaged.js`.
   - Common endpoints: `/tzgl/xslqcx/judgeKaptcha.zf`, `/tzgl/xslqcx/xslqxx.zf`, `/tzgl/xslqcx/xslqxxNew.zf`, `/tzgl/xslqcx/getSslqxxListAjax.zf`, `/xtgl/lqtzsmb/xzlqtzs.zf?ksh=&mbid=`.
   - Report only if a real query or IDOR returns sensitive admission data, notice/EMS data, or another concrete attack result. Empty result pages, public progress lists, and blank notice templates are negative evidence.

4. Treat WAF 200 responses as hostile until body-confirmed.
   - `/v2/api-docs` returning HTTP 200 on VSB/static university sites may be a WAF block page such as `Web应用防火墙 / 请求异常 / 攻击过滤条件`, not Swagger exposure.
   - Always read body/title and compare random path/known blocked path before marking as candidate.

## Stop / no-submit conditions

- CAS reset endpoint returns the same `未预留所选的找回方式` or other standard message for random users and placeholder accounts.
- ZFSoft admission query returns only `很抱歉，暂未查询到你的录取信息` for random controls.
- Notice download endpoint returns a template with empty hidden values (`mbid`, `nr`, `zsnd`, `yhglList`) and no personal/admission data.
- WebVPN/service hall redirects to CAS and unauthenticated API attempts return login/404 only.
- `Access-Control-Allow-Origin: *` appears only on public/empty admission pages with no browser-readable sensitive data.

## Reporting threshold

Before writing a report, require:

- one concrete sensitive response or cross-object result;
- a random/nonexistent control showing the difference;
- a locally tested single-line curl or browser-reproducible request;
- screenshot notes for source page, request, sensitive response, and control group.
