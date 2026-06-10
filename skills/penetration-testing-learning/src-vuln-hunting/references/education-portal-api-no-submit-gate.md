# CQNU education portal/API no-submit verification pattern (2026-05)

Use this reference when an education SRC target exposes a mix of admissions systems, CAS, portal SPAs, and bundled JS APIs, but evidence quality is unclear. The key lesson is to converge quickly to a no-submit decision unless a candidate returns real sensitive data, proves upload/download impact, or bypasses authentication.

## Target class

- University admissions systems: `zsxt` / `zsbxt` style endpoints for admission query and admission notice templates.
- CAS / Apereo login systems: `/cas/login`, `/cas/status`, `/cas/serviceValidate`.
- Vue/webpack campus portal SPAs exposing `app.*.js`, `chunk-vendors.*.js`, `base.js` and gateway-style API prefixes.
- Loongyun/Fighter-style portal APIs with prefixes like:
  - `/saas/gateway/fighter-middle/api`
  - `/saas/gateway/fighter-portal/api`
  - `/common/document/upload`
  - `/system/sysUser/page`
  - `/system/tenant/listNoPermissionCheck`
  - `/forget-password/getType`

## Workflow

1. Start from high-value hypotheses, not broad path spray:
   - Can admissions endpoints return real student/admission/EMS data without auth?
   - Can notice/template endpoints download another user's notice?
   - Can exposed JS API paths access user/teacher/contact/document data without auth?
   - Can `common/document/upload` upload without login and return a public URL?
   - Can CAS `service`/`redirect_uri` become an open redirect or ticket bypass?
   - Are Swagger/Actuator/Druid/.git paths genuinely exposed rather than fallback/error pages?

2. Keep probes small and bounded:
   - Batch at most ~20 high-value endpoints.
   - Prefer `--connect-timeout 2` and `--max-time 5-8` for flaky university assets.
   - If a Python/requests batch hangs or outputs nothing, immediately switch to small `curl` loops with per-request output files.
   - Save body/header/meta under a workspace and summarize status, size, content-type, body hash and decision.

3. For SPA/JS API extraction:
   - Fetch homepage, then `base.js`, `js/app.*.js`, and `js/chunk-vendors.*.js` first.
   - Extract `baseURL`, API prefixes and token/upload/download/user/contact/password-reset endpoints.
   - Do not report JS route disclosure by itself.
   - Validate each promising endpoint with the correct method (`GET` vs `POST`) and minimal JSON body.

4. Validate Loongyun/Fighter-style campus portal APIs:
   - `GET` often returns `Request method 'GET' not supported`.
   - `POST` with JSON may return `登录信息失效` or `参数不合法[没有登录信息]`; this is a negative/auth-enforced result.
   - `tenant/listNoPermissionCheck` may return tenant names/logos/basic config; this is public/low-value unless it includes secrets, credentials, internal tokens, or personal data.
   - `forget-password/getType` returning reset method configuration is not a vulnerability if slider/encryption/captcha controls remain required and no account enumeration or reset bypass is proven.
   - `common/document/upload` must actually accept a file and return a reachable URL before it can be considered; a login-required error is negative evidence.

5. Validate admissions endpoints conservatively:
   - Province/major/list endpoints returning generic JSON are not sensitive.
   - Notice/template endpoints returning a shell/template page for invalid IDs are not arbitrary download.
   - Do not use real candidate identifiers except minimal authorized/public samples, and redact all names/IDs/exam IDs in notes.
   - CORS + query access is only a supplement unless browser-readable sensitive data is demonstrated.

6. Validate CAS conservatively:
   - Test `login?service=https://evil.example/`, `logout?service=...`, OAuth authorize with invalid client, and `serviceValidate` with invalid ticket.
   - If responses are login/error pages or `INVALID_TICKET`, do not report redirect or ticket bypass.
   - `/cas/status` 500 with Java/Spring stack (`hasIpAddress`, Tomcat/Spring classes, internal port parse error) is an information disclosure/configuration issue, but not submit-worthy by itself unless it enables a further auth bypass or sensitive data access.

7. Sensitive path sweep boundaries:
   - `000`, 404, login HTML, unified errors, SPA fallback, or WAF pages are negative evidence.
   - Swagger/Actuator/Druid/.git only matter when the expected content is present and useful: OpenAPI JSON, Actuator env/heapdump data, Druid console, or git config/objects.

## No-submit decision template

Use a concise decision file when no candidate passes the gate:

- Conclusion: no new report recommended.
- Summarize each tested class:
  - admissions/zsxt/zsbxt
  - portal JS/API
  - upload/download
  - CAS
  - Swagger/Actuator/Druid/OA/high-value hosts
- For each: list representative URLs, evidence directory, result, and why it fails the submission threshold.
- Include a few low-impact one-line curls that reproduce negative evidence.
- Explicitly state the missing proof:
  - no unauthorized real personal/business data
  - no upload success + public URL
  - no arbitrary download / notice / EMS data
  - no CAS/OAuth bypass or usable open redirect
  - no real Swagger/Actuator/Druid/.git exposure

## Report threshold

Do not submit unless at least one of these is proven:

- Unauthenticated API returns real student/teacher/user/business data with control requests.
- IDOR returns a different user's or different tenant's object.
- Upload succeeds and returns a reachable URL with demonstrable impact.
- Download endpoint returns another user's file/notice or sensitive document.
- CAS/OAuth issue produces a usable redirect/token/ticket bypass or account impact.
- Actuator/Swagger/Druid/.git exposure yields sensitive configuration, credentials, endpoint invocation, or exploitable code/data.

## Pitfalls

- Do not turn `登录信息失效`, `没有登录信息`, `Request method not supported`, generic tenant config, or reset-method config into a vulnerability.
- Do not treat CAS stack trace as medium/high without an exploit chain.
- Do not keep long-running broad probes alive when the site is slow; kill and pivot to small curl batches.
- Do not retain raw personal admissions data in notes; use `[REDACTED_PERSON]`, `[REDACTED_ID]`, `[REDACTED_EXAM_ID]`.
