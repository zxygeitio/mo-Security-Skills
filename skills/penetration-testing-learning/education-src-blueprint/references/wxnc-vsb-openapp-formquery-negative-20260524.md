# wxnc.edu.cn VSB/OpenApp FormQuery negative evidence (2026-05-24)

## Scope

Target: `wxnc.edu.cn` / 无锡师范高等专科学校.

Primary reachable assets observed:
- `http://www.wxnc.edu.cn/` — HTTP 200, Visual SiteBuilder 9 / VSB portal.
- `http://zsjy.wxnc.edu.cn/` — HTTP 200, 招生就业处, VSB/OpenApp FormQuery.
- `http://jwc.wxnc.edu.cn/` — HTTP 502统一错误页; not reportable.

Common education high-value subdomains such as `ehall`, `authserver`, `sso`, `cas`, `webvpn`, `vpn`, `mail`, `oa`, `portal`, `xg`, `lib`, `zsb`, `job`, `jxjy`, `api`, `service`, `wx`, `file`, `test`, `admin`, `english` had no reachable business surface from the test environment during this round.

## VSB/OpenApp FormQuery endpoints

Useful front-end pattern:
- `appOwner = "2085021629"`
- front-end auth header uses `Authorization: tourist` from `gettoken(10)`, not a custom `token:` header.
- `session` header is populated from `/system/resource/getSession.jsp`.
- required headers for metadata calls:
  - `Authorization: tourist`
  - `session: <getSession.jsp value>`
  - `owner: 2085021629`
  - `appId: app-form-query`
  - `resolutionRatio: 1920*1080`

Metadata endpoint:
- `POST /aop_component//webber/formquery/query/front/items/get`
- Body: `{"owner":"2085021629","templateCode":"<Form-...>"}`
- Returns form definitions only; no candidate/student data.

Captcha endpoint:
- `GET /aop_component//webber/formquery/query/generate/code?t=<random>`
- Returns captcha image and `id` used as `randomKey` / `verifyCodeId`.

Real query endpoint:
- `POST /aop_component//webber/formquery/data/get/info`
- Front-end sends roughly:
  - `owner`
  - `randomCode`
  - `randomKey`
  - `datas`
  - `templateCode`
  - `pageCode`
  - `ifRandomCode: true`
- Query is gated by name + ID card + captcha. Without proving captcha bypass, IDOR/enumeration, or real sensitive data access, do not submit.

## Confirmed query templates

All four are anonymous by design (`needLogin=N`) but captcha-protected (`msgCode=Y`) and require `姓名 + 身份证号`.

1. `zkxxcx/cjylq.htm`
   - `templateCode`: `Form-1777344861877-5881`
   - `viewId`: `1148757`
   - Name: `提前招生校测成绩与录取查询`
   - `conditionOrder`: `Item-1777344861835-9071,Item-1777344861835-5414`

2. `zkxxcx/jkm.htm`
   - `templateCode`: `Form-1777343632032-957`
   - `viewId`: `1148728`
   - Name: `提前招生缴款码查询`
   - `conditionOrder`: `Item-1777343632026-7889,Item-1777343632026-800`

3. `zkxxcx/kddh.htm`
   - `templateCode`: `Form-1777343119501-4074`
   - `viewId`: `1148758`
   - Name: `录取通知书快递单号查询`
   - `conditionOrder`: `Item-1777343118758-3508,Item-1777343118768-3271`

4. `zkxxcx/zkz.htm`
   - `templateCode`: `Form-1777344176581-2573`
   - `viewId`: `1148729`
   - Name: `准考证打印`
   - `conditionOrder`: `Item-1777344176569-163,Item-1777344176569-3753`

## Non-reportable findings

Do not submit any of these alone:
- `needLogin=N` on招生查询 pages: normal public-query design.
- Form metadata exposure: only field names and template configuration, not PII.
- `ifEncrypt=False` in item rules: front-end display/config flag; not data exposure by itself.
- `/system/resource/getToken.jsp` and `/system/resource/getSession.jsp`: normal VSB/OpenApp front-end mechanics.
- VSB static resources and click counters: normal public CMS resources.
- `/aop_component//filesystem/upload?appId=app-form-query`: GET says method not supported; previous POST upload attempt returned 403, so unauthenticated upload was not proven.
- `jwc.wxnc.edu.cn` 502: service error is not a security vulnerability without a verifiable impact.
- Uniform VSB 404 pages for `.git`, `.svn`, `.env`, `actuator`, `swagger`, `jsonp`, `admin`, `cas`, `authserver`: no evidence.

## Submit only if future evidence proves

A wxnc report is worth writing only if one of these is verified:
- captcha bypass or server-side captcha not enforced on `data/get/info`;
- IDOR/enumeration returns real candidate/ID-card/录取/缴款码/快递/准考证 data for multiple users;
- unauthenticated upload succeeds and returns a public, school-domain URL with meaningful executable/rendered impact;
- a separate high-value asset such as ehall/CAS/OA/WebVPN becomes reachable and exposes data/auth bypass/RCE/SQLi.

## Tooling note for this local host

When writing repeatable scripts in skills or commands, prefer `/usr/bin/python3` or the Hermes venv Python over bare `python3` if a shell command hangs unexpectedly. On this host, `/usr/local/bin/python3` was observed as a recursive shim (`exec python3 -m ropgadget "$@"`). Capture the fix as “use an absolute Python interpreter”, not as a general negative claim about Python tooling.
