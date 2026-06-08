# Education SRC Small-Batch Evidence Gate

This reference adapts the class-level SRC evidence gate to education targets, where false positives and low-value findings are common.

## Trigger

Use this when the target is a school, education bureau, education SaaS, campus card, ehall/CAS/OA/WebVPN, enrollment query, or student/teacher data system.

## First command

Generate a target workspace and hypothesis directories:

```bash
/usr/bin/python3 ~/.agent/scripts/src-hypothesis-builder.py TARGET --scope education --outdir /tmp/src_TARGET
```

Education role model:

- visitor,
- student,
- teacher,
- administrator,
- supplier,
- examinee.

Education object model:

- `studentId`, `userId`, `teacherId`, `workNo`, `idcard`, `phone`, `fileId`, `resId`, `appId`, `orgId`, `tenantId`, `processId`, `token`.

## High-value education entry points

Prefer these over dictionary-style path scanning:

- enrollment/admission query,
- ehall / online service hall,
- CAS / authserver / password reset,
- campus card / payment / trade records,
- OA / task center / transaction center,
- second classroom / activity systems,
- file upload/download,
- supplier registration,
- applet / mobile / Uni-app APIs,
- JavaScript chunks, `env.js`, `serverConfig.json`, `remoteEntry`, import maps.

## Small-batch rule

For each hypothesis:

1. put only 5-20 high-value URLs in `urls.txt`,
2. run `src-http-probe.py` with 5-8 second timeouts,
3. classify every result the same day as reportable, deepen, negative evidence, or abandoned,
4. run `src-evidence-gate.py` before writing any report.

Do not return to unbounded all-path scripts after a timeout or candidate pileup. Switch to single-request or small-batch verification with immediate disk output.

## Education stop conditions

Stop the current branch when:

- 20 high-value APIs return token-expired, 401/403, login page, or empty body;
- Swagger/rhpt/ehall only exposes docs or public config, with no token exchange or sensitive read;
- upload returns only forced download or non-rendering file and no new impact can be proven;
- CORS only reflects public endpoints or has no credentials/sensitive browser-readable data;
- CAS/password reset returns only standard errors and no stable enumeration or takeover chain;
- mail security is only DMARC/SPF/DKIM config without spoofing or account enumeration proof;
- VSB/SUDY/WordPress/main portal is only public articles, counters, default public REST, or SPA fallback;
- the same root cause was already submitted and this is only supplemental evidence.

## Reportable education candidate requirements

Before reporting, require all three:

1. real attack result: sensitive data, cross-object access, usable key, accessible uploaded file, stable reset/enumeration difference, or safe SQL/RCE proof;
2. control group: random path, invalid ID, invalid token, unauthenticated/authenticated contrast, or public/private interface contrast;
3. copyable reproduction: locally tested single-line curl or bash heredoc, plus screenshot position notes.

## Screenshot positions

Use this default mapping:

- 【截图位置1】入口 or source of API/JS/interface.
- 【截图位置2】request or curl command.
- 【截图位置3】sensitive/impact response.
- 【截图位置4】attack result or accessible uploaded URL.
- 【截图位置5】control group / invalid token / invalid ID / random path.

## Anti-patterns

Do not submit education reports based only on:

- `Token失效` or normal auth errors,
- static Swagger exposure,
- public config values,
- SPA fallback 200,
- WAF block pages,
- WordPress default public APIs,
- CAS standard errors,
- forced-download uploads without separate impact,
- same-root-cause duplicates.
