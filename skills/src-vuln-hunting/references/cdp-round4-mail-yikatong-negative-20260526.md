# CDP.edu.cn Round 4 negative verification: mail + yikatong (2026-05-26)

Class: education SRC / recon-driven low-impact verification.

Use this as a session-specific reference when revisiting 成都职业技术学院 `cdp.edu.cn`, especially after historical notes mention QQ Exmail account-enumeration or yikatong campus-card endpoints.

## Scope and evidence paths

Evidence directory:
- `/tmp/cdp_round4_20260526/`

Key files:
- `/tmp/cdp_round4_20260526/resolved.tsv` — 31 resolved CDP-related host records.
- `/tmp/cdp_round4_20260526/alive.json` — stable externally reachable assets observed in this run.
- `/tmp/cdp_round4_20260526/mail_exmail/dns.txt` — MX/TXT/DMARC/DKIM checks.
- `/tmp/cdp_round4_20260526/mail_exmail/exmail_summary.tsv` — QQ Exmail low-frequency side-channel recheck.
- `/tmp/cdp_round4_20260526/targeted/probe.tsv` — small-batch probe results before timeout.
- `/tmp/cdp_round4_20260526/targeted/mail_root_.body` — Tencent Enterprise Mail public login page.
- `/tmp/cdp_round4_20260526/targeted/mail_cgi_login_.body` — public login/session-timeout template.
- `/tmp/cdp_round4_20260526/ykt_recheck/ykt.tsv` — yikatong high-value endpoint recheck.
- `/tmp/vuln_reports/cdp/deep-recon-20260526-final.txt` — final no-submit artifact updated with Round 4.

## Asset expansion result

A low-impact expansion found 31 DNS-resolved hosts, including:
- `mail.cdp.edu.cn`, `smtp.cdp.edu.cn`
- `app.cdp.edu.cn`, `app-vsmg.cdp.edu.cn`
- `course.cdp.edu.cn`, `dzmg.cdp.edu.cn`, `jedu.cdp.edu.cn`, `jw.cdp.edu.cn`
- `lib.cdp.edu.cn`, `special.cdp.edu.cn`, `tafe.cdp.edu.cn`, `uia.cdp.edu.cn`
- `weixin.cdp.edu.cn`, `zhao.cdp.edu.cn`, `zyk.cdp.edu.cn`
- previously known `www`, `ehall`, `cas`, `aic`, `webvpn`, `yikatong`, etc.

In this environment, stable externally reachable HTTP surfaces were mainly:
- `mail.cdp.edu.cn` / `smtp.cdp.edu.cn` through Tencent Enterprise Mail;
- `yikatong.cdp.edu.cn`.

Many school/education-network hosts returned `000`, timeout, or network unreachable. Treat these as availability negatives only, never as vulnerability evidence.

## Mail / QQ Exmail recheck

DNS still indicates Tencent Enterprise Mail:
- MX: `mxbiz1.qq.com`, `mxbiz2.qq.com`
- SPF: `v=spf1 include:spf.mail.qq.com ~all`

A prior reference recorded a possible QQ Exmail account-enumeration side channel for `20230001@cdp.edu.cn`. Round 4 rechecked with wrong-password, low-frequency probes for:
- `20230001`
- `20230002`
- `20240001`
- `20190001`
- `99999999`

Round 4 result:
- all returned NORMAL branch (`errtype=1`);
- no stable `verify=true` branch was reproduced;
- response sizes varied within normal failure ranges.

Decision: do not submit CDP QQ Exmail account enumeration from Round 4. If revisiting, require a fresh stability check: at least one candidate must repeatedly return `verify=true&clientuin=<localpart>` while multiple controls return only `errtype=1`.

## `mail.cdp.edu.cn`

Observed:
- Public Tencent Enterprise Mail login page.
- `/cgi-bin/login` unauthenticated request returns only login/session-timeout/redirect template.

No evidence of:
- mailbox access;
- token leakage;
- address book / account list disclosure;
- password reset bypass;
- stable account-existence differential in this run.

Decision: no submit.

## `yikatong.cdp.edu.cn` recheck

Rechecked high-value endpoints with short, direct `curl --noproxy '*'` calls and redacted crypto/token fields.

Observed:
- `/server/auth/getEncrypt`: `success:true` public encryption-helper response with `id/publicKey/fixed:false` — not a vulnerability by itself.
- `/server/captcha/check` with invalid token: `验证码已失效，请重新获取` — no bypass.
- `/server/home/sendSms` with invalid image code: `图形验证码不正确` — SMS remains gated.
- `/server/user/info`: encrypted failure object, not user data.
- `/server/user/tradeList`, `/server/card/cardList`: failure objects, not business data.
- `/server/user/uploadFacePhoto`: validation error (`base64Img:照片必选`), no uploaded file URL or ID.
- Multiple yikatong requests with `Origin` did not return exploitable CORS headers.

Decision: no submit. Same threshold as earlier yikatong references still applies: only report if a legal low-privilege account proves IDOR/privilege escalation, captcha/SMS bypass reaches a real sensitive action, or an unauthenticated endpoint returns real card/user/transaction data.

## Durable lessons for future CDP work

1. Historical positive-looking QQ Exmail side-channel evidence can become non-reproducible; always re-run a fresh two-run stability check before reporting.
2. For CDP, keep negative evidence explicit and update the no-submit artifact rather than forcing a weak report.
3. Avoid long monolithic probe loops on slow education targets; small batches should write TSV/body/header immediately so partial results survive timeout.
4. Redact all token, key, encrypted `data`, `secretKey`, `publicKey`, and image-base64 material in summaries.
5. Submit only if there is real impact: unauthenticated sensitive data, account takeover, IDOR with a legal test account, executable/uploaded proof file, RCE/SQLi, or a verified SMS/captcha bypass chain.
