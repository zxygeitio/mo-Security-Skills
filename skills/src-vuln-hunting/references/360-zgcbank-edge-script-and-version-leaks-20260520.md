# 360 SRC ZGCBank edge-site anomalies: script injection, SPA fallback, Tomcat version leaks (2026-05-20)

## Scope / trigger
Use this when continuing 360/ZGCBank vulnerability hunting on non-PMS edge assets such as:
- `wx.zgcbank.com`
- `www.zgcbank.com`
- `h5.zgcbank.com`

These findings are separate from PMS registration/login/password-reset verification-code flows.

## VPN/routing prerequisite
360 VPN must be active before validation. In this session `tun0` was `10.9.235.78/16`. Some ZGCBank hosts needed explicit split-tunnel host routes via the VPN gateway after DNS resolution:

```bash
for ip in 119.253.85.205 119.253.85.202 220.181.58.135 220.181.58.129; do
  ip route replace $ip/32 via 10.9.0.1 dev tun0 2>/dev/null || true
done
```

Verify with:

```bash
curl -sk --http1.1 --connect-timeout 6 --max-time 12 -o /dev/null -w '%{http_code} size=%{size_download} ip=%{remote_ip}\n' https://wx.zgcbank.com/
```

## Confirmed issue class 1: abnormal JavaScript appended after page body

### wx.zgcbank.com
A prior report captured `https://wx.zgcbank.com/` returning a health-check page with abnormal appended JS:
- `brmidyrvj.php`
- `function c_venus`
- `E_venus`
- `localurl`

Script behavior:
- enumerates `SCRIPT`, `IFRAME`, `FRAME`, `IMG`, `EMBED`, `LINK`
- builds `brmidyrvj.php?url=<resource-list>&localurl=<document.URL>`
- sends via `XMLHttpRequest`

Report as “页面异常脚本注入/疑似页面篡改”, not as account takeover/XSS unless direct user-controlled injection is proven.

### www.zgcbank.com /robots.txt
`https://www.zgcbank.com/robots.txt` returned `HTTP/1.1 200 OK` with official site content plus abnormal appended script.

Useful proof commands:

```bash
curl -sk --http1.1 --connect-timeout 8 --max-time 20 -D /tmp/www_zgcbank_robots_hdr.txt -o /tmp/www_zgcbank_robots_body.html 'https://www.zgcbank.com/robots.txt'
head -1 /tmp/www_zgcbank_robots_hdr.txt
wc -c /tmp/www_zgcbank_robots_body.html
grep -aoE '北京中关村银行|brmidyrvj\.php|function c_venus|E_venus|localurl' /tmp/www_zgcbank_robots_body.html | sort -u
```

Observed evidence:
- `HTTP/1.1 200 OK`
- body contains “北京中关村银行”
- body contains `brmidyrvj.php`, `function c_venus`, `E_venus`, `localurl`
- `/` body around 3642 bytes, `/robots.txt` around 4631 bytes; the difference is the abnormal tail script.

Suggested title:
`北京中关村银行官网部分不存在路径返回首页并被追加异常JavaScript代码`

Suggested severity: 中危.

Pitfall: do not submit “SPA fallback / nonexistent path returns homepage” as the vulnerability by itself. The valuable point is “fallback response includes abnormal appended script”.

## Confirmed issue class 2: default Tomcat error page leaks exact version

`wx.zgcbank.com` nonexistent paths returned default Tomcat error pages leaking `Apache Tomcat/10.0.27`.

Useful proof commands:

```bash
curl -sk --http1.1 --connect-timeout 8 --max-time 20 -D /tmp/wx_tomcat_hdr.txt -o /tmp/wx_tomcat_body.html 'https://wx.zgcbank.com/no_such_360_probe'
head -1 /tmp/wx_tomcat_hdr.txt
wc -c /tmp/wx_tomcat_body.html
grep -aoE 'HTTP Status 404|Apache Tomcat/[0-9.]+|The requested resource \[[^]]+\] is not available' /tmp/wx_tomcat_body.html | sort -u
```

Observed evidence:
- `HTTP/1.1 404`
- `HTTP Status 404`
- `The requested resource [/no_such_360_probe] is not available`
- `Apache Tomcat/10.0.27`

Suggested title:
`北京中关村银行微信服务域名错误页泄露 Apache Tomcat 版本信息`

Suggested severity: 低危.

## Classification / counting guidance
In the 2026-05-20 session, after excluding already reported PMS verification-code and password-reset issues, the non-PMS new findings counted as:
1. `wx.zgcbank.com` abnormal JS injection / suspected page tampering — 中危
2. `www.zgcbank.com/robots.txt` abnormal JS injection / fallback page tampering — 中危
3. `wx.zgcbank.com` Tomcat 10.0.27 version leak — 低危

Submit the two abnormal-JS reports first. Submit Tomcat version leak last or as a lower-value hardening issue.

## Reporting wording
Use cautious phrasing:
- good: `异常JavaScript代码`, `页面疑似篡改`, `页面异常脚本注入`, `资源地址与当前URL被异常回传`
- avoid unless proven: `存储型XSS`, `远程代码执行`, `账号接管`, `用户数据泄露`

For 360 forms, keep reproduction under field limits: one heredoc command to fetch, one grep for keywords, one short impact paragraph, screenshot markers.
