# BZUU continued recon: slow-target execution and report gate (2026-05-25)

Scope: `bzuu.edu.cn` / `oshall.bzuu.edu.cn` continued after prior go-fastdfs and rhpt/getAppConfig findings.

## Session lesson

A large Python/curl batch that tries to fetch many JS files, Swagger docs, and endpoint probes can stall on slow education hosts and produce no final TSV if it writes only at the end. For BZUU-like targets, use small batches and immediate evidence writes:

```bash
curl -4 --http1.1 -sk --connect-timeout 4 --max-time 10 -D /tmp/h -o /tmp/b -w 'CODE:%{http_code} SIZE:%{size_download}\n' 'https://target/path'
head -c 300 /tmp/b
```

If a batch times out, do not rerun the same shape. First inspect any existing workspace files, then manually verify only the high-value candidates with standalone curl calls.

## Verified BZUU boundary

`getAppConfig` still returns unauthenticated JSON with initial password rule and CORS reflection:

```bash
curl -4 --http1.1 -sk -D- -H 'Origin: https://evil.example' 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/getAppConfig'
```

Observed characteristics:

```text
HTTP 200
Content-Type: application/json
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
passwordHint: 登录账号为学号/工号，初始密码规则为：Bzuu@身份证后6位
```

This remains a medium-boundary candidate only if not already submitted. Do not claim account takeover without authorized proof of real account login.

## Negative controls verified

Sensitive rhpt APIs are still token-protected:

```bash
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/studentPhoneList?pageNo=1&pageSize=10'
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/teacherPhoneList?pageNo=1&pageSize=10'
```

Observed:

```json
{"error":"Internal Server Error","message":"Token失效，请重新登录","status":500}
```

Third-party token endpoint without real credentials:

```bash
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-interface/zhxyInterfaceApi/getAccessToken?appId=app&appSecret=test'
```

Observed:

```json
{"success":false,"message":"appId不存在","code":500,"result":null}
```

Second-classroom management/client APIs are login-required:

```bash
curl -4 --http1.1 -sk 'https://ektm.bzuu.edu.cn/api/backend/server/v1/index/statistics/info'
curl -4 --http1.1 -sk 'https://ekta.bzuu.edu.cn/api/app/client/v1/student/user/my-info'
```

Observed:

```json
{"code":10001,"data":null,"msg":"登陆失败，请重新登陆","token":""}
```

## Report gate for future runs

Do not create a new BZUU report from:

- repeated go-fastdfs status/upload evidence; it is the old root cause unless new rendered/executable impact is proven;
- Swagger/API docs exposure alone;
- JS baseURL/API path discovery alone;
- ektm `common/all-school` public metadata;
- ekta/ektm login-required JSON;
- Shibboleth metadata without trust abuse or account impact;
- ASP.NET SMS/reset normal validation failures.

Submit only if a future run proves RCE, SQLi, auth bypass, arbitrary password reset/SMS abuse, unauthorized real student/teacher/admin/activity/grade/salary data, IDOR over real records, or a newly distinct file upload impact.
