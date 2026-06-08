# BZUU 2026-05-25 follow-up: second-classroom/API and repeated go-fastdfs boundary

Scope: `www.bzuu.edu.cn` and associated hosts after prior BZUU go-fastdfs and rhpt/getAppConfig findings. This reference is for future BZUU rechecks and education-SRC false-positive filtering.

Evidence workspace from the session:

```text
/tmp/bzuu_hunt_20260525_111341
```

## Outcome

No new independent high-value vulnerability was verified.

The only still-reportable candidate remains the existing rhpt/getAppConfig medium-boundary issue if it has not already been submitted. The go-fastdfs state still reproduces but is the historical same root cause and should be supplemental evidence only.

## Key reproduced commands and decisions

### 1. rhpt getAppConfig still leaks initial-password rule

Endpoint:

```bash
curl -4 --http1.1 -sk -D- 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/getAppConfig'
```

Observed unauthenticated JSON includes:

```json
"passwordHint":"登录账号为学号/工号，初始密码规则为：Bzuu@身份证后6位",
"casUrl":"https://auth.bzuu.edu.cn/authserver/",
"serviceUrl":"https://oshall.bzuu.edu.cn/zhxyApi/applets/workhall/api/casSucessLogin"
```

CORS reflected origin also reproduced:

```bash
curl -4 --http1.1 -sk -H 'Origin: https://evil.example' -D- 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/getAppConfig' -o /dev/null
```

Observed:

```text
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
```

Decision: valid medium-boundary candidate only if not already submitted. Do not claim account takeover unless an authorized real account login is proven.

Controls:

```bash
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/studentPhoneList?pageNo=1&pageSize=10'
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/teacherPhoneList?pageNo=1&pageSize=10'
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/achievement'
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/gzff/data'
```

All sampled sensitive APIs returned token-expired / login-required responses, so do not report unauthorized contacts, grades, or salary access.

### 2. ektm second-classroom management API base URL

Frontend `https://ektm.bzuu.edu.cn/static/js/app.*.js` contains module `QmSG` returning:

```text
https://ektm.bzuu.edu.cn/api/backend/server/v1/
```

Public config endpoint:

```bash
curl -4 --http1.1 -sk 'https://ektm.bzuu.edu.cn/api/backend/server/v1/common/all-school'
```

Returns only school metadata such as name, logo, id and hour unit. Other sampled endpoints returned login-required responses:

```bash
curl -4 --http1.1 -sk 'https://ektm.bzuu.edu.cn/api/backend/server/v1/index/statistics/info'
curl -4 --http1.1 -sk 'https://ektm.bzuu.edu.cn/api/backend/server/v1/index/activity/list'
curl -4 --http1.1 -sk 'https://ektm.bzuu.edu.cn/api/backend/server/v1/api/admin/resource/upload'
```

Decision: public metadata + CORS is low value; do not submit unless a future pass obtains unauthenticated activity/student/admin data or write/upload impact.

### 3. ekta second-classroom client API

Frontend `https://ekta.bzuu.edu.cn/static/js/app.*.js` exposes:

```text
baseURL: https://ekta.bzuu.edu.cn/api/app/client/v1/
```

It also encrypts request parameters in the client-side interceptor and stores `Token` in localStorage. Sampled API checks:

```bash
curl -4 --http1.1 -sk 'https://ekta.bzuu.edu.cn/api/app/client/v1/student/user/my-info'
curl -4 --http1.1 -sk 'https://ekta.bzuu.edu.cn/api/app/client/v1/activity/processing/statistics'
```

Returned:

```json
{"code":10001,"data":null,"msg":"登陆失败，请重新登陆","token":""}
```

Decision: JS API discovery only. Not reportable without unauthenticated/low-privilege data or token bypass.

### 4. jyxt ASP.NET SMS/reset chain

`https://jyxt.bzuu.edu.cn/Account/Login` exposes:

```text
AppCode = 'ZZZZ'
/Account/Login/SendSmsCode
/Account/Login/Validation_P
/Account/Login/Validation_S
/Account/Login/UpdateNewPassWord
```

Low-impact random probes with the page anti-forgery token returned:

```text
SendSmsCode: {"Success":false,"Result":"手机号码或姓名不存在！"}
Validation_P: {"Success":false,"Result":"验证码有误，请重新输入"}
Validation_S: {"Success":false,"Result":"请重新发送验证码"}
```

Decision: no SMS send, reset bypass, account takeover, or stable exploitable enumeration was proven. Do not submit generic ASP.NET errors or normal validation failures.

### 5. go-fastdfs still reproduces, but same old root cause

`/fileServer/status` still exposes internal file-server state including:

```text
"Fs.Local": "http://10.10.36.161:8080"
```

Low-impact txt upload still works:

```bash
curl -4 --http1.1 -sk -X POST 'https://oshall.bzuu.edu.cn/fileServer/upload' -F 'file=@/tmp/marker.txt;filename=bzuu_marker_20260525.txt' -F 'output=json2' -F 'scene=default'
```

Returned a path such as:

```text
/default/20260525/11/49/8/bzuu_marker_20260525.txt
```

Fetch with `/fileServer` prefix and `download=0`:

```bash
curl -4 --http1.1 -sk -D- 'https://oshall.bzuu.edu.cn/fileServer/default/20260525/11/49/8/bzuu_marker_20260525.txt?download=0'
```

Observed `Content-Type: text/plain; charset=utf-8` and the marker body.

Decision: same historical go-fastdfs issue; use only as supplemental evidence. Do not repackage as new upload/phishing unless a future pass proves a new executable/rendered impact or distinct root cause.

## Future BZUU reporting gate

Submit only if a future run proves one of:

- RCE, SQLi, auth bypass, arbitrary password reset, or real SMS abuse.
- Unauthorized access to real student/teacher/admin/activity/grade/salary data.
- IDOR over real records.
- File upload with new distinct impact beyond the old go-fastdfs root cause.
- Valid use of leaked token/secret/app credential to access protected data.

Do not submit:

- repeated go-fastdfs status/upload as a new report,
- ektm `common/all-school` public metadata,
- ekta baseURL/encryption/API paths alone,
- jyxt normal validation failures,
- getAppConfig as a duplicate if the medium-boundary report was already submitted.
