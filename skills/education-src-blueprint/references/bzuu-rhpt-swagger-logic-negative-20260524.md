# BZUU rhpt Swagger / 智慧校园逻辑漏洞续挖负证据 (2026-05-24)

## Scope

Target: `bzuu.edu.cn` / `oshall.bzuu.edu.cn` after the previously submitted go-fastdfs `/fileServer/status` root cause. Goal was to continue high-impact logic/API/auth/upload hunting and avoid repackaging non-reportable findings.

Evidence workspace:

```text
/tmp/bzuu_logic_20260524_1807
```

Important files:

```text
/tmp/bzuu_logic_20260524_1807/final_logic_system.md
/tmp/bzuu_logic_20260524_1807/swagger/https___oshall_bzuu_edu_cn_zhxyApi_swagger_resources_.body
/tmp/bzuu_logic_20260524_1807/swagger_docs2/rhpt-system.json
/tmp/bzuu_logic_20260524_1807/swagger_docs2/rhpt-workform.json
/tmp/bzuu_logic_20260524_1807/swagger_docs2/rhpt-applets.json
/tmp/bzuu_logic_20260524_1807/swagger_auth_tests/results.tsv
/tmp/bzuu_logic_20260524_1807/interface_token_fuzz/results.tsv
/tmp/bzuu_logic_20260524_1807/upload_verify2/
/tmp/bzuu_logic_20260524_1807/logic_probe.tsv
/tmp/bzuu_logic_20260524_1807/candidates.tsv
```

## Key technique: Swagger resources behind a gateway prefix

`oshall.bzuu.edu.cn` exposes Swagger resource metadata under the `zhxyApi` gateway prefix:

```bash
curl -4 --http1.1 -sk -D- "https://oshall.bzuu.edu.cn/zhxyApi/swagger-resources"
```

Observed HTTP 200 JSON with service document locations:

```text
/rhpt-interface/v2/api-docs
/rhpt-workhall/v2/api-docs
/rhpt-jimu/v2/api-docs
/rhpt-applets/v2/api-docs
/rhpt-workform/v2/api-docs
/rhpt-system/v2/api-docs
/rhpt-datafill/v2/api-docs
```

Direct service URLs such as `https://oshall.bzuu.edu.cn/rhpt-system/v2/api-docs` returned 302 to `/zhxy/home`. The correct fetch pattern is to preserve the gateway prefix:

```bash
curl -4 --http1.1 -sk "https://oshall.bzuu.edu.cn/zhxyApi/rhpt-system/v2/api-docs"
curl -4 --http1.1 -sk "https://oshall.bzuu.edu.cn/zhxyApi/rhpt-workform/v2/api-docs"
curl -4 --http1.1 -sk "https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/v2/api-docs"
```

This is useful for route discovery, but Swagger/API-document exposure alone is not a high-severity education-SRC report unless it leads to unauthenticated sensitive data access, token issuance, or a write operation.

## High-value logic routes discovered

From the Swagger docs, prioritize these families for future authenticated/authorization-bypass testing:

```text
/rhpt-applets/applets/gzff/data                                工资发放接口
/rhpt-applets/applets/synthesis/query/achievement               学生成绩查询
/rhpt-applets/applets/synthesis/query/studentPhoneList          学生通讯录查询
/rhpt-applets/applets/synthesis/query/teacherPhoneList          教师通讯录查询
/rhpt-applets/applets/workhall/api/verificationPhoneAndIdCard   原手机号和身份证号码校验
/rhpt-interface/zhxyInterfaceApi/getAccessToken                 第三方授权 token
/rhpt-system/appApi/listServerNode                              服务器节点列表
/rhpt-system/appApi/listDataBase                                数据源列表
/rhpt-system/appApi/listDataTables                              数据表列表
```

Low-impact unauthenticated probes showed the sensitive routes are currently token-protected:

```bash
curl -4 --http1.1 -sk "https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/gzff/data"
# 401 {"message":"Token失效，请重新登录"}

curl -4 --http1.1 -sk "https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/achievement"
# 401 {"message":"Token失效，请重新登录"}

curl -4 --http1.1 -sk "https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/studentPhoneList"
# 401 {"message":"Token失效，请重新登录"}

curl -4 --http1.1 -sk "https://oshall.bzuu.edu.cn/zhxyApi/rhpt-system/appApi/listDataBase"
# 401 {"message":"Token失效，请重新登录"}
```

Decision: do not report these as unauthenticated access unless a valid bypass/token/low-privilege IDOR proof returns real salary, grade, phonebook, identity-check, workflow, or datasource data.

## Third-party access-token endpoint

The route exists and reveals required parameters:

```bash
curl -4 --http1.1 -sk "https://oshall.bzuu.edu.cn/zhxyApi/rhpt-interface/zhxyInterfaceApi/getAccessToken"
# {"success":false,"message":"appId不能为空"}

curl -4 --http1.1 -sk "https://oshall.bzuu.edu.cn/zhxyApi/rhpt-interface/zhxyInterfaceApi/getAccessToken?appId=test"
# {"success":false,"message":"appSecret不能为空"}

curl -4 --http1.1 -sk "https://oshall.bzuu.edu.cn/zhxyApi/rhpt-interface/zhxyInterfaceApi/getAccessToken?appId=app&appSecret=test"
# {"success":false,"message":"appId不存在"}
```

Decision: this becomes high-value only if a real `appId/appSecret` is found in JS, mini-program bundles, historical files, config leaks, or third-party integration artifacts and can issue a token that reads/writes real business data.

## Upload boundary

Business upload endpoint remains protected:

```bash
curl -4 --http1.1 -sk -X POST "https://oshall.bzuu.edu.cn/zhxyApi/sys/common/upload" -F "file=@safe.txt"
# 401 Token失效
```

`fileServer/upload` still accepts unauthenticated safe files, but this is part of the already-submitted go-fastdfs/fileServer root cause:

```bash
curl -4 --http1.1 -sk -X POST "https://oshall.bzuu.edu.cn/fileServer/upload" \
  -F "file=@safe.txt;filename=bzuu_safe_logic.txt"
# returns http://oshall.bzuu.edu.cn:443/default/YYYYMMDD/.../bzuu_safe_logic.txt

curl -4 --http1.1 -sk -D- "https://oshall.bzuu.edu.cn/fileServer/default/YYYYMMDD/.../bzuu_safe_logic.txt"
# 200, Content-Type: application/octet-stream, Content-Disposition: attachment
```

Decision: treat as supplemental evidence for the old fileServer/go-fastdfs report only. Do not create a new high-risk file-upload report because files are served as `application/octet-stream` with `Content-Disposition: attachment`, not executed or rendered.

## Non-reportable checks in this round

Do not submit from this round:

- Swagger/API docs exposure alone.
- `Token失效，请重新登录` responses.
- CAS login page or JWXT login redirects.
- Empty dictionary/download/search responses.
- `getAccessToken` parameter errors without a working credential.
- `fileServer/upload` as a new report separate from the old go-fastdfs root cause.

## Future breakthrough conditions for BZUU

A new reportable high-impact root cause requires at least one of:

1. Real `appId/appSecret` issues a token via `/rhpt-interface/zhxyInterfaceApi/getAccessToken`.
2. Frontend/mini-program/history leaks a valid token/openId/appSecret.
3. Token validation bypass or weak binding lets unauthenticated users call salary, grade, phonebook, identity-check, workflow, or datasource APIs.
4. With a legitimate low-privilege account, IDOR/vertical-privilege bypass proves access to other users’ salary, grade, phonebook, applications, attachments, datasource metadata, or write actions.

Until then, the correct conclusion is “not recommended to submit.”
