# 湖南农业大学 wzhd 问卷系统 CORS 复现边界记录

## 适用场景
教育 SRC 中遇到 TRS/IGI 类问卷、互动、征集系统，页面形如：

`/personalCenter/answerSheet/answerSheet.html?metadataId=<id>&siteId=<siteId>`

前端 JS 通过 `/IGI/open/answer/getSurvey` 获取问卷结构，通过 `/IGI/open/answer/collect` 提交答卷。

## 低影响验证流程

1. 抽取问卷前端 JS：
   - `server.js` 中通常封装 `$.ajax`，默认 POST、`application/x-www-form-urlencoded`，并带 `formdata: 1`、`distributionType: 1`。
   - `answerSheetForm.js` 中重点找：
     - `/IGI/open/answer/getSurvey`
     - `/IGI/open/answer/collect`
     - `/IGI/survey/getSurveyById`

2. 验证 CORS 任意 Origin 反射：

```bash
curl -sk -D- -o /tmp/hunau_getSurvey.json "https://TARGET/IGI/open/answer/getSurvey" -H "Origin: https://evil.example" -H "formdata: 1" -H "Content-Type: application/x-www-form-urlencoded" -H "distributionType: 1" --data "id=METADATA_ID&siteId=SITE_ID"
```

漏洞成立头：

```text
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
```

3. 验证 OPTIONS 预检：

```bash
curl -sk -X OPTIONS -D- -o /dev/null "https://TARGET/IGI/open/answer/getSurvey" -H "Origin: https://evil.example" -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: content-type,formdata,distributiontype"
```

## 湖南农业大学实测锚点

目标：`wzhd.hunau.edu.cn`

问卷页面：
`https://wzhd.hunau.edu.cn/personalCenter/answerSheet/answerSheet.html?metadataId=82b182fd95f029700197b05849000000&siteId=160`

稳定接口：
`https://wzhd.hunau.edu.cn/IGI/open/answer/getSurvey`

请求体：
`id=82b182fd95f029700197b05849000000&siteId=160`

稳定返回：
- `statusCode: 200`
- 标题：`关于开展第二轮“献策湘农‘十五五’”金点子征集活动的公告`
- 字段结构包含：姓名、联系电话、邮箱、标题、内容
- 响应头反射任意 Origin 且 `Access-Control-Allow-Credentials: true`

## 报告边界与不要过报

- 可以报告：CORS 配置不当，任意第三方站点可跨域读取该公开问卷接口 JSON 数据；若同源下有登录态接口复用同策略，存在凭证跨域读取风险。
- 不要报告为：未授权导出答卷、后台统计泄露、任意提交有效问卷，除非已经拿到对应接口的实际数据。
- 湖南农业大学该次验证中：
  - `/IGI/open/answer/collect` 可跨域，但问卷已结束，返回 `{"statusCode":400,"message":"问卷已结束回收"}`，不能写成有效提交。
  - `/IGI/survey/getSurveyById` 未登录返回 `{"statusCode":302,"message":"获取用户登录信息失败"}`，不能写成后台问卷未授权。
  - `/IGI/open/answer/list`、`export`、`statistics`、`chart` 等猜测接口返回 404/学校内网资源访问提示，不能写成答卷导出或统计泄露。
  - 招聘系统 `zp.hunau.edu.cn` API 从外网多为学校内网资源访问提示，不能写成招聘数据未授权。

## 提交建议

教育 SRC 若只收实质性 RCE/SQLi/越权，该类 CORS 可能被降级或忽略；提交时建议定为“CORS 配置不当/安全配置错误”，中危或低危偏中，不要包装成高危数据泄露。报告必须包含：

1. 前端 JS 接口来源截图/代码片段；
2. 带 `Origin: https://evil.example` 的 curl 请求；
3. 响应头中 `Access-Control-Allow-Origin` 反射和 `Access-Control-Allow-Credentials: true`；
4. JSON 响应中实际可读取的问卷标题、字段结构；
5. 明确说明未验证到答卷导出/后台统计，避免过报。
