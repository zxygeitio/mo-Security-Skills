# 高校 SRC 低噪声验证与“不建议提交”门禁案例：NJAU

适用场景：高校主域资产很多、WAF/统一认证/CAS/站群系统混杂，目标是筛出可提交的实质漏洞，而不是把配置缺陷包装成报告。

## 可复用流程

1. 先做低噪声资产面：公开证书源 + subfinder + 手工 seed，去重后只对 HTTP 存活目标做高价值筛选。
2. 对 SPA 应用不要只测页面前缀路由：
   - 先抓 JS chunk，提取字符串中的真实 API path。
   - 同时测试“SPA 前缀路径”和“根路径 API”。NJAU 的 order 应用中 `/v2/api/*` 是 SPA fallback，真实 API 在根路径 `/api/*`。
3. 对 RSFW/EMAP/金智类系统优先测只读接口与上传接口的鉴权状态：
   - `/sys/emapcomponent/file/getFileBatchByTokenArray.do`
   - `/sys/emapcomponent/file/getUploadedAttachment.do`
   - `/sys/emapcomponent/schema/getList.do`
   - `/sys/emapcomponent/import/schema/list.do`
   - `/sys/emapflow/definition/queryFormActions.do`
   - `/sys/emapcomponent/file/uploadTempFile.do`
   结果若是 CAS 跳转、401、404、系统异常且无敏感数据，不要包装报告。
4. CORS 判断必须做二次利用门禁：
   - 仅有 `Access-Control-Allow-Origin` 反射或 `Access-Control-Allow-Credentials: true` 不足以提交。
   - 需要证明 200 业务接口可跨域读取登录态敏感数据。
   - 302 到 errorPage、静态 JS、403 拒绝页、OPTIONS 空响应都只能记为配置候选。
5. CAS logout/open redirect 判断门禁：
   - 若 `logout?service=https://evil.example.com/` 只是把 service 写入页面 JS 或“重新登录/安全退出”链接，不发生服务端 302，不算实质开放跳转。
   - 用跟随跳转验证 `history` 和 final_url；无自动跳转则不建议提交。
6. WP3/SUDY 站群接口门禁：
   - `/_wp3services/generalQuery?queryObj=articles` 缺参报错、带 siteId 返回公开新闻，通常是正常公开接口。
   - 只有公开文章列表不算信息泄露。
   - 注入 payload 若被“访问禁止”统一拦截，不能包装为 SQLi。
7. 对 Swagger/Actuator/Druid/.env/WEB-INF 做保守只读探测即可；403、CAS、统一错误页不构成漏洞。

## 证据落盘建议

为每类候选保存：
- 汇总 TSV：路径、方法、状态码、长度、Content-Type、Location、ACAO/ACAC、body sample。
- 每个请求的 `.hdr` 和 `.body` 原始证据。
- 最终报告中明确“为什么不建议提交”，避免后续误把候选当漏洞。

## 不建议提交判定模板

满足任一情况时，直接写“不建议提交”：
- 仅配置缺陷，无敏感数据读取/写入/越权闭环。
- 只有公开站点信息、公开新闻、公开静态资源。
- 需要登录但无授权账号验证，不推测登录后危害。
- 响应是 302/CAS/401/403/404/统一错误页。
- 上传接口返回“请先登录”或未返回可访问 fileUrl/token。

## 代表性复现命令形态

CORS 候选：
`curl -k -i 'https://target.example/api/' -H 'Origin: https://evil.example.com' -H 'User-Agent: Mozilla/5.0 Hermes SRC low-noise'`

SPA 根 API 对比：
`curl -k -i 'https://target.example/api/home/site-options' -H 'Accept: application/json' -H 'User-Agent: Mozilla/5.0 Hermes SRC low-noise'`
`curl -k -i 'https://target.example/v2/api/home/site-options' -H 'Accept: application/json' -H 'User-Agent: Mozilla/5.0 Hermes SRC low-noise'`

CAS logout 跳转门禁：
`curl -k -i 'https://auth.example/authserver/logout?service=https://evil.example.com/' -H 'User-Agent: Mozilla/5.0 Hermes SRC low-noise'`

## CVE版本验证门禁 (重要)

**错误案例**: 报告Tomcat 7.0.109受CVE-2023-45648/CVE-2023-42795/CVE-2023-41080影响，实际上这些CVE影响的是Tomcat 8.5.x/9.x/10.x，不适用于7.x。

**规则**: 提交CVE相关报告前必须验证:
1. 确认目标实际版本号 (从错误页/Server头/响应头提取)
2. 查询NVD/CVE详情，确认受影响版本范围包含目标版本
3. Tomcat版本对应关系: 7.x(2011-2022), 8.x(2014-), 9.x(2018-), 10.x(2020-)
4. Tomcat 7.0.109是7.x最终版本(2022-01-13发布，EOL)，已修复发布前所有CVE

**验证命令**:
```bash
# 获取Tomcat版本
curl -sI 'http://target/' | grep -i server
curl -sL 'http://target/o/' | grep 'Apache Tomcat'  # 503错误页泄露版本

# 查询CVE受影响范围
# 访问 https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX 查看"Affected Products"
```

**常见误判**:
- Tomcat 7.0.109 ≠ Tomcat 7.x (7.0.109是7.x最后版本，已修补)
- Liferay Portal版本 ≠ Tomcat版本 (Liferay可能使用旧版Tomcat)
- 404/503页面的Server头可能被反向代理隐藏

## 关键经验

高校 SRC 深挖时，最有价值的不是"发现很多候选"，而是迅速淘汰不可提交项：CORS 反射、公开 WP3 查询、CAS 注销链接污染、SPA fallback、系统异常页都很常见。没有敏感数据/越权/写入/RCE/SQLi 闭环时，应给出"不建议提交"，不要为了产出报告降低门槛。
