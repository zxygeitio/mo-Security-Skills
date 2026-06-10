# SRC 报告命令正确性硬门禁与 bzuu.edu.cn 复测经验

适用场景：教育 SRC / 公益 SRC / 外网 Web 漏洞报告输出前的最后验证，尤其是用户指出上次报告存在协议、路径或参数命令错误之后。

## 核心规则

1. 报告中的每一条 curl / PoC 命令必须在本机实测后再写入报告。
2. 实测必须覆盖：协议、Host、路径、参数、Header、请求方法、状态码、响应体关键特征。
3. 禁止把以下内容包装成报告：
   - 404 / 401 / 403 / 302 跳转但没有越权或数据证据；
   - SPA fallback、统一错误页、WAF 拦截页；
   - 仅前端配置、公开登录参数、公开 AppId、普通 JS 路径；
   - 已提交过的同根因漏洞；
   - 未形成数据读取、文件写入、认证绕过、越权、RCE、SQLi、敏感信息实质泄露的候选。
4. 如果候选点没有达到中危以上实质危害，输出“不建议提交”，不要凑报告。
5. 报告前保留验证目录，至少包含：响应头、响应体、汇总表、最终可复制命令。

## 推荐验证产物结构

在 /tmp 下建立每次任务独立目录，例如：

- alive.tsv：存活资产与标题、状态码、Server、最终 URL
- js_urls.sorted：提取到的 JS / JSON 资源
- interesting.txt：从 JS 中提取的 API、upload、download、token、auth 等候选
- verify/summary.txt：逐条 curl 验证结果
- verify/*.hdr：响应头
- verify/*.body：响应体
- final_candidates.txt：只保留进入报告评审的候选

## curl 验证门禁模板

单接口验证：

curl -sk --connect-timeout 5 --max-time 15 -D /tmp/resp.hdr -o /tmp/resp.body -w '%{http_code} %{size_download} %{content_type} %{url_effective}\n' 'https://target.example/path?x=1'

POST / 上传 / 认证边界验证时必须额外记录请求方法和关键 Header：

curl -sk --connect-timeout 5 --max-time 20 -X POST -H 'Content-Type: application/x-www-form-urlencoded' -D /tmp/post.hdr -o /tmp/post.body -w '%{http_code} %{size_download} %{content_type}\n' --data 'a=1&b=2' 'https://target.example/api'

CORS/OPTIONS 只能作为辅助证据，不能单独作为中高危报告：

curl -sk --connect-timeout 5 --max-time 15 -X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: POST' -D /tmp/cors.hdr -o /tmp/cors.body -w '%{http_code} %{size_download}\n' 'https://target.example/api'

## bzuu.edu.cn 复测经验

本轮对 bzuu.edu.cn 深挖得到的可复用判断：

- oshall.bzuu.edu.cn/fileServer/status 若仍 200，属于已提交 go-fastdfs 未授权/信息泄露同根因；除非出现新的可写入、可解析、可访问证明，否则不要重复提交。
- oshall.bzuu.edu.cn/fileServer/static/uppy.html 暴露示例页面和示例 auth_token，只能作为线索；必须证明真实上传成功、可访问、可造成实际危害才可报。
- oshall.bzuu.edu.cn/zhxy/env.js 暴露 zhxyApi、CAS、fileServer、wxAppId/tbAppId、manageUrl 等，默认按前端配置暴露处理；没有接口越权或数据返回时不建议提交。
- oshall.bzuu.edu.cn/zhxyApi/sys/common/upload 返回 401 时，不可包装成未授权上传。
- auth.bzuu.edu.cn/authserver/loginParam 返回登录页展示配置、联系方式、提示语，通常属于公开配置，不建议提交。
- vpn/sso/oa/webvpn 深信服 / Portal 入口中的 /por/get_sms.csp、/por/login_sms*.csp 若仅返回 unexpected user service / session timeout / maybe attacked，不构成短信漏洞或认证绕过。
- lib.bzuu.edu.cn JS 中的 readercenter/opac/api 路径若实际 404 或需登录，不作为漏洞报告。

## 报告输出决策

满足以下任一条件才继续写报告：

- 未授权读取到非公开业务数据、个人信息、内部资产信息或敏感配置；
- 文件上传成功且文件可访问，并能证明危害，不仅是静态 HTML 不解析；
- 认证绕过、任意验证码/短信可滥用、越权访问、IDOR、SQLi、RCE 等已被对照验证；
- 前端泄露的 token / secret / appSecret 能进一步访问数据接口。

否则最终答复应明确：不建议提交，并简述已排除项和原因。
