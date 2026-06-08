# 临沂城市职业学院 LyWebServer 上传已报后的续挖负证据

适用场景：目标为 `lycvc.linyi.cn` 或同类 LyWebServer CMS，已提交 `/api/cms/upload` 未授权上传后，继续寻找新根因。

## 本轮结论

`/api/cms/upload?siteId=1930900465347256321` 是已报告过的根因，不要重复包装为新漏洞。续挖时必须寻找不同根因，例如新未授权敏感数据、认证绕过、SQLi、RCE、账号接管、可写入业务表单且可被后台读取等。

多轮低影响验证未发现新的可提交高价值漏洞。后续若没有新增资产或授权态入口，建议停止围绕主站静态 CMS 反复探测。

### 2026-05-24 续挖补充结论

再次从“证书 SAN / 同 IP vhost / 常见教育系统前缀 / JS/API / 端口”角度复核，仍未发现非上传根因的新高价值漏洞：

- 证书 SAN 仅为 `*.linyi.cn`、`linyi.cn`，未暴露 `lycvc` 专属新增资产。
- `subfinder -d lycvc.linyi.cn` 仅发现主站；`crt.sh` 当时返回 502，不能作为新增证据。
- 常见 vhost：`oa/sso/cas/authserver/ehall/jwxt/jwc/mail/lib/tsg/zsjy/job/vpn/webvpn/portal/api/cms/admin/ids/idp/zs/jy/xg/xyw.lycvc.linyi.cn` 通过 `--resolve` 固定到 `120.220.31.123` 后均为 LyWebServer 404，不是独立系统。
- 端口快速复核：仅 443 open；80/8080/8443 filtered。
- 首页 JS 仍只提取到 `/api/cms/captchaImage`、`/api/cms/upload?siteId=`、`/api/hits/v`；未发现 token、AppSecret、OA/CAS/ehall 或新 API baseURL。
- 页面引用 `https://yx.iotk12.com/pic/js/ai.min.js`，该路径当前 404；只作为第三方脚本线索，不构成学校侧漏洞。
- `/api/cms/upload` 仍可上传 `txt/html` 且文件可访问，证明原漏洞仍有效；但这是同一根因，只能补充原报告，不要新建报告。

复用命令模式：对该目标做 vhost 复核时优先使用短超时 `curl -skI --resolve <host>:443:120.220.31.123 --connect-timeout 2 --max-time 5 https://<host>/`，因为 Python 并发大爬虫容易被 DNS/网络超时拖住且无中间产物。


### 2026-05-24 修复不完全复测与命令正则坑

若平台显示 `lycvc.linyi.cn` 的 `/api/cms/upload` 已修复，应按“修复不完全/漏洞仍存在”角度复测，而不是当作新根因重复挖掘。复测门槛：无 Cookie、无 Authorization 上传一个无害 `html/txt` proof，接口返回 `code=200`、`url`，再访问该 URL 返回 `HTTP 200` 且 `Content-Type: text/html` 或 `text/plain`，响应体包含唯一 proof 字符串。

已验证复测命令形态：

```bash
curl -sk --resolve lycvc.linyi.cn:443:120.220.31.123 https://lycvc.linyi.cn/ | grep -o 'lysid="[0-9]*"' | head -1
printf '<!doctype html><html><head><meta charset="utf-8"><title>lycvc-upload-retest-PROOF</title></head><body><h1>lycvc-upload-retest-PROOF</h1><p>unauth upload retest proof</p></body></html>\n' > /tmp/lycvc-upload-retest-PROOF.html
curl -sk --resolve lycvc.linyi.cn:443:120.220.31.123 -X POST 'https://lycvc.linyi.cn/api/cms/upload?siteId=1930900465347256321' -F 'file=@/tmp/lycvc-upload-retest-PROOF.html;filename=lycvc-upload-retest-PROOF.html'
curl -sk --resolve lycvc.linyi.cn:443:120.220.31.123 -D- 'https://lycvc.linyi.cn/pic/YYYY/MM/DD/<returned>.html'
```

报告命令坑：`grep -o 'lysid="[0-9]"'` 只匹配一位数字（如 `lysid="1"`），真实 `lysid="1930900465347256321"` 是多位数字，必须写成 `grep -o 'lysid="[0-9]*"'` 或更稳的 `grep -o 'var lysid="[^"]*"'`。给用户报告/复测命令时必须使用多位数字版本，避免用户复制后无返回。

报告角度：标题用“未授权文件上传漏洞修复不完全，仍可上传并访问HTML文件”；漏洞 URL 仍是 `/api/cms/upload?siteId=1930900465347256321`；复现步骤突出“此前显示已修复，但无认证上传仍成功”。

## 稳定指纹

- 主站：`https://lycvc.linyi.cn/`
- A 记录：`120.220.31.123`
- Server: `LyWebServer`
- 首页变量：`var lysid="1930900465347256321"`
- 公开 JS：
  - `/static/common.js`
  - `/static/hits.js`
  - `/static/jquery.js`
  - `/pic/js/*.js`

JS 中仅稳定提取到：
- `/api/cms/captchaImage`
- `/api/cms/upload?siteId=`
- `/api/hits/v`

未发现新的后台 API、AppSecret、Token、OA/CAS/ehall 接口或敏感业务 API。

## DNS/探测稳定性注意

本目标在会话中多次出现 DNS 解析超时，尤其是 curl 默认解析阶段报：

```text
CODE=000 ERR=Resolving timed out after 2001 milliseconds
```

这不是目标漏洞，也不要记录为“站点不可用”。已知 IP 时可用 `curl --resolve` 固定解析继续低影响验证：

```bash
curl -skL --resolve lycvc.linyi.cn:443:120.220.31.123 --connect-timeout 3 --max-time 8 https://lycvc.linyi.cn/
```

后续批量脚本应对该目标使用短超时、小批量、流式落盘，避免 Python 大爬虫在 DNS/网络超时上长时间卡住且无中间产物。

## 已验证但不可提交的点

### 1. `/api/cms/captchaImage`

现象：
- 未授权返回验证码图片 base64。
- 响应可反射任意 `Origin`，并带 `Access-Control-Allow-Credentials: true`。

验证示例：

```bash
curl -sk --resolve lycvc.linyi.cn:443:120.220.31.123 -D- -H 'Origin: https://evil.example' 'https://lycvc.linyi.cn/api/cms/captchaImage'
```

判定：
- 只返回验证码图片，不含敏感数据。
- CORS 不能单独提交；必须能跨域读取敏感数据或链到账号/业务影响才有价值。

### 2. `/api/cms/upload`

现象：
- `GET` 返回 `{"code":500,"msg":"Request method 'GET' not supported"}`。
- `POST multipart` 即历史未授权上传根因。

判定：
- 已提交过上传漏洞后，只能作为原报告补充证据，不要新建重复报告。

### 3. `/api/cms/feedback`

现象：
- `GET` 返回 `Request method 'GET' not supported`。
- 空 JSON `POST` 返回 `{"code":500,"msg":"征集编号不能为空"}`。
- form-urlencoded `POST` 返回 `{"code":500,"msg":"系统异常: /api/cms/feedback"}`。
- `id/zjid/zjId/siteId/contentId/pid` 等参数组合仍只返回“征集编号不能为空”或系统异常。

判定：
- 只证明接口存在和参数校验，未证明可写入成功、后台可读取、XSS/SQLi 或业务影响。
- 不建议提交。

### 4. `/api/hits/v`

有效参数示例：

```bash
curl -sk --resolve lycvc.linyi.cn:443:120.220.31.123 -X POST 'https://lycvc.linyi.cn/api/hits/v' -H 'Content-Type: application/x-www-form-urlencoded' --data 'lyuid=&title=test&url=https://lycvc.linyi.cn/a/4033/283/2057644864713555970.html&sid=1930900465347256321&cid=4033&pid=2057644864713555970&ptype=1'
```

可能返回：
- `{"lyuid":"...","hits":21}`
- `{"hits":22}`

判定：
- 本质是访问量统计/刷点击，危害低。
- 不符合 RCE/SQLi/越权/认证绕过/未授权敏感数据门槛。

### 5. 站内搜索 `/ssjg/index.html`

测试：
- `/ssjg/index.html?wd=test&cid=0`
- `/ssjg/index.html?wd=%27&cid=0`
- `/ssjg/index.html?wd=test%27&cid=0`
- `/ssjg/index.html?wd=无人机&cid=0`

结果：全部返回相同大小、相同 hash 的静态搜索结果页：
- HTTP 200
- 19234 bytes
- sha1: `8004c8d53f4a8be74fdd9712306979aaa33150a0`
- 未出现 `SQL`、`Exception`、`syntax`、差异化搜索结果或错误栈。

判定：
- 未发现 SQL 注入。
- 这是静态/伪搜索结果页或前端模板，不建议提交。

### 6. 站内页面/表单

已覆盖：网站地图、招生就业、人才招聘、信息公开、学生工作、图书馆、继续教育、二级学院等页面。

发现：
- 页面基本都是静态 LyWebServer CMS 生成页。
- 表单主要是站内搜索。
- 未发现新的登录、报名、留言、招聘投递、后台业务表单入口。

图书馆“馆长信箱”链接：
- `/tsggzxx_tj.jsp?urltype=tree.TreeTempUrl&wbtreeid=1175`
- `/tsggzxx_tj.jsp`
- 以及若干 Visual SiteBuilder/JSP 风格旧路径

结果：均 404，不构成漏洞。

## 已排除路径

以下均未形成可提交漏洞：
- `/.git/HEAD`
- `/.env`
- `/WEB-INF/web.xml`
- `/actuator/env`
- `/swagger-ui.html`
- `/v2/api-docs`
- `/v3/api-docs`
- `/doc.html`
- `/druid/index.html`
- `/backup.zip`, `/www.zip`, `/db.sql`, `/backup.sql`
- `/admin`, `/login`, `/cms/login`, `/admin/login.html`, `/lyadmin`, `/lycms`
- `/api/admin/login`, `/api/user/info`
- `/static/config.js`, `/config.js`, `/env.js`
- `/fileServer/status`
- Visual SiteBuilder/JSP 老路径：`/system/resource/code/*`, `/pic/system/go.jsp`, `/tsggzxx_tj.jsp`

多数为 404、统一错误页、或仅 CORS 反射错误响应。

## 子域名结论

常见学校系统前缀快速验证：
- `oa`, `sso`, `cas`, `authserver`, `ehall`, `jwxt`, `jwc`, `mail`, `lib`, `tsg`, `zsjy`, `job`, `vpn`, `webvpn`, `portal`, `api`, `cms`, `admin`, `ids`, `idp`

结果：仅 `lycvc.linyi.cn` 稳定解析并存活；未发现 CAS、ehall、OA、教务、邮箱、VPN 等独立系统资产。

## 续挖决策

继续投入前先问：是否能找到“非上传根因”的新证据？

值得继续的方向：
1. 新资产：真实后台域名/管理端入口、CAS/ehall/OA/招生就业系统，而不是主站 404 路径。
2. 真实业务 API 未授权读取敏感数据。
3. 表单/feedback 类接口成功写入并能在前台或后台被读取，且能证明影响。
4. 新子域名上不同系统暴露。
5. 上传根因的补充攻击演示只用于原报告增强，不另起新报告。

不建议提交：
- CORS + captchaImage。
- hits 刷访问量。
- feedback 参数错误/系统异常。
- GET upload method not supported。
- 静态搜索页 200。
- JSP/Visual SiteBuilder 老路径 404。
- 404/错误页带 CORS。
