---
name: education-src-blueprint
description: "教育SRC漏洞挖掘蓝图 — 目标筛选→漏洞类型优先级→利用验证→报告质量门禁→提交决策树。详细历史案例已拆到 references。"
tags: [education, src, butian, cas, ehall, wisedu, lyuap, report-gate]
---

# 教育 SRC 蓝图轻量入口

## 适用场景

- 目标是高校、学院、教育集团、教育局、智慧校园、CAS/统一身份认证、办事大厅、教务、OA、招生、邮箱、VPN/WebVPN。
- 用户要求提高教育 SRC 通过率、减少低价值报告、定位可提交实质漏洞。
- 需要把教育目标的大量子域快速分流为值得深挖的业务系统。

## 核心判断

教育 SRC 最常见失败原因不是"没扫到东西"，而是把低价值信息泄露当漏洞提交。必须优先找能证明业务影响的漏洞：账号/身份/学生或教职工数据、办事流程、成绩/课程/缴费/一卡通、后台管理、文件上传下载、CAS ticket/service、API Key 可用性。

**⚠️ 用户明确要求"高危漏洞"和"可利用的"**（2026-06-09反复强调）。低危信息泄露（CORS、Actuator暴露、SAML元数据、微信AppID泄露、堆栈跟踪）不被视为有价值漏洞。CAS Open Redirect单独报告可能被SRC拒收。优先级：RCE > SQLi > 认证绕过 > IDOR/越权 > 未授权敏感数据访问 > SSRF(需证明可达) > 文件上传 > 弱口令可登录。信息泄露类（CORS/Actuator/元数据/版本号/密钥泄露）单独不报，必须链到数据访问或认证绕过。

## 优先级矩阵

- P0/P1：CAS 认证绕过、CAS Open Redirect 可窃 ticket、越权读取学生/教职工数据、未授权管理 API、SQLi/RCE、文件上传可访问、AppSecret/API Key 可调用敏感接口。
- P1/P2：CORS 读取登录态敏感接口、验证码/找回密码逻辑缺陷、用户枚举带稳定差异、Swagger/Actuator 暴露且可调用敏感功能、OA API 未授权。
## P3/不报：安全头缺失、jQuery/中间件版本、robots、普通登录页、盐值/JSESSIONID 单独泄露、无敏感数据 CORS、SUDY 后台 IP、站点地图/通知公告、SPA fallback 假 200、**CAS Open Redirect（2026-06实测连续被SRC审核拒绝，不单独报告）**。

## 教育目标分流

1. 先看核心入口：`auth`/`authserver`/`cas`/`sso`/`ids`/`one`/`ehall`/`portal`/`jw`/`oa`/`webvpn`/`vpn`/`mail`/`ecard`/`pay`。
2. 识别供应商：金智/Wisedu、联奕/Lianyi、Apereo CAS、泛微、致远、SUDY、VSB、强智、正方、青果、网瑞达/wengine-auth、JEECMS、博达网站群。
3. 对高价值入口生成小批 URL，交给 `src-http-probe.py --control --dedupe`，再由 `src-quality-gate.py` 过滤假阳性。
4. 5 分钟内没有 P0/P1 候选则换入口；不要在新闻站、静态站、纯门户上耗时。

## grep 正则陷阱

手动验证 IP 泄露、敏感字段时，grep 正则必须用量词：
- 正确: `grep -oP 'value="[^"]*"'` 或 `grep -o 'value="[0-9.]*"'`
- 错误: `grep -o 'value="[0-9.]"'`（少了 `*` 只匹配单个字符，无输出）

## wengine-auth (网瑞达) 认证网关指纹 (2026-06-09 cust.edu.cn实战)

多个中国高校使用网瑞达(wengine)作为统一认证网关，保护教务、办事大厅等系统。详见 `references/wengine-auth-fingerprinting.md`。

**快速指纹：**
- 重定向URL包含 `wengine-auth/login?id=XX`
- Server: none
- Cookie: `wengine_new_ticket=xxx`
- 404页面: `/wengine-auth-failed.png`
- 关键词: `网瑞达`、`资源访问控制系统`、`clientless vpn`

**认证流程：**
1. 访问受保护系统 → 302到 `wwwn.cust.edu.cn/wengine-auth/login`
2. 再302到CAS登录（如 `mysso.cust.edu.cn/cas/login?service=http://wwwn.cust.edu.cn/wengine-auth/login?cas_login=true`）

**测试要点：** CAS漏洞会影响所有wengine保护的系统

## JEECMS v9 指纹识别 (2026-06-09 cust.edu.cn实战)

就业信息网等系统常使用JEECMS：

**指纹特征：**
- 路径：`/r/cms/`、`/admin/login`、`/jeecms/`
- 404页面包含：`jeecmsv9f`、`data-genuitec-path`
- JS路径：`/r/cms/jquery.js`、`/r/cms/front.js`
- Cookie: `_site_id_cookie`

**测试要点：**
- 检查 `/actuator/health`（可能返回403但存在）
- 检查 `/admin/login`（管理后台）
- 检查 `/api/`、`/rest/`（API端点）

## 已加固目标处置

当全部攻击面（SQLi/文件上传/LFI/RCE/认证绕过/SSRF/XXE/目录遍历/.git泄露/CORS/数据库未授权）均测试通过且无发现时：
1. 不要反复重测同一攻击面（浪费时间且用户会不满）
2. IP 泄露类发现需验证 IP 身份：若泄露 IP 是 CDN/WAF 的 DNS 服务器而非 origin server，价值显著降低
3. 只有信息泄露的教育目标应明确告知用户"无中高危可利用漏洞"，不包装低危为高危
4. 向用户建议换目标或接受信息泄露报告

## 标准执行

```bash
/usr/bin/python3 /root/.hermes/scripts/src-fast-assess.py example.edu.cn --out /tmp/src_assess_example
/usr/bin/python3 /root/.hermes/scripts/src-practical-next.py /tmp/src_assess_example --out /tmp/src_assess_example/next.md --json-out /tmp/src_assess_example/next.json
/usr/bin/python3 /root/.hermes/scripts/src-http-probe.py /tmp/src_assess_example /tmp/src_assess_example/urls.txt --timeout 8 --control --dedupe
/usr/bin/python3 /root/.hermes/scripts/src-quality-gate.py /tmp/src_assess_example/probe_results.tsv --out /tmp/src_assess_example/quality_gate.md --json-out /tmp/src_assess_example/quality_gate.json
```

说明：命令是模板，正式目标根据 `next.md` 选 5-20 个高价值 URL 建 `urls.txt`，不要全量盲打。

## CAS 专项门禁

- Open Redirect：必须证明 `service` 接受外域/危险 scheme，并说明 ticket 风险；最好用安全接收域演示跳转链。
- **CAS clientredirect 验证法（2026-06-09 实测）**：当CAS登录页面包含微信/企业微信登录时，检查页面中 `clientredirect` URL是否包含恶意service参数。这是验证CAS Open Redirect的有效方法：
  ```bash
  curl -sk 'https://mysso.target/cas/login?service=https://evil.com/steal' | grep -oP 'clientredirect[^"]*evil[^"]*'
  # 返回: clientredirect;jsessionid=xxx?client_name=WeChatPublic&service=https://evil.com/steal
  ```
  如果 `clientredirect` URL 包含恶意域名，说明CAS确实接受了任意service参数。
- 用户枚举：必须有存在/不存在账号稳定差异，且低频验证；不要爆破。
- ⚠️ 金智CAS常见假阳性：部分部署对所有用户名返回相同消息（如"您的账号尚未激活"），必须测试≥3个不同用户名确认差异存在，否则不可提交。验证方法：同时测试admin/test/随机不存在用户名，比较响应是否一致。
- 验证码缺陷：证明服务端未校验或验证码明文可复用；客户端校验本身不一定可提交。
- 盐值泄露：单独低价值；必须链到密码加密绕过、撞库增益或其他实质影响。
- CORS：必须证明浏览器可读登录态敏感接口；只有预检反射但无敏感读取通常低危或不报。

## 审核拒绝高发类型（实战经验）

以下类型漏洞在实际SRC审核中经常被拒绝或判定为低价值，不要花费大量时间深挖：

**CAS相关（通过率极低）：**
- CORS配置不当（wildcard+credentials）— 几乎所有学校都这样配置，审核员不认为是漏洞
- CAS Open Redirect（service参数接受外域）— 即使能窃取Ticket，审核员常以"需要社工配合"拒绝。**2026-06-09实测：长春理工大学CAS Open Redirect被SRC审核拒绝。** 即使用clientredirect验证法证明漏洞存在，仍被拒绝。
- CAS用户枚举（错误信息差异）— 除非能稳定区分存在/不存在用户
- CAS盐值泄露 — 无实际利用价值
- CAS JSESSIONID泄露 — 单独无价值

**信息泄露类（需配合攻击链）：**
- Actuator/Swagger/Druid暴露（被WAF拦截时更无价值）
- 堆栈信息泄露（500错误页面）
- 服务器版本/中间件版本
- 安全头缺失
- robots.txt/sitemap.xml

**ehall/门户类：**
- JSONP API未授权访问（只返回配置信息，无业务数据）
- school.json/userInfo.json等游客接口
- 应用列表/应用配置泄露

**真正有价值的漏洞类型（优先投入）：**
- SQL注入（业务系统，如教务/研招/学工）
- 认证绕过（直接访问受保护数据）
- IDOR/越权（读取其他学生信息/成绩）
- 文件上传（webshell执行）
- 弱口令（可登录的真实账号）
- 未授权API返回真实业务数据（学生信息/成绩/财务）
- RCE（远程代码执行）

**判断标准：** 如果漏洞不能直接导致"读取/修改/删除其他用户数据"或"执行代码"，大概率会被拒绝。

提交前必须满足：

- 重新执行 PoC 成功，响应内容与报告一致。
- 有对照组：无效 token、随机路径、不存在 ID、未登录态、不同 Origin 或不同账号。
- 有证据落盘：headers/body/curl/截图位置。
- 无历史重复：查 `session_search` 与 `/tmp/vuln_reports`。
- 字段完整：标题/域名/类型/等级/行业/精确到区地址/URL/详情/复现/影响/修复。
- 不能夸大：无法证明数据访问、越权或攻击结果时，写“不建议提交”。

## IP泄露验证门禁（重要）

发现IP地址泄露时，**必须验证是否为真实服务器IP**，而非CDN/WAF基础设施IP。误报会导致报告被拒。

验证步骤：
1. DNS解析域名，对比泄露IP与解析IP是否在同一网段
2. 查询泄露IP的地理位置和ISP（`curl -sk "http://ip-api.com/json/<IP>"`）
3. 直接用泄露IP访问Web服务（`curl -sk -H "Host: domain" http://<IP>/`），看是否返回真实内容
4. 检查泄露IP是否运行CDN/WAF特征服务（DNS服务器、代理端口1080/3128/8080等）
5. 对比域名解析IP网段（如198.18.x.x是常见CDN网段）

典型CDN/WAF IP特征：
- 解析到198.18.x.x、198.19.x.x等网段
- 泄露IP位于香港/海外，ISP为CDN提供商
- 泄露IP开放DNS(53)、代理(1080/3128/8080)等端口
- 泄露IP的dig查询返回域名解析到CDN网段

案例：njmu.edu.cn的SUDY CMS泄露IP 109.122.3.227，经验证为香港Alice Networks LTD的CDN DNS服务器，非真实服务器IP。

## PoC命令质量门禁

提供给用户的PoC命令必须**直接可复制执行**，常见陷阱：
- grep正则必须完整：`value="[0-9.]*"` 而非 `value="[0-9.]"`（缺少`*`量词）
- 优先使用 `-oP` (Perl正则) 替代 `-o` (基本正则)，避免兼容性问题
- 测试命令在实际环境执行验证后再提供给用户
- 单行curl命令避免行尾反斜杠续行

## Pitfall: 用户要求"真正有价值的漏洞"（重要 — 2026-06-09 三次纠正）

用户在同一次会话中三次明确拒绝低危发现：
1. "这些漏洞危害都不大请继续挖掘高危漏洞并要可利用的"
2. "这些漏洞危害都无请按照真正有价值的漏洞去专研挖掘"
3. "这些漏洞危害不大请寻找危害大的漏洞请深入挖掘不要偷懒也不要想在给我省token不需要你要全力挖掘就行"

**关键信号**：用户明确说"不要偷懒"、"不要省token"、"全力挖掘"。这意味着：
- 发现低危漏洞后必须继续深挖，不能停下来报告
- 不能因为"目标防护严格"就放弃，要尝试所有攻击向量
- 每次输出必须包含新的实质性发现，不能重复已知信息

**执行规则**:
1. 发现低价值漏洞后, 继续深挖高危漏洞, 不要停下来报告低危
2. 优先寻找: CAS认证绕过、Open Redirect可窃Ticket、IDOR/越权、SQLi/RCE、未授权API返回业务数据、文件上传
3. 低危发现只在最后作为附录, 不作为独立报告
4. 如果5分钟内没有P0/P1候选, 换入口或换目标, 不在低价值发现上反复包装
5. **不要用"目标防护严格"作为停止挖掘的理由** — 换攻击面、换子域名、换技术栈
6. **每次向用户汇报时，必须有新的实质性进展**，不能只说"已测试X个系统，未发现漏洞"

## 常见反驳清单

- 这是公开信息还是敏感业务数据？
- 是否只是登录页、错误页、WAF 页、SPA fallback？
- 是否有随机不存在路径对照？
- 是否有鉴权对照或不同账号对照？
- 是否只是版本/CVE 猜测，未验证适用？
- 是否同根因已提交？
- 是否超出教育 SRC 授权范围？

## PoC 命令常见陷阱

### grep 正则遗漏量词
用户执行 `grep -o 'value="[0-9.]"'` 匹配不到结果，因为 `[0-9.]` 只匹配**单个字符**。
正确写法必须加 `*` 量词：`grep -o 'value="[0-9.]*"'`，或用 `-oP` Perl正则：`grep -oP 'value="[^"]*"'`。
**经验法则**：PoC 中的 grep 正则凡是涉及多位数字/字母的字符类，必须检查是否缺少 `+` 或 `*` 量词。提供 PoC 时优先用 `-oP 'value="[^"]*"'` 这种不依赖量词的写法，更不容易出错。

### src-http-probe.py 假阴性
SUDY CMS 的 `/_web/_portal/api/user/main.psp` 在自动化探测中被判定为 `LOGIN_OR_AUTH_REQUIRED`（假阴性），但手动 curl 可正常获取 IP 泄露数据。**验证此类漏洞必须手动 curl 复现，不能依赖自动化 probe 结果作为最终判断。**

## Pitfall: SUDY CMS PSP 端点质量门禁假阴性

SUDY WebPlus CMS 的 `/_web/_portal/api/user/main.psp` 端点存在 IP 泄露漏洞（返回 `<input id="ipAddress" value="真实IP"/>`），但 `src-http-probe.py --control` 会将其判为 `LOGIN_OR_AUTH_REQUIRED` 并拒绝。原因：probe 的 control 请求可能触发不同响应路径，或 PSP 端点对特定 User-Agent/Referer 返回登录提示而非 IP。

**规则：对 SUDY CMS 目标，PSP/RST 端点必须手动 curl 验证，不能仅依赖自动化 probe 结果。** 验证命令：
```bash
PoC: curl -sk "https://kdc.njmu.edu.cn/_web/_portal/api/user/main.psp" | grep -oP 'value="[^"]*"'
⚠️ grep陷阱: 必须用 `value="[^"]*"` 或 `value="[0-9.]*"`，不能用 `value="[0-9.]"`（少了`*`只匹配单个字符，无输出）
```

## Pitfall: 教育机构关联域名

许多教育机构有多个关联域名（如 njmu.edu.cn + nmukd.edu.cn），`src-fast-assess.py` 只枚举目标域子域名，不会发现关联域。对教育目标，始终用 `subfinder -d RELATED_DOMAIN` 单独枚举关联域名。关联域名常见模式：
- 学校缩写 + edu.cn (如 njmu.edu.cn)
- 学院缩写 + edu.cn (如 nmukd.edu.cn = 南医科康达)
- ehall/authserver/portal 可能在关联域而非主域

## Reference 路由

- IP泄露验证方法论：见 `src-vuln-hunting` skill 的 `references/ip-leakage-validation.md`
- 完整旧版技能全文：`references/legacy-full-skill-2026-06-08.md`
- 广西师范大学：`references/gxnu-edu-testing-patterns.md` — 自定义CAS(非金智)+CORS *+creds漏洞+WAF拦截Actuator+SUDY CMS+网易邮箱
- 教育供应商指纹和专项案例：见 `src-vuln-hunting` skill 的 `references/edu-vendor-fingerprinting.md`
- 广西师范大学测试模式：`references/gxnu-edu-testing-patterns-20260609.md` — ehall JSONP API 未授权访问、CAS CORS、SUDY CMS、研招网、Shibboleth IdP
- 广西师范大学测试模式：`references/gxnu-edu-testing-patterns-20260609.md` — 自研CAS(非金智)+金智ehall JSONP API+研招系统ASP.NET+超星教务+SUDY CMS站群+审核拒绝经验
- 长春理工大学测试模式：`references/cust-edu-testing-patterns-20260609.md` — CAS Open Redirect(clientredirect验证)、wengine-auth认证网关、腾讯企业邮箱、JEECMS v9
- 长春理工大学测试模式：`references/cust-edu-cn-testing-patterns-20260609.md` — CAS Open Redirect、wengine-auth 认证、腾讯企业邮箱
- 成都职业技术学院(2026-06-10): `references/cdp-edu-cn-testing-patterns-20260610.md` — 联奕CAS lyuapServer+安全中心端口4102/4107暴露+CORS*(aic)+Tomcat 8.0.9+UmiJS SPA ehall+Cloudflare WARP
- wengine-auth认证网关：见本技能 SKILL.md 的 "wengine-auth (网瑞达) 认证网关指纹" 章节
- JEECMS v9指纹：见本技能 SKILL.md 的 "JEECMS v9 指纹识别" 章节
- 自定义CAS Open Redirect验证：见本技能 SKILL.md 的 "CAS clientredirect 验证法" 章节
- NJMU KDC测试模式(2026-05): `references/njmu-kdc-testing-patterns.md`
- NJMU KDC深度测试(2026-06-09): `references/njmu-kdc-testing-patterns-20260609.md`
- CAS 专项：见 `src-vuln-hunting` skill 的 `references/cas-vuln-testing-patterns.md`、`references/wisedu-cas-testing-patterns.md`
- 研究生招生网系统：见本技能 `references/graduate-school-admission-testing-patterns.md`
- 超星教务系统：见本技能 `references/chaoxing-jwjx-testing-patterns.md`
- 自定义CAS Open Redirect：`references/custom-cas-open-redirect-patterns.md` — form action反射型、子域名拼接绕过、用户信息字段(@)绕过、完整攻击链
- 广西师范大学测试模式：`references/gxnu-edu-cn-testing-patterns.md` — 自定义CAS、ehall JSONP泄露、WAF指纹、子域名清单
- 低价值不提交：见 `src-vuln-hunting` skill 的 `references/education-portal-api-no-submit-gate.md`
- 高危利用：见 `src-vuln-hunting` skill 的 `references/high-severity-exploitation-patterns.md`
- 广西师范大学：`references/gxnu-edu-cn-testing-patterns.md` — 自研CAS(非wisedu)+金智ehall JSONP API+研招系统ASP.NET+超星教务+SUDY CMS站群+审核拒绝经验
- IP泄露深度验证方法论：`references/njmu-ip-leakage-deep-verification.md`

## 相关技能

- `global-control`：系统总控与工具健康检查。
- `src-vuln-hunting`：SRC 通用流程、证据门禁和报告规范。
- `web-pentest-fast`：外网 Web 快速测试入口。
- `exploit-chain`：从低价值线索升级为业务攻击链。
