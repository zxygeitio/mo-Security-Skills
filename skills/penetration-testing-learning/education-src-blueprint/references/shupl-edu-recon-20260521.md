# 上海政法学院 shupl.edu.cn 低影响侦察记录（2026-05-21）

## 适用价值
这是一次高校教育 SRC 目标的“未形成可提交高价值漏洞”的侦察样本。未来测试同类高校门户时，可复用这里的过滤结论和慢目标探测方式，避免把后台暴露、假 200、CMS 公开接口错误响应包装成低质量报告。

## 目标资产与指纹
- `www.shupl.edu.cn`：SUDY/苏迪 CMS，主站源码含 `sudy-wp-siteId="3"`、`/_js/jquery.sudy.wp.visitcount.js`、`/_wp3services/generalQuery`。
- `ehall.shupl.edu.cn`：办事大厅/任务中心，页面含 `taskcenter`、`infoplus`、`CSRFToken`、`JSESSIONID` URL 形式；常见金智教育 `/jsonp/*` 端点返回 404，未复现 appIntroduction 教职工信息泄露。
- `zs.shupl.edu.cn`：IIS/ASP.NET 招生站，`/manage/login.aspx` 为招生平台管理后台，含验证码；`/trace.axd` 返回远程跟踪禁用错误页。
- `webvpn.shupl.edu.cn`：WebVPN 登录/资源导航。
- `lib.shupl.edu.cn`：图书馆页面，含超星/订阅相关前端资源。
- `mail.shupl.edu.cn`：网易企业邮箱登录。
- 其他链接资产：`job`、`iso`、`cnisco`、`xuanke`、`yjsehall`、`admission`、`sdc`、`newoa` 等，多为统一认证、IIS 默认/自定义 404 或普通门户。

## 已过滤的不建议提交点
1. 主站 `/_wp3services/generalQuery?queryObj=articles`：未带站点参数仅返回“缺少必填参数”；带 `siteId=3` 等参数未拿到敏感数据，不构成未授权敏感数据泄露。
2. `ehall.shupl.edu.cn/taskcenter/*`：可见前端配置、CSRFToken、JSESSIONID URL 形式，但未验证到未授权业务数据接口。常见 `/jsonp/serviceCenterData.json`、`/jsonp/appIntroduction.json`、`/jsonp/school.json` 均为 404。
3. `zs.shupl.edu.cn/manage/login.aspx`：后台暴露但有验证码；未验证到验证码绕过、弱口令、SQL 注入或未授权后台接口。
4. `zs.shupl.edu.cn/trace.axd`：返回“跟踪错误/远程跟踪禁用”，不能作为实质漏洞。
5. IIS/SPA/自定义 404 假 200：如部分资产对不存在路径返回 200 + 404 图片/默认页，必须过滤。

## 慢目标探测教训
本次多个高校子域名存在 TLS 握手慢、响应慢或连接悬挂，Python `urllib` + 大 ThreadPool 的全量脚本即使设置 timeout 也容易整批超时，且因为结果最后才写文件，导致中间证据丢失。

推荐写法：
- 按“单主机/小批路径”分批探测，不要一次性 `assets × paths` 全量并发。
- 每个请求使用 `curl --max-time 3 --connect-timeout 2` 或 subprocess，而不是长生命周期 `urllib` 批量池。
- 每得到一个结果就追加写 JSONL/文本，避免脚本超时后没有任何落盘结果。
- 对教育 SRC，批量探测超时后不要为了补洞而提高并发；优先收敛到低影响、可复核、可提交的 P0/P1 类型。

## 复测优先级
如果未来继续深挖，优先方向：
1. 招生/就业类 ASP.NET 站点的实际业务 API、验证码流程、找回密码/查询接口（避免爆破）。
2. `ehall` 前端 JS 中是否出现真实业务 API、OA/Seeyon REST Token、Supwisdom transaction 等集成线索。
3. SUDY CMS 仅在能拿到敏感数据、SQL 错误回显或后台未授权时才进入报告；普通公开接口错误响应不报。
