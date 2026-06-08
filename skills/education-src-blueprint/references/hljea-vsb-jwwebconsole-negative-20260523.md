# 黑龙江省招生考试院 hljea.org.cn 低影响续挖记录（2026-05-23）

## 适用价值
用于教育/考试院类目标中，区分 Visual SiteBuilder 静态门户、公开咨询系统、访问禁止页、连接不稳定与可提交实质漏洞，避免把低价值线索包装成报告。

## 目标与指纹
- 主站：`https://www.hljea.org.cn/`
- 标题：黑龙江省招生考试院
- CMS：Visual SiteBuilder 9（页面含 `<!--Announced by Visual SiteBuilder 9-->`、`/_sitegray/`、`/system/resource/js/counter.js`）
- 随机路径返回明确 404，不是 SPA fallback。
- 发现业务子站线索：`https://xxcx.hljea.org.cn/JWWebConsoleNew/home`，标题“黑龙江招生考试信息港”，为网上咨询系统。

## 已验证负证据
主站低影响检查：
- `/_web/_search/api/search/new.rst` → 404
- `/_dwr/test/` → 404
- `/system/resource/code/news/click/clicktimes.jsp?wbnewsid=1&owner=1876519242&type=wbnews` → 仅公开点击计数 JSON：`{"wbshowtimes":0,"randomid":"n","wbnewsid":1}`
- `/system/resource/code/news/click/dynclicks.jsp?...` → 公开数字
- `/.git/HEAD` → “访问禁止”，不是源码泄露
- `/swagger-ui.html` → “访问禁止”，不是 Swagger 泄露
- `/.env`、`/v2/api-docs`、`/admin`、`/login` → 404 或不可用
- `/content/multiUpload.do`、`/WEB-INF/web.xml`、常见备份文件 → 未验证到上传/泄露

`xxcx.hljea.org.cn/JWWebConsoleNew/home` 曾返回页面并暴露路径：
- `checkAskactiv`
- `toStudentLogin`
- `toNewProblem`
- `toMyProblem?ksh=`
- `search`
- `problems?pid=`

但后续访问大量为 `000` / 连接不稳定，未稳定验证到 IDOR、SQLi、未授权敏感数据或认证绕过。

2026-05-23 晚间复测网络层证据：
- DNS 正常：`xxcx.hljea.org.cn -> 116.182.14.171`，`www.hljea.org.cn -> 116.182.14.161`，`www.lzk.hl.cn -> 116.182.14.170`。
- 路由可达：`traceroute -T -p 443 116.182.14.171` 第二跳即到目标，约 56ms；`nmap -Pn -sT -p 443` 显示 443 open，80/8080/8443 filtered。
- TCP SYN/ACK 正常：`hping3 -S -p 443 -c 3 116.182.14.171` 三次均收到 SA，说明不是本机断网。
- TLS 握手无响应：curl/openssl 发送 ClientHello 后超时，TLS1.0/1.1/1.2/1.3、禁用 ALPN、不同 cipher、SNI/Host/`--connect-to` 均无改善。
- 浏览器 CDP 导航同样超时；Burp MCP 因本机 Burp 8080 未启动不可用，但不是该目标访问失败的主因。
- 结论：当前阶段是目标侧 HTTPS/TLS 层连接不稳定或策略丢弃，不满足继续验证 `pid`/`ksh`/`search` 的前提；不能把 000/超时作为漏洞证据。

本次证据文件：
- `/tmp/src-workspaces/hljea.org.cn/20260523/recover_access_20260523_221447.txt`
- `/tmp/src-workspaces/hljea.org.cn/20260523/tls_variants_20260523_221834.txt`
- `/tmp/src-workspaces/hljea.org.cn/20260523/nmap_hljea_20260523_222040.txt`
- `/tmp/src-workspaces/hljea.org.cn/20260523/tls_clienthello_variants_20260523_222126.txt`

## 报告门禁结论
不建议提交：
- 公开点击计数不含敏感数据。
- “访问禁止”页面不是泄露。
- 404/000/连接不稳定不是漏洞证据。
- 公开咨询首页和公开问答列表只有在证明 `pid`/`ksh` 可越权读取考生隐私、检索存在 SQLi、或登录/提问流程可认证绕过时才可提交。

## 后续深挖优先级
若目标连接恢复稳定，优先围绕 `xxcx.hljea.org.cn/JWWebConsoleNew` 做低影响验证：
1. `problems?pid=` 连续 ID 对照：只在返回未脱敏考生号、手机号、身份证、录取状态等隐私时升级。
2. `toMyProblem?ksh=`：验证是否仅凭考生号读取“我的咨询”记录；必须做随机/不存在 ksh 对照。
3. `search`：只在可稳定复现 SQL 报错、注入数据差异或敏感内容越权返回时升级。
4. `checkAskactiv`：仅作为活动配置/提问开放状态线索；无敏感数据时不报。
5. `toStudentLogin/toNewProblem`：关注认证绕过或弱校验，但不要把登录页暴露本身当漏洞。

## 操作教训
- 对政务/考试院站点，主站往往是 VSB 静态门户；不要在主站路径爆破上投入过多。
- 发现业务子站后，应以“稳定可复现 + 敏感数据/操作影响”为门槛；连接 `000` 只能记录为外部可达性问题。
- 对同类目标最终输出应明确“不建议提交”并保留负证据包路径，避免用低危配置、公开信息或不稳定连接凑报告。
