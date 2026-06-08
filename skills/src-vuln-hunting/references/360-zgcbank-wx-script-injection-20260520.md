# 360 SRC 中关村银行 wx.zgcbank.com 异常脚本注入验证

## 适用场景
360 / 企业 SRC 中遇到银行、政企等业务域名首页返回很小的健康检查页面，但响应体尾部出现可疑 JavaScript，例如 `brmidyrvj.php`、`c_venus`、`E_venus`、`localurl=document.URL` 等。

## 本次验证要点
目标：`wx.zgcbank.com`

首页正常内容类似健康检查：
- `Send:GET /health.html`
- `Receive:Service is Running`
- `Interval:5`

异常内容出现在 `</html>` 后：
- `<script language="JavaScript" type="text/javascript">function c_venus(){...}`
- 枚举 `SCRIPT / IFRAME / FRAME / IMG / EMBED / LINK`
- 拼接 `brmidyrvj.php?url=<资源列表>&localurl=<当前页面URL>`
- 使用 `XMLHttpRequest` 发起 GET 请求

该类问题不要写成 XSS，除非能证明用户可控输入触发；更稳妥标题是“页面异常脚本注入 / 页面被篡改 / 异常 JavaScript 代码”。

## 最小复现命令
优先用 heredoc，避免多行 curl 续行被复制破坏：

```bash
bash <<'EOF'
set -e
curl -sk --http1.1 --connect-timeout 8 --max-time 20 -D /tmp/wx_zgcbank_hdr.txt -o /tmp/wx_zgcbank_body.html 'https://wx.zgcbank.com/'
head -1 /tmp/wx_zgcbank_hdr.txt
wc -c /tmp/wx_zgcbank_body.html
grep -aoE 'Send:GET /health.html|Service is Running|brmidyrvj\.php|function c_venus|E_venus|localurl' /tmp/wx_zgcbank_body.html | sort -u
grep -ao '<script[^>]*>.*</script>' /tmp/wx_zgcbank_body.html | head -1
EOF
```

## 证据判断
漏洞成立的关键证据：
1. HTTP 200 返回首页响应体。
2. 页面包含正常健康检查内容。
3. 响应体尾部或 `</html>` 后存在异常 `<script>`。
4. 异常脚本包含资源枚举逻辑和 `brmidyrvj.php?url=...&localurl=...` 回传逻辑。

注意：访问 `brmidyrvj.php` 返回 404 并不推翻漏洞，因为风险点是银行域名响应中出现异常脚本并在浏览器端发起异常请求；后端回传端点是否存在可作为补充，不是必要条件。

## 报告表述建议
- 漏洞类型：安全配置错误 / 页面异常脚本注入 / 页面篡改风险。
- 风险级别：中危起步；若证明真实业务页面也被注入或能回传敏感 URL/资源，可升高。
- 不要夸大为账号接管或高危 XSS。
- 影响聚焦：页面被篡改、访问者浏览器执行异常 JS、枚举当前页面资源和 URL、可能导致挂马/钓鱼/流量劫持/供应链攻击。

## 修复建议
1. 排查源站文件、反向代理、负载均衡、WAF/CDN、静态发布链路，确认脚本注入来源。
2. 清理 `brmidyrvj.php` 相关异常代码，并检查同服务器/同目录/同应用是否批量感染。
3. 做入侵排查：Web 根目录、定时任务、启动项、异常账号、WebShell、发布包完整性。
4. 增加 CSP 和静态文件完整性监控。
5. 对响应体尾部追加脚本做自动化检测与告警。
