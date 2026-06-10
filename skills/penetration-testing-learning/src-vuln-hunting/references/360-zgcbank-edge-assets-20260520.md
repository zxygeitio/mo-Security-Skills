# 360 SRC 中关村银行边缘/移动端资产续挖记录（2026-05-20）

## 适用场景
继续 360/ZGCBank 项目时，如果用户说“已报告，继续挖新漏洞”，且 PMS 注册/登录/找回密码链路已经提交，应切换到非同根因资产面：`www.zgcbank.com`、`wx.zgcbank.com`、`app.zgcbank.com`、`h5.zgcbank.com`、`static.zgcbank.com` 等边缘/移动端域名。

## 关键流程
1. 必须先确认 360 split VPN：`tun0`、OpenVPN 进程、目标可达。
2. 对解析到公网 IP 但经 VPN 才稳定访问的目标，可按需添加单 host route 到 `10.9.0.1 dev tun0`，但不要改默认路由。
3. 低频验证，不做高强度扫描；重点看：
   - 健康检查页面 `/health.html`
   - 默认错误页 `/robots.txt`、随机不存在路径、`/index.jsp`、`/foo.action`
   - 移动端加密协商接口 `/isec/getServerRandom.do`、`/isec/keyAgreement.do`
   - 官网 SPA fallback 中是否有异常脚本追加
4. 已提交 PMS 验证码/找回密码问题后，不要再把同根因接口增强当新漏洞；只保留不同资产、不同组件、不同影响面的结论。

## 本次稳定发现模式

### 1. 异常 JavaScript 注入/疑似篡改
`wx.zgcbank.com` 首页和 `www.zgcbank.com` 部分路径出现尾部异常脚本：

- 关键字：`brmidyrvj.php`、`function c_venus`、`E_venus`、`localurl`
- 行为：枚举 `SCRIPT/IFRAME/FRAME/IMG/EMBED/LINK` 资源，把资源 URL 和 `document.URL` 拼接到 `brmidyrvj.php?url=...&localurl=...` 后用 XMLHttpRequest 请求。
- 报告表述：按“页面异常脚本注入/疑似页面篡改”写，不夸大为账号接管或可直接 XSS。
- 证据必须包含：HTTP 200、响应体大小、异常关键字、`</html>` 后追加脚本或异常脚本片段。

### 2. Tomcat 默认错误页版本泄露
`wx.zgcbank.com` 与 `app.zgcbank.com` 不存在路径/不支持方法会暴露默认 Tomcat 错误页。

- `wx.zgcbank.com`: `Apache Tomcat/10.0.27`
- `app.zgcbank.com`: `Apache Tomcat/9.0.107`
- 报告表述：低危信息泄露；不同域名、不同版本可以分开提交，但价值较低。
- 证据路径示例：`/robots.txt`、随机不存在路径、`/isec/keyAgreement.do` 使用 GET 返回 405。

### 3. 多域名健康检查页面暴露
`app.zgcbank.com`、`wx.zgcbank.com`、`h5.zgcbank.com` 暴露 `/health.html`：

- 关键字：`Send:GET /health.html`、`Receive:Service is Running`、`Interval:5`
- 报告表述：低危信息泄露/安全配置错误；不要包装成高危。
- 适合作为配置加固类低危提交。

## 可复制验证模板

```bash
bash <<'EOF'
set -e
for h in www.zgcbank.com wx.zgcbank.com app.zgcbank.com h5.zgcbank.com; do
  echo "=== $h ==="
  curl -sk --http1.1 --connect-timeout 8 --max-time 20 -D /tmp/${h}_hdr.txt -o /tmp/${h}_body.html "https://$h/health.html"
  head -1 /tmp/${h}_hdr.txt || true
  grep -aoE 'Send:GET /health.html|Receive:Service is Running|Interval:[0-9]+|brmidyrvj\.php|function c_venus|Apache Tomcat/[0-9.]+' /tmp/${h}_body.html | sort -u || true

done
EOF
```

## 报告优先级
1. 异常 JavaScript 注入/疑似篡改：中危优先提交。
2. Tomcat 版本泄露：低危，作为独立域名组件泄露提交。
3. 健康检查页面暴露：低危，配置加固类。

## 注意事项
- `www.zgcbank.com` 存在 SPA fallback，很多不存在路径返回首页；不要把“路径 200”单独报漏洞，只有同时出现异常脚本或其他实质信息才报告。
- `static.zgcbank.com` 返回 502 不等于漏洞，除非能证明敏感信息泄露或绕过。
- `/isec/getServerRandom.do` 未登录返回公钥/签名结果通常是移动端加密协商设计，不要单独作为漏洞，除非证明可绕过认证或获取敏感数据。
