# 微信小程序 + Burp GUI + WordPress REST API 漏洞挖掘复盘

## 适用场景
- Windows 端微信/QQ 小程序通过 Proxifier 转发到 Kali Burp。
- Burp GUI 能看到 HTTP history，但 Burp MCP 日志为空或不同步。
- 小程序业务域名最终表现为 WordPress REST API（如 `/index.php/wp-json/wp/v2/*`）。

## 抓包配置要点
1. Proxifier 规则顺序必须是：
   - `Localhost Direct`: `localhost;127.0.0.1;%ComputerName%;::1` -> Direct
   - `Kali Direct`: Kali 代理 IP -> Direct
   - 小程序进程 -> Proxy Kali Burp
   - `Default` -> Direct
2. `Target hosts/ports` 指的是目标业务站点，不是代理服务器。代理地址只写在 Proxy Server 中。
3. 小程序规则建议覆盖：
   - `WeChat.exe;WeChatAppEx.exe;WeChatBrowser.exe;WeChatWeb.exe;WeChatApp.exe;wmpf_host.exe;wmpf.exe;XWeb.exe;miniapp.exe;WeChatPlayer.exe;WeChatUtility.exe`
4. 如果 Default 走 Proxy，会把 Edge/Office/系统流量全部打进 Burp，污染 HTTP history。
5. 如果把 `127.0.0.1:*` 也代理，会出现大量本机端口噪音（如 `9210-9219`），并可能影响客户端内部通信。

## Burp GUI 与 MCP 的差异处理
- 不要假设 Burp MCP 会同步 Burp GUI HTTP history。实际可能出现：GUI 有 Windows/Proxifier 过来的请求，MCP JSON 日志为 0。
- 判断链路是否通：
  - Windows/Proxifier 日志显示 `open through proxy kali`。
  - Kali `tcpdump -i eth0 -nn -A 'tcp port 8080'` 能看到 `CONNECT` 或 HTTP 明文。
  - Burp GUI `Proxy -> HTTP history` 有请求。
- 如果关掉 Burp GUI，`127.0.0.1:8080` 的 Burp 代理可能随之停止；外层 `socat 192.168.x.x:8080 -> 127.0.0.1:8080` 仍监听但后端拒绝连接。
- 在这种模式下，优先从 Burp GUI/截图/导出 XML 分析；MCP 不可作为唯一证据源。

## WordPress REST API 小程序接口测试清单
抓到 `https://target/index.php/wp-json/wp/v2/posts?...` 后，先按以下顺序验证：

1. 公开内容确认
   - `/index.php/wp-json/`
   - `/index.php/wp-json/wp/v2/posts?per_page=10&page=1&_embed=true`
   - `/index.php/wp-json/wp/v2/pages?per_page=100`
   - `/index.php/wp-json/wp/v2/media?per_page=100`
   - `/index.php/wp-json/wp/v2/comments?per_page=100`

2. 敏感读取/越权边界
   - `/index.php/wp-json/wp/v2/users`
   - `/index.php/wp-json/wp/v2/settings`
   - `/index.php/wp-json/wp/v2/posts?status=draft`
   - `/index.php/wp-json/wp/v2/pages?status=draft`
   - `/index.php/wp-json/wp/v2/media?status=private`
   - `/index.php/wp-json/wp/v2/posts/{id}?context=edit`

3. 写操作低影响验证
   - `POST/PUT/DELETE /index.php/wp-json/wp/v2/comments/{id}`
   - 未认证返回 `rest_cannot_edit` / `rest_cannot_delete` / 401 时，不构成写越权。

4. 插件命名空间
   - 从 `/index.php/wp-json/` 的 `namespaces` 和 `routes` 中提取插件接口。
   - 常见重点：`code-snippets/v1`、`mailpoet/v1`、`wordfence/v1`、`yoast/v1`、`post-views-counter`。
   - 直接测列表/详情/管理类端点是否返回 401；只返回公开 SEO/head/readme 信息不报。

5. 敏感文件
   - `/.env`、`/wp-config.php.bak`、`/wp-config.php.save`、`/wp-config.php~`、`/wp-content/debug.log`、`/backup.zip`、`/db.sql`、`/.git/HEAD`。
   - 301/403/自定义 HTML/首页 fallback 均不算泄露。

## CORS 任意 Origin 反射的提交边界
WordPress REST 可能对任意 `Origin` 返回：

```text
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: OPTIONS, GET, POST, PUT, PATCH, DELETE
```

但如果跨域可读的只是公开文章、页面、媒体、评论，且 users/settings/draft/private/edit/write 均被 401/403/400 拦截，则不要包装成高危 CORS。按用户偏好，这类问题通常不建议提交，除非能证明：
- 登录态敏感数据可被跨域读取；或
- 后台/个人信息/课表/学生数据可被读取；或
- 搭配有效 XSS/CSRF/凭证泄露形成实质危害。

## 评论/Gravatar 伪敏感信息陷阱
REST comments 中的 `author_avatar_urls` 是 Gravatar hash URL。Hash 字符串中偶然出现 11 位数字片段，不能直接证明手机号泄露。除非能还原真实邮箱/手机号并证明与用户身份绑定，否则不要作为敏感信息泄露报告。

## 报告决策
可提交：
- 未授权读取学生/课表/个人信息。
- IDOR 读取他人课表/绑定信息。
- 未授权上传/评论写入/后台操作。
- 插件接口返回订阅者、邮件、代码片段、配置、token 等敏感内容。

不建议提交：
- 公开 WordPress posts/pages/media/comments。
- CORS 反射但只能读公开数据。
- WordPress/插件/theme 版本暴露，未验证出 CVE 利用。
- Gravatar hash 中偶现数字片段。
