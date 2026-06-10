# Windows Proxifier → Kali Burp 抓微信/QQ小程序包

## 适用场景

- 小程序运行在用户 Windows 机器上，Burp Suite 运行在 Kali/Hermes 机器上。
- Windows 用 Proxifier 按进程把微信/QQ小程序流量转发到 Kali Burp。
- Hermes 需要分析 Burp HTTP history 中的小程序接口。

## Kali 侧

1. 保持 Burp Suite GUI 打开。Community 版代理通常随 GUI 生命周期存在；关闭 GUI 后 `127.0.0.1:8080` 可能消失。
2. Burp 默认只监听 loopback 时，用 socat 对外转发：

```bash
KALI_IP=$(ip -4 addr show eth0 | awk '/inet /{print $2}' | cut -d/ -f1)
socat TCP-LISTEN:8080,bind=$KALI_IP,fork,reuseaddr TCP:127.0.0.1:8080
```

3. 验证：

```bash
ss -tlnp | grep -E "127.0.0.1:8080|$KALI_IP:8080"
curl -x http://127.0.0.1:8080 http://httpbin.org/ip
```

注意：`ss` 可能只明显显示 socat 的 `$KALI_IP:8080`，但 Burp GUI HTTP history 中有包、curl 代理成功时，以实际代理验证为准。

## Windows Proxifier 代理服务器

Proxy Server：

- Address: Kali IP，例如 `192.0.2.137`
- Port: `8080`
- Protocol: `HTTPS`；不稳定时可试 `HTTP`
- Authentication: none

## Proxification Rules 正确顺序

1. Localhost Direct

- Applications: Any
- Target hosts: `localhost; 127.0.0.1; %ComputerName%; ::1`
- Target ports: Any
- Action: Direct

2. Kali Direct

- Applications: Any
- Target hosts: Kali IP，例如 `192.0.2.137`
- Target ports: Any
- Action: Direct

3. WeChat MiniProgram / QQ MiniProgram

- Applications 示例：
  - WeChat: `WeChat.exe;WeChatAppEx.exe;WeChatBrowser.exe;WeChatWeb.exe;WeChatApp.exe;wmpf_host.exe;wmpf.exe;XWeb.exe;miniapp.exe;WeChatPlayer.exe;WeChatUtility.exe`
  - QQ: `QQ.exe;qq.exe;QQProtect.exe;QQExternal.exe;QQMiniApp.exe;QQBrowser.exe`
- Target hosts: Any
- Target ports: `80;443;8080;8443`
- Action: Proxy HTTPS Kali

4. Default

- Applications: Any
- Target hosts: Any
- Target ports: Any
- Action: Direct

## 常见配置错误

- 不要把 `192.0.2.137` 写进小程序规则的 Target hosts。Target hosts 是“目标业务网站”，不是代理服务器。代理服务器只配置在 Action/Proxy Server 中。
- Default 不要设为 Proxy，否则 Edge、Office、系统更新、QQ 本地端口都会污染 Burp。
- `127.0.0.1:*` 必须 Direct，否则微信/QQ本地检活端口如 `9210-9219` 会被错误代理。
- 端口分隔必须用英文半角分号：`80;443;8080;8443`，不要用中文分号 `；`。

## 判断是否配置成功

Proxifier 中应出现真实业务域名，例如：

```text
WeChatAppEx.exe - api.example.com:443 open through proxy kali HTTPS
```

不应只看到：

```text
servicewechat.com
sh.servicewechat.com
127.0.0.1:921x
edge.microsoft.com
cloudmessaging.edge.microsoft.com
```

`servicewechat.com`、`sh.servicewechat.com`、`/ob/sdkmonitor`、`/ob/wxob` 多为微信运行环境/监控上报；不是目标小程序后端。

## Burp MCP 与 GUI 的关系

- Burp MCP 的 JSON 日志不一定同步 Burp GUI 的 Proxy → HTTP history。
- 当 Windows Proxifier 流量在 GUI 里可见但 `mcp_burpsuite_burp_logs` 为空时，不要误判为没抓到包；直接看 GUI、导出 HTTP history XML，或改用 tcpdump/mitmproxy 辅助。
- 关闭 Burp GUI 后，Burp 代理可能停止，MCP health 会显示 `127.0.0.1:8080 connection refused`；此时 socat 仍监听外网 IP 也没用，因为后端 Burp 不在。

## 分析微信小程序包时的筛选策略

1. 先排除微信/系统域名：
   - `servicewechat.com`
   - `sh.servicewechat.com`
   - `weixin.qq.com`
   - `qq.com`
   - `gtimg.cn`
   - `qpic.cn`
   - `edge.microsoft.com`
   - `cloudmessaging.edge.microsoft.com`
   - `127.0.0.1:*`
2. 重点找非微信官方域名，尤其是请求头带 `Referer: https://servicewechat.com/...` 的业务域名。
3. 小程序内容可能来自 WordPress/博客/API 内容源。看到如 `/wp-json/wp/v2/posts`、`/wp-json/wp/v2/pages`、`/wp-json/wp/v2/media` 时，按公开内容源处理，继续验证是否存在未授权敏感数据、私密内容、上传、用户枚举、插件漏洞；不要把普通公开 REST 内容直接包装成漏洞。
4. Burp 过滤器可能隐藏静态资源，必要时点 `Filter on` 改为显示全部。

## 辅助 tcpdump 抓 Host/CONNECT

当 GUI 排序/过滤干扰时，可临时监听 Kali 8080：

```bash
timeout 90 tcpdump -i eth0 -nn -A 'tcp port 8080' 2>/tmp/proxifier_8080_capture.err \
  | stdbuf -oL grep -aE '^(Host:|CONNECT |GET |POST |PUT |PATCH |DELETE )' \
  > /tmp/proxifier_8080_capture.txt
```

注意：CONNECT 后的 HTTPS 明文仍由 Burp 解密；tcpdump 主要用于确认哪些 Host/CONNECT 到达 Kali。