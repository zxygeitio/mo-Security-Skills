# Windows Proxifier 到 Kali Burp 抓微信/QQ小程序

适用场景：小程序运行在用户 Windows 电脑上，Burp Suite 运行在 Kali/Hermes 机器上，需要让 Hermes 看到并分析小程序接口包。

## Kali 侧准备

1. 启动 Burp 并确认 `127.0.0.1:8080` 可用：

```bash
~/.agent/scripts/hermes-ensure-tools.sh --burp
~/.agent/scripts/hermes-ensure-tools.sh --status
```

2. 获取 Kali 网卡 IP，并把网卡 IP 的 8080 转发到 Burp 本地 8080。Burp 默认只绑定 `127.0.0.1` 时，Windows 不能直接连：

```bash
KALI_IP=$(ip -4 addr show eth0 | awk '/inet /{print $2}' | cut -d/ -f1)
pkill -f "socat TCP-LISTEN:8080,bind=$KALI_IP" 2>/dev/null || true
socat TCP-LISTEN:8080,bind=$KALI_IP,fork,reuseaddr TCP:127.0.0.1:8080 &
ss -tlnp | grep "$KALI_IP:8080"
```

3. 验证 Windows 是否真的打到 Kali，可在 Kali 临时抓包：

```bash
timeout 20 tcpdump -i eth0 -nn 'tcp port 8080' -c 20
```

看到 `Windows_IP -> Kali_IP.8080` 或 `CONNECT target:443 HTTP/1.1`，说明 Proxifier 到 Kali 链路通。

## Windows Proxifier 正确规则

Proxy Server 里配置 Kali 代理：

- Address: Kali IP，例如 `192.168.110.137`
- Port: `8080`
- Protocol: `HTTPS`（不通时再试 HTTP）
- 不需要认证

规则顺序必须从上到下：

1. `Localhost Direct`
- Applications: `Any`
- Target hosts: `localhost; 127.0.0.1; %ComputerName%; ::1`
- Target ports: `Any`
- Action: `Direct`

2. `Kali Direct`
- Applications: `Any`
- Target hosts: Kali IP，例如 `192.168.110.137`
- Target ports: `Any`
- Action: `Direct`

3. `WeChat MiniProgram`
- Applications: `WeChat.exe;WeChatAppEx.exe;WeChatBrowser.exe;WeChatWeb.exe;WeChatApp.exe;wmpf_host.exe;wmpf.exe;XWeb.exe;miniapp.exe`
- Target hosts: `Any`
- Target ports: `80;443;8080;8443`
- Action: `Proxy HTTPS kali`

4. `Default`
- Applications: `Any`
- Target hosts: `Any`
- Target ports: `Any`
- Action: `Direct`

关键坑：

- `Target hosts` 是目标业务站点，不是代理服务器；不要把 Kali IP 写进小程序代理规则的 Target hosts。
- `Target ports` 至少要包含 `443`；不要只写 `8080`。
- `Default` 必须是 `Direct`，否则 Edge/Office/系统流量会污染 Burp。
- 端口分隔符必须是英文半角分号：`80;443;8080;8443`，不要用中文 `；`。
- `127.0.0.1` 本地端口必须 Direct，否则 QQ/微信本地通信会被错误代理到 Kali。

QQ 小程序可增加类似规则：

- Applications: `QQ.exe;qq.exe;QQMiniApp.exe;QQBrowser.exe;QQExternal.exe`
- 放在 Localhost/Kali Direct 之后，Default Direct 之前。

## Windows 证书

Windows 浏览器访问 `http://KALI_IP:8080` 下载 Burp CA，安装到：

- 本地计算机
- 受信任的根证书颁发机构

如果只能看到 `CONNECT`，看不到 HTTPS 明文，优先检查证书是否装到正确存储；如果浏览器 HTTPS 可解密但小程序不可解密，再考虑小程序/内置组件证书绑定或特殊网络栈。

## Burp MCP 与 Burp GUI 不一致的排查

实战中可能出现：Burp GUI 的 `Proxy -> HTTP history` 有流量，但 `mcp_burpsuite_burp_logs` 为空。不要据此判断“没有抓到包”。处理顺序：

1. 先用 `tcpdump -i eth0 -nn 'tcp port 8080'` 验证 Windows 是否连到 Kali 8080。
2. 用 xdotool 激活 Burp 窗口并查看 GUI：

```bash
DISPLAY=:0.0 xdotool search --name 'Burp Suite' | tail -1
DISPLAY=:0.0 xdotool windowactivate <WID>
DISPLAY=:0.0 xdotool key ctrl+shift+p
```

3. 截屏/OCR 查看 `Proxy -> HTTP history`，不要只依赖 MCP JSONL。
4. 若需要结构化分析，可让用户在 Burp GUI 中导出 HTTP history XML，再用 Burp MCP 的 XML import 分析。

## 小程序业务流量筛选

微信官方上报通常不是目标业务接口，常见包括：

- `servicewechat.com`
- `sh.servicewechat.com`
- `/ob/sdkmonitor`
- `/ob/wxob`
- `weixin.qq.com`, `qq.com`, `gtimg.cn`, `qpic.cn`

这些通常只说明链路通，不直接作为漏洞目标。继续让用户操作小程序：首页、课表、切换周次、课程详情、个人中心、登录/绑定信息，然后在 Burp 里筛选非微信官方域名，例如：

- `*.edu.cn`
- `api.*`
- `jw.*`
- `course.*`
- `school.*`
- `auth.*`
