---
name: burp-suite-setup
description: Burp Suite proxy setup with HTTPS certificate configuration on Kali Linux. Covers proxy listener config, CA certificate extraction/installation, browser integration, and xdotool automation for headless environments.
---

# Burp Suite 代理配置 + HTTPS 证书 (Kali Linux)

## 环境概览

- Burp Suite Community Edition v2026.3.2
- Java 21 (OpenJDK)
- Kali Linux rolling
- DISPLAY=:0.0 (Xfce desktop)
- xdotool available for GUI automation

## 一、启动 Burp Suite（Hermes 按需自启）

默认原则：需要抓包/HTTP history/代理复现时，Hermes 主控应自行启动 Burp Suite、Burp MCP/Gateway 并验证端口，不等待用户手动打开。实战前首选完整就绪脚本：

```bash
/root/.hermes/scripts/hermes-burp-ready.sh
```

Kali `burpsuite` 包装器参数坑：`--config-file` 和 `--project-file` 必须使用等号形式（如 `--config-file=/root/.BurpSuite/proxy_config.json`），不要写成 `--config-file /path`，否则包装器会报 `Expected a value for option config-file`。如果 `xdotool search --name Burp` 只看到 `burp-StartBurp` 且 `ss -tlnp | grep 8080` 长时间为空，说明 Burp GUI 停在启动/项目选择页，MCP 没坏，代理 listener 尚未创建；此时优先处理 GUI 启动页或用现成项目文件启动，再验证 8080。

实测可恢复路径（2026-06-08）：若没有 Java/Burp 进程，先启动真实 GUI：

```bash
DISPLAY=:0.0 burpsuite --use-defaults --disable-extensions --config-file=/root/.BurpSuite/proxy_config.json
```

看到项目选择页时选择默认 `Temporary project in memory`，点击 `Start Burp`；若弹 `Burp Browser Error`，点 `OK` 后再点 `Start Burp`。成功标志：`ss -tlnp | grep ':8080'` 显示 `java` 监听，`burp_health` 返回 `reachable: true`。

Burp GUI 卡住时的纯 CLI 降级：

```bash
/root/.hermes/scripts/hermes-mitm-fallback.sh verify
```

该脚本启动 `mitmdump` 监听 `127.0.0.1:8081`，验证 HTTP/HTTPS，输出 `/tmp/hermes-mitm-fallback/traffic.jsonl` 和 `/tmp/hermes-mitm-fallback/flows.mitm`；用于临时抓包/落证据，不替代 Burp MCP 的报告分析能力。

该脚本会完成：
- 调用 `hermes-ensure-tools.sh --burp` 启动/确认 Burp Suite GUI、Gateway、Burp MCP server。
- 确认 `127.0.0.1:8080` 监听、`hermes mcp test burpsuite` 发现 6 个工具。
- 确认 Burp CA 存在并写入系统 CA/NSS，生成 Android 系统证书 `/tmp/9a5ba575.0` 一类路径。
- 用 curl 经 Burp 代理验证 HTTP/HTTPS 都能通过。
- 用 Burp MCP 直连验证 `burp_health`、HTTP/HTTPS `burp_proxy_request`、`burp_logs`、`burp_analyze_logs` 闭环。
- 输出证据目录 `/tmp/hermes-burp-ready/summary.json`、`hermes_mcp_test.txt`、`curl_http.json`、`curl_https.json`、`mcp_direct.json`。

常用模式：
```bash
/root/.hermes/scripts/hermes-burp-ready.sh --quiet       # 只输出 summary JSON
/root/.hermes/scripts/hermes-burp-ready.sh --no-clear    # 保留现有 MCP 日志，不清空 traffic.jsonl
/root/.hermes/scripts/hermes-burp-ready.sh --expose-lan  # 额外用 socat 暴露 Kali 网卡 IP:8080 给 Windows/手机
```

轻量检查仍可用统一脚本：

```bash
/root/.hermes/scripts/hermes-ensure-tools.sh --burp
/root/.hermes/scripts/hermes-ensure-tools.sh --status
```

脚本会：
- 确认 Gateway/Burp MCP server 状态；必要时启动 Gateway。
- 启动 Burp Suite GUI：`DISPLAY=:0.0 burpsuite --use-defaults`。
- 等待 `127.0.0.1:8080` 监听。
- 尝试用 xdotool 处理启动弹窗并关闭 Intercept。

手动等价命令（脚本不可用时）：

```bash
DISPLAY=:0.0 burpsuite --use-defaults 2>&1
```

**处理启动弹窗**（如果有旧临时项目文件残留）:

```bash
MAIN=$(DISPLAY=:0.0 xdotool search --name "Burp Suite Community Edition" 2>/dev/null | head -1)
DISPLAY=:0.0 xdotool windowactivate $MAIN
# 按 Tab+Enter 选择默认选项
DISPLAY=:0.0 xdotool key Tab Return
```

验证启动完成:
```bash
ss -tlnp | grep 8080  # 应看到 java 进程在 127.0.0.1:8080 LISTEN
```

## 二、关闭 Intercept 让流量自动通过

Burp Suite 默认 Intercept 是 ON，请求会被卡住。关闭方法:

```bash
MAIN=$(DISPLAY=:0.0 xdotool search --name "Burp Suite Community Edition" | head -1)
DISPLAY=:0.0 xdotool windowactivate $MAIN
sleep 0.3
# Ctrl+Shift+P 切换到 Proxy 标签
DISPLAY=:0.0 xdotool key ctrl+shift+P
sleep 0.5
# Ctrl+T 切换 Intercept on/off
DISPLAY=:0.0 xdotool key ctrl+T
sleep 0.5
DISPLAY=:0.0 xdotool key ctrl+T  # 按两次确保
```

## 三、提取 Burp CA 证书

通过 Burp 代理连接任意 HTTPS 站点，从 TLS 握手响应中提取 CA 证书链:

```bash
# 提取证书链
echo "" | timeout 10 openssl s_client \
  -proxy 127.0.0.1:8080 \
  -connect example.com:443 \
  -servername example.com \
  -showcerts 2>&1 | \
  sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
  > /tmp/burp_cert_chain.pem

# 分离各个证书
python3 << 'EOF'
import re
with open('/tmp/burp_cert_chain.pem') as f:
    content = f.read()
certs = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', content, re.DOTALL)
# 最后一个证书是自签名根 CA（subject == issuer）
root_cert = certs[-1]
with open('/tmp/burp_ca.pem', 'w') as f:
    f.write(root_cert.strip() + '\n')
print(f"CA 根证书已保存: /tmp/burp_ca.pem")
EOF
```

**CA 证书指纹**: CN=PortSwigger CA, 有效期 2014-2036 (22年)

## 四、安装 CA 证书

### 4.1 系统信任存储 (Debian/Kali)

```bash
cp /tmp/burp_ca.pem /usr/local/share/ca-certificates/burp_ca.crt
update-ca-certificates
# 验证
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /tmp/burp_ca.pem
```

### 4.2 Chromium NSS 数据库

```bash
apt-get install -y libnss3-tools  # 安装 certutil
certutil -A -d sql:/root/.pki/nssdb -t "CT,," -n "Burp Suite CA" -i /tmp/burp_ca.pem
certutil -L -d sql:/root/.pki/nssdb | grep -i burp  # 验证
```

### 4.3 Firefox (需先启动过 Firefox)

```bash
CERTDIR=$(find /root/.mozilla/firefox -name "cert9.db" 2>/dev/null | head -1 | xargs dirname)
[ -n "$CERTDIR" ] && certutil -A -d "$CERTDIR" -t "CT,," -n "Burp Suite CA" -i /tmp/burp_ca.pem
```

## 五、配置浏览器代理

```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
```

Firefox GUI: Preferences → Network Settings → Manual proxy → HTTP: 127.0.0.1:8080, 勾选 "Also use for HTTPS"

## 六、测试验证

```bash
# HTTP
curl -x http://127.0.0.1:8080 http://httpbin.org/ip

# HTTPS
curl -x http://127.0.0.1:8080 --cacert /tmp/burp_ca.pem https://httpbin.org/ip

# 使用系统证书
curl -x http://127.0.0.1:8080 https://httpbin.org/ip
```

### 6.1 Burp MCP 闭环验证（Hermes 使用）

排查 Hermes 能否操控 Burp 时要分层验证：

1. Hermes MCP 配置/工具发现：
```bash
hermes mcp list
hermes mcp test burpsuite
```
期望 `burpsuite` enabled，`hermes mcp test burpsuite` 能连接并发现工具（常见工具：`burp_health`、`burp_proxy_request`、`burp_logs`、`burp_analyze_logs`、`burp_clear_logs`、`burp_import_export_xml`）。

2. Burp 代理进程：
```bash
/root/.hermes/scripts/hermes-ensure-tools.sh --burp
ss -tlnp | grep ':8080'
```
注意：Burp MCP server 正常不等于 Burp Suite 代理已监听；`burp_health` 报 `connection refused` 通常是 Burp GUI/Proxy 未启动，不是 MCP 配置损坏。

3. MCP 实际请求/日志闭环：
- 先用 `burp_clear_logs` 清空 `/root/.hermes/burp_mcp/traffic.jsonl`。
- 用 `burp_proxy_request` 分别请求一个 HTTP 和 HTTPS 测试 URL，例如：
  - `http://httpbin.org/get?hermes_burp_mcp_check=1`
  - `https://httpbin.org/get?hermes_burp_mcp_https_check=1`
- 再用 `burp_logs(search='hermes_burp_mcp')` 和 `burp_analyze_logs` 验证日志中出现 2 条 200 响应。

4. 升级判断：
```bash
burpsuite --version
apt-cache policy burpsuite
```
若 `已安装` 与 `候选` 相同，Kali 当前源无可用升级；不要为了“开启 MCP”盲目升级。Hermes 当前 Burp MCP 是通过本地 `burp_mcp_server.py` 调 Burp HTTP proxy 完成，不依赖 Burp 官方内置 MCP 开关。

## 七、通过 Burp 发送请求 (Repeater 替代方案)

当需要在 Burp Proxy 捕获的流量上做修改重放时，最方便的方式是:

```bash
# 直接通过代理发修改后的请求
curl -x http://127.0.0.1:8080 -X POST https://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"key":"value"}'
```

## 七点五、Windows Proxifier → Kali Burp 抓微信/QQ小程序

适用场景：小程序运行在用户 Windows 电脑上，Burp 在 Kali/Hermes 机器上，需要把 Windows 进程流量转发到 Kali Burp 供 Hermes 分析。

### 7.5.1 Kali 侧准备

Burp 默认只监听 `127.0.0.1:8080`，Windows 不能直接访问。保持 Burp GUI/代理进程运行，然后用网卡 IP 做转发：

```bash
/root/.hermes/scripts/hermes-ensure-tools.sh --burp
KALI_IP=$(ip -4 addr show eth0 | awk '/inet /{print $2}' | cut -d/ -f1)
pkill -f "socat TCP-LISTEN:8080,bind=$KALI_IP" 2>/dev/null || true
socat TCP-LISTEN:8080,bind=$KALI_IP,fork,reuseaddr TCP:127.0.0.1:8080
```

验证：

```bash
ss -tlnp | grep -E "127.0.0.1:8080|$KALI_IP:8080"
curl -x "http://$KALI_IP:8080" http://httpbin.org/ip
```

### 7.5.2 Windows Proxifier 正确规则

Proxy Server 里配置 Kali：

- Address: `KALI_IP`（例如 `192.168.110.137`）
- Port: `8080`
- Protocol: `HTTPS`（不通再试 HTTP）
- Authentication: none

Proxification Rules 顺序必须是：

1. `Localhost Direct`
   - Applications: Any
   - Target hosts: `localhost;127.0.0.1;%ComputerName%;::1`
   - Target ports: Any
   - Action: Direct

2. `Kali Direct`
   - Applications: Any
   - Target hosts: `KALI_IP`
   - Target ports: Any
   - Action: Direct

3. `WeChat MiniProgram to Burp`
   - Applications: `WeChat.exe;WeChatAppEx.exe;WeChatBrowser.exe;WeChatWeb.exe;WeChatApp.exe;wmpf_host.exe;wmpf.exe;XWeb.exe;miniapp.exe;WeChatPlayer.exe;WeChatUtility.exe`
   - Target hosts: Any
   - Target ports: `80;443;8080;8443`
   - Action: Proxy HTTPS kali

4. `Default`
   - Applications: Any
   - Target hosts: Any
   - Target ports: Any
   - Action: Direct

关键坑：`Target hosts/ports` 是“目标业务站点”，不是代理服务器。不要把 `KALI_IP:8080` 写进微信规则的 Target hosts/ports；`KALI_IP:8080` 只应该出现在 Proxy Server 配置里。端口分隔符必须用英文半角分号：`80;443;8080;8443`，不要用中文 `；`。

如测 QQ 小程序，在 Localhost/Kali Direct 后增加 QQ 规则：

- Applications: `QQ.exe;qq.exe;QQProtect.exe;QQExternal.exe;QQMiniApp.exe;QQBrowser.exe`
- Target hosts: Any
- Target ports: `80;443;8080;8443`
- Action: Proxy HTTPS kali

不要把 Default 设为 Proxy；否则 Edge、Office、系统后台、QQ/微信本地 `127.0.0.1:921x` 检活都会污染 Burp，甚至破坏本地组件通信。

### 7.5.3 Windows 安装 Burp CA

在 Windows 浏览器访问：

```text
http://KALI_IP:8080
```

下载 `cacert.der`，安装到：

- 本地计算机
- 受信任的根证书颁发机构

### 7.5.4 验证路径

先用 Edge 临时验证链路，再测小程序：

1. 临时 Proxifier 规则：`msedge.exe -> Any host -> 80;443 -> Proxy kali`
2. Edge 打开 `http://httpbin.org/get`
3. Burp HTTP history 应出现 `httpbin.org` 明文请求
4. 测完删除/禁用 Edge 规则，避免污染

若 Burp 只有 `servicewechat.com`、`sh.servicewechat.com`、`/ob/sdkmonitor`、`/ob/wxob`、`/wxa-qbase/report`，这通常只是微信基础库/监控上报，不是业务接口。继续在 Proxifier Connections 中找访问真实业务域名的进程并加入规则；同时在小程序中触发强制联网动作：退出重进、切换周次/学期、课程详情、个人中心/绑定学校/下拉刷新。

### 7.5.5 Hermes 分析注意事项

- 保持 Burp GUI/代理进程运行。关闭 Burp GUI 往往会关闭 `127.0.0.1:8080` 代理；此时 socat 仍可能监听 `KALI_IP:8080`，但后端会 `connection refused`。
- Burp MCP 的 JSON 日志不一定等同于 Burp GUI 的 Proxy HTTP history；外部 Windows/Proxifier 进来的流量可能已在 GUI 中可见，但 MCP log 仍为空。遇到这种情况，以 GUI HTTP history、Burp 导出 XML、或命令行抓包/mitmproxy 作为分析来源。
- 快速判断 Windows 是否真的打到 Kali：

```bash
timeout 20 tcpdump -i eth0 -nn -A 'tcp port 8080'
```

看是否有来自 Windows IP 的 `CONNECT host:443 HTTP/1.1`、`GET`、`POST`、`Host:`。若 tcpdump 有流量但 Burp 无明文，继续检查 Burp 是否运行、证书是否安装、是否是 CONNECT 隧道或证书校验问题。

## 八、常见问题

### Q: 请求超时/卡住
**原因**: Intercept 是 ON。关闭方法见第二节，或 GUI 中点 Proxy → Intercept → "Intercept is off"

### Q: HTTPS 证书错误
**原因**: Burp CA 证书未安装。按第四节操作安装到对应位置。

### Q: 代理端口 8080 不监听
**原因**: Burp 可能未完全启动。检查是否有恢复弹窗/启动向导需要处理。
**排查**: `DISPLAY=:0.0 xdotool search --name "Burp"` 查看窗口列表

### Q: Burp Suite 频繁弹临时项目恢复对话框
**原因**: 上次 Burp 异常退出。按 Tab+Enter 处理弹窗即可。

## 九、xdotool 常用操作速查

| 操作 | 命令 |
|------|------|
| 查找窗口 | `xdotool search --name "Burp Suite Community Edition"` |
| 激活窗口 | `xdotool windowactivate <WID>` |
| 发送按键 | `xdotool key ctrl+shift+P` |
| 关闭 Intercept | `xdotool key ctrl+T` (在 Proxy 标签下) |
| 按 Tab | `xdotool key Tab` |
| 按 Enter | `xdotool key Return` |
| 按 Escape | `xdotool key Escape` |

## 十八、Windows Proxifier → Kali Burp 抓微信/QQ小程序

适用场景：小程序运行在用户 Windows 电脑上，Burp Suite 运行在 Kali/Hermes 机器上，需要让 Windows 的 Proxifier 把小程序流量转发到 Kali Burp，便于 Hermes 通过 Burp/MCP 分析。

### 18.1 Kali 侧先确认代理入口

1. 启动/确认 Burp：
```bash
/root/.hermes/scripts/hermes-ensure-tools.sh --burp
/root/.hermes/scripts/hermes-ensure-tools.sh --status
```

2. Burp 默认只监听 `127.0.0.1:8080` 时，用 `socat` 暴露到 Kali 网卡 IP：
```bash
KALI_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+')
pkill -f "socat TCP-LISTEN:8080,bind=$KALI_IP" 2>/dev/null || true
socat TCP-LISTEN:8080,bind=$KALI_IP,fork,reuseaddr TCP:127.0.0.1:8080 &
ss -tlnp | grep "$KALI_IP:8080"
```

3. 告诉用户 Windows 侧代理服务器只填：`KALI_IP:8080`。不要把这个地址写进 Proxifier 规则的 Target Hosts。

### 18.2 Proxifier 的关键概念

- Proxy Server 里的 `KALI_IP:8080` 是“代理服务器地址”。
- Rule 里的 `Target Hosts/Target Ports` 是“被测程序要访问的真实目标站点/端口”。
- 常见错误：把 `192.168.x.x` 和 `8080` 写进小程序规则的 Target Hosts/Ports，导致规则只匹配访问 Kali 代理本身的连接，真实 `api.xxx.com:443` 小程序流量不会命中。

### 18.3 推荐 Proxifier 规则顺序

按从上到下顺序：

1. `Localhost Direct`
   - Applications: `Any`
   - Target Hosts: `localhost;127.0.0.1;%ComputerName%;::1`
   - Target Ports: `Any`
   - Action: `Direct`

2. `Kali Direct`
   - Applications: `Any`
   - Target Hosts: Kali IP，例如 `192.168.110.137`
   - Target Ports: `Any`
   - Action: `Direct`

3. `WeChat MiniProgram`
   - Applications: `WeChat.exe;WeChatAppEx.exe;WeChatBrowser.exe;WeChatWeb.exe;WeChatApp.exe;wmpf_host.exe;wmpf.exe;XWeb.exe;miniapp.exe;wechatappex.exe;wechatbrowser.exe`
   - Target Hosts: `Any`
   - Target Ports: `80;443;8080;8443`
   - Action: `Proxy HTTPS kali`（指向 Kali IP:8080）

4. 如测 QQ 小程序，可加 `QQ MiniProgram`
   - Applications: `QQ.exe;qq.exe;QQProtect.exe;QQExternal.exe;QQMiniApp.exe;QQBrowser.exe`
   - Target Hosts: `Any`
   - Target Ports: `80;443;8080;8443`
   - Action: `Proxy HTTPS kali`

5. `Default`
   - Applications: `Any`
   - Target Hosts: `Any`
   - Target Ports: `Any`
   - Action: `Direct`

注意：端口分隔符必须是英文半角分号 `;`，不要使用中文全角 `；`。

### 18.4 证书

Windows 访问：
```text
http://<KALI_IP>:8080
```
下载 Burp CA，并安装到：
```text
本地计算机 → 受信任的根证书颁发机构
```
不是“当前用户/个人”。

### 18.5 验证和排错顺序

1. 清空 Burp MCP 日志，避免旧包干扰：
```python
# 使用 burp_clear_logs 工具，或清空 /root/.hermes/burp_mcp/traffic.jsonl
```

2. 先做 Edge Test 切分问题：临时加规则 `msedge.exe -> Any host -> 80;443 -> Proxy HTTPS kali`，Windows Edge 打开：
```text
http://httpbin.org/get
```
如果 Burp 能收到 Edge 流量，说明 Windows→Kali→Burp 链路正常，后续只需修小程序进程匹配；如果收不到，优先查 Proxifier 代理服务器、规则启用状态、Windows 到 Kali 连通性。

3. 小程序实际操作时，在 Proxifier Connections 中找“访问真实业务域名”的进程，例如：
```text
WeChatAppEx.exe - api.example.com:443 open through proxy kali HTTPS
```
而不是：
```text
127.0.0.1:921x
192.168.x.x:8080
msedge.exe - msn/bing/office 域名
```
看到真实业务域名后，把对应 exe 补进小程序规则的 Applications。

4. 如果 Proxifier 显示 through proxy，但 Burp/MCP 没有明文请求：
   - 先确认是否只有 CONNECT；
   - 检查 Windows 是否把 Burp CA 装到了“本地计算机/受信任的根证书颁发机构”；
   - 若浏览器 HTTPS 可解密但小程序不行，再考虑小程序/内置网络栈证书绑定、微信特殊网络栈或需要开发者工具/Hook/解包辅助。

### 18.6 常见污染源

- `Default` 设成 Proxy 会把 Edge、Office、系统更新、QQ 后台全部送进 Burp，污染 HTTP history；默认应为 Direct。
- `qq.exe -> 127.0.0.1:9210-9219` 一类本地端口必须 Direct，不应进 Burp。
- `msedge.exe -> msn/bing/office/graph.microsoft.com` 通常不是目标小程序流量，除非正在做 Edge Test。

---

## 移动端/远端客户端抓包补充

- Windows Proxifier 把微信/QQ小程序流量转发到 Kali Burp 的完整配置、排错和业务流量筛选见 `references/windows-proxifier-miniprogram.md`。

# 移动端 APP 抓包 (Android)

## 十、环境准备

**Kali 信息**:
- IP: `ip -4 addr show eth0 | grep inet` → 通常 192.168.x.x
- Burp 代理监听 127.0.0.1:8080

**Android/ADB**:
```bash
apt-get install -y android-sdk-platform-tools
adb devices  # 确认设备连接
```

**模拟器端口**: 夜神 62001, 逍遥 21503, Genymotion 5555

## 十一、Burp 代理绑定到网卡 (关键！)

**问题**: Burp 默认绑定 127.0.0.1，手机无法连接。

**方案A: GUI 修改 (手动，需桌面环境)**
Proxy → Proxy Settings → Proxy Listeners → 选中已有 listener → Edit
→ Bind to address: 选择 "All interfaces" 或具体网卡 IP
→ 勾选 "Support invisible proxying"

**方案B: socat 端口转发 (纯 CLI，推荐)**
```bash
# 获取 Kali 网卡 IP
KALI_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+')
echo "Kali IP: $KALI_IP"

# 转发 网卡:8080 → 127.0.0.1:8080
socat TCP-LISTEN:8080,bind=$KALI_IP,fork,reuseaddr TCP:127.0.0.1:8080 &
echo "socat forwarding: $KALI_IP:8080 → 127.0.0.1:8080"
```

## 十二、Android 证书转换

证书须为 DER 格式 + 计算 subject_hash_old + 重命名为 `<hash>.0`:

```bash
# 从系统已安装的 CA 转换
CA_PEM=/usr/local/share/ca-certificates/burp_ca.crt

# 1. PEM → DER (Android 需要 DER)
openssl x509 -inform PEM -in $CA_PEM -outform DER -out /tmp/burp_ca.der

# 2. 计算 Android 系统证书 hash
HASH=$(openssl x509 -inform PEM -subject_hash_old -in $CA_PEM | head -1)
echo "Hash: $HASH"

# 3. 创建 Android 系统证书文件
cp $CA_PEM /tmp/${HASH}.0
echo "证书文件: /tmp/${HASH}.0"
```

**本例实际值**: Hash=`9a5ba575`, 文件=`/tmp/9a5ba575.0`

## 十三、推送证书到 Android 设备

### Android ≤7 (用户证书即可)
手机浏览器访问 `http://burp` 下载 cacert.der → 安装

### Android ≥9 (必须系统证书！用户证书无效)
```bash
# 1. 连接设备
adb connect 127.0.0.1:62001   # 夜神模拟器示例
adb devices

# 2. 推送到设备
adb push /tmp/9a5ba575.0 /data/local/tmp/

# 3. 进入 shell → root → 挂载系统可写 → 复制证书
adb shell
su
mount -o rw,remount /system
cp /data/local/tmp/9a5ba575.0 /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/9a5ba575.0
reboot
```

### SSL Pinning 绕过 (APP 证书绑定)
如抓不到 HTTPS 包:
- **JustTrustMe** (Xposed 模块) - 最简单
- **Frida**: `frida -U -l ssl_pinning_bypass.js -f com.target.app`
- **修改 APK**: 反编译 → 修改 smali → 重打包

## 十四、设备代理配置

手机 WiFi → 修改网络 → 高级选项:
- 代理: 手动
- 主机名: Kali IP (如 192.168.110.137)
- 端口: 8080

## 十五、开始抓包

```bash
# 1. 确认 Burp 运行中
ss -tlnp | grep 8080

# 2. 确认 socat 转发运行中 (如用方案B)
pgrep -f "socat.*8080"

# 3. 确保 Intercept 关闭 (让流量通过)
# Ctrl+Shift+P → Ctrl+T

# 4. 手机上操作 APP，Burp → HTTP History 查看
```

## 十八、Windows Proxifier 抓微信/QQ小程序流量

当小程序运行在用户 Windows 主机、Burp 运行在 Kali 时，按 `references/windows-proxifier-miniprogram-burp.md` 配置 Proxifier 规则和 Kali socat 转发。关键坑：小程序规则的 Target hosts/ports 是业务目标，不是 Kali 代理地址；Default 应保持 Direct；Localhost/Kali Direct 必须排在前面；Burp GUI 的 HTTP history 可能已有外部客户端流量而 MCP JSON 日志仍为空，此时直接查 GUI 或导出 HTTP history XML 分析。


|------|------|------|
| 抓不到任何包 | 代理 IP/端口错误 | 检查 Kali IP + 8080 |
| 抓不到任何包 | 手机与 Kali 不同网 | ping Kali IP |
| HTTPS 乱码/证书错误 | Android 9+ 未装系统证书 | 按十三推送系统证书 |
| HTTPS 乱码/证书错误 | hash 文件名错误 | 重算 `subject_hash_old` |
| 某 APP 抓不到 HTTPS | SSL Pinning | JustTrustMe / Frida |
| adb 连不上 | 模拟器未开启 USB 调试 | 检查端口（夜神62001） |

## 十八、Windows Proxifier 抓微信/QQ小程序流量

当小程序运行在用户 Windows 机器、Burp 运行在 Kali 时，参考 `references/windows-proxifier-miniprogram.md`。核心原则：Kali 用 socat 将网卡 IP:8080 转发到 Burp 127.0.0.1:8080；Windows Proxifier 只代理微信/QQ小程序外网 80/443；localhost、LAN、Edge/无关浏览器必须 Direct，避免 `127.0.0.1:921x` 和 Edge/Office/MSN/Bing 流量污染 Burp。



```bash
#!/bin/bash
# Burp Suite 移动端抓包一键配置
set -e

echo "[1/5] 检查 ADB..."
which adb || apt-get install -y android-sdk-platform-tools

echo "[2/5] 获取 Kali IP..."
KALI_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+')
echo "  Kali IP: $KALI_IP"

echo "[3/5] 启动 socat 转发 ${KALI_IP}:8080 → 127.0.0.1:8080..."
pkill -f "socat.*8080" 2>/dev/null || true
socat TCP-LISTEN:8080,bind=$KALI_IP,fork,reuseaddr TCP:127.0.0.1:8080 &
echo "  socat PID: $!"

echo "[4/5] 准备 Android 证书..."
CA_PEM=/usr/local/share/ca-certificates/burp_ca.crt
HASH=$(openssl x509 -inform PEM -subject_hash_old -in $CA_PEM | head -1)
cp $CA_PEM /tmp/${HASH}.0
echo "  证书: /tmp/${HASH}.0"

echo "[5/5] 生成 adb push 命令..."
echo ""
echo "  === 在手机上执行 ==="
echo "  1. WiFi代理: $KALI_IP:8080"
echo "  2. 推送证书:"
echo "     adb push /tmp/${HASH}.0 /data/local/tmp/"
echo "     adb shell"
echo "     su -c 'mount -o rw,remount /system'"
echo "     su -c 'cp /data/local/tmp/${HASH}.0 /system/etc/security/cacerts/'"
echo "     su -c 'chmod 644 /system/etc/security/cacerts/${HASH}.0'"
echo "     reboot"
echo ""
echo "  3. 打开APP → Burp HTTP History 查看流量"
```
