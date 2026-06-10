# Windows Proxifier -> Kali Burp for WeChat/QQ Mini Programs

Use when the target app runs on the user's Windows host and Burp Suite runs on Kali.

## Topology

Windows Proxifier -> Kali LAN IP:8080 -> socat -> Burp 127.0.0.1:8080

Example Kali IP seen in this environment: `192.0.2.137`.

## Kali side

1. Ensure Burp GUI/proxy is running and reachable on `127.0.0.1:8080`.
2. Expose Burp to the LAN without changing Burp listener settings:

```bash
KALI_IP=$(ip -4 addr show eth0 | awk '/inet /{print $2}' | cut -d/ -f1)
pkill -f "socat TCP-LISTEN:8080,bind=$KALI_IP" 2>/dev/null || true
socat TCP-LISTEN:8080,bind=$KALI_IP,fork,reuseaddr TCP:127.0.0.1:8080
```

3. Verify:

```bash
ss -tlnp | grep "$KALI_IP:8080"
```

## Windows Proxifier rules

Proxy server:
- Address: Kali LAN IP, e.g. `192.0.2.137`
- Port: `8080`
- Protocol: HTTPS usually works for HTTP CONNECT proxying; HTTP can also be tested if HTTPS fails.

Rules must be ordered top to bottom:

1. Localhost Direct
- Applications: Any
- Target hosts: `localhost;127.0.0.1;%ComputerName%;::1`
- Target ports: Any
- Action: Direct

2. Kali Direct
- Applications: Any
- Target hosts: Kali LAN IP, e.g. `192.0.2.137`
- Target ports: Any
- Action: Direct

3. WeChat MiniProgram to Burp
- Applications: `WeChat.exe;WeChatAppEx.exe;WeChatBrowser.exe;WeChatWeb.exe;WeChatApp.exe;wmpf_host.exe;wmpf.exe;XWeb.exe;miniapp.exe;WeChatPlayer.exe;WeChatUtility.exe`
- Target hosts: Any
- Target ports: `80;443;8080;8443`
- Action: Proxy Kali

4. Optional QQ MiniProgram to Burp
- Applications: `QQ.exe;qq.exe;QQProtect.exe;QQExternal.exe;QQMiniApp.exe;QQBrowser.exe`
- Target hosts: Any
- Target ports: `80;443;8080;8443`
- Action: Proxy Kali

5. Default
- Applications: Any
- Target hosts: Any
- Target ports: Any
- Action: Direct

Important pitfalls:
- Do NOT put the Kali IP/port in the mini-program rule's Target hosts/Target ports. Target means destination site, not proxy server.
- Do NOT leave Default as Proxy unless intentionally capturing all Windows traffic. It pollutes Burp with Edge/Office/system traffic.
- Use English semicolons in Proxifier lists: `80;443;8080;8443`, not Chinese `；`.
- Always keep localhost/direct rules above WeChat/QQ rules or local IPC like `127.0.0.1:921x` will be broken/proxied.

## Validation workflow

1. On Kali, run a short tcpdump while the user triggers traffic:

```bash
timeout 20 tcpdump -i eth0 -nn 'tcp port 8080' -c 20
```

Seeing `Windows_IP -> Kali_IP.8080` and `CONNECT host:443 HTTP/1.1` proves Proxifier reaches Kali.

2. Check Burp GUI: Proxy -> HTTP history. For external Windows clients, Burp GUI history can contain traffic even when the Hermes Burp MCP JSON log is empty.

3. If Hermes `mcp_burpsuite_burp_logs` is empty but GUI has packets, analyze via GUI screenshots/OCR or ask/export Burp HTTP history XML and import it with `mcp_burpsuite_burp_import_export_xml`.

4. If only `servicewechat.com`, `sh.servicewechat.com`, `gtimg.cn`, `qq.com`, or Microsoft/Edge telemetry appears, the business API is not captured yet. Have the user inspect Proxifier Connections for the real process and non-WeChat business domain, then add that `.exe` to the capture rule.

5. To force mini-program business requests, ask the user to remove/reopen the mini-program, switch week/term, open course detail, refresh, enter personal/login/bind-school pages, and disable Burp filters (`Filter on -> Show all`) so JS/config/API/static requests are not hidden.
