# Windows Proxifier -> Kali Burp for WeChat/QQ Mini Program Traffic

## When to use
Use this when the user's Windows machine runs WeChat/QQ mini programs, while Burp Suite runs on Kali and Hermes needs to inspect mini program traffic.

## Known-good topology
- Windows Proxifier sends selected app traffic to Kali: `KALI_IP:8080`.
- Kali runs Burp on `127.0.0.1:8080`.
- If Burp only listens on loopback, expose it with socat: `socat TCP-LISTEN:8080,bind=$KALI_IP,fork,reuseaddr TCP:127.0.0.1:8080`.
- Keep Burp Intercept off; inspect Proxy -> HTTP history.

## Proxifier rule order
1. `Localhost Direct`
   - Applications: Any
   - Target hosts: `localhost;127.0.0.1;%ComputerName%;::1`
   - Target ports: Any
   - Action: Direct
2. `Kali Direct`
   - Applications: Any
   - Target hosts: Kali proxy IP, e.g. `192.0.2.137`
   - Target ports: Any
   - Action: Direct
3. `WeChat MiniProgram to Burp`
   - Applications: `WeChat.exe;WeChatAppEx.exe;WeChatBrowser.exe;WeChatWeb.exe;WeChatApp.exe;wmpf_host.exe;wmpf.exe;XWeb.exe;miniapp.exe;WeChatPlayer.exe;WeChatUtility.exe`
   - Target hosts: Any
   - Target ports: `80;443;8080;8443`
   - Action: Proxy to Kali Burp
4. Default
   - Action: Direct

For QQ mini programs, add a similar rule for the actual QQ process seen in Proxifier Connections, but keep Localhost/Kali Direct above it.

## Common mistakes
- Do not put the Kali proxy IP in the mini program rule's Target hosts. Target hosts are the destination business domains, not the proxy server.
- Do not set Default to Proxy. It floods Burp with Edge/Office/system traffic and can break local IPC.
- Do not proxy `127.0.0.1:*`; QQ/WeChat local ports such as `127.0.0.1:9210-9219` are local component health channels and should be Direct.
- Use ASCII semicolons in Proxifier fields: `80;443;8080;8443`, not Chinese `；`.

## Verification flow
1. Check Kali listener and forwarding:
   - `ss -tlnp | grep -E '127.0.0.1:8080|KALI_IP:8080'`
2. From Kali, test Burp proxy:
   - `curl -x http://127.0.0.1:8080 http://httpbin.org/ip`
3. From Windows/Proxifier, temporarily proxy `msedge.exe` and open `http://httpbin.org/get` to split chain issues from process-matching issues.
4. If Proxifier shows `open through proxy` but Burp MCP logs are empty, inspect Burp GUI HTTP history directly. Some MCP logs do not mirror traffic captured by the GUI proxy.
5. If GUI is closed and `127.0.0.1:8080` disappears, reopen Burp; the socat listener alone is not enough.
6. If GUI history sees only `servicewechat.com`, `sh.servicewechat.com`, `badjs.weixinbridge...`, or local `127.0.0.1` traffic, continue looking for the actual mini program process/domain in Proxifier Connections.

## Burp GUI vs MCP lesson
For traffic arriving from Windows through Proxifier into the Burp GUI proxy, Burp's GUI HTTP history may contain requests while the local Burp MCP JSON log remains empty. Do not conclude no traffic exists from MCP alone. Verify via GUI screenshot/OCR or Burp HTTP history XML export. If the user wants CLI-only capture, switch to mitmproxy/mitmdump on a separate port and have Proxifier point at it.
