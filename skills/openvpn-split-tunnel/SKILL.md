---
name: openvpn-split-tunnel
description: Configure OpenVPN split tunnel to access target internal networks while preserving local internet/AI API access. Essential for pentest engagements where VPN would otherwise redirect all traffic.
---

# OpenVPN Split Tunnel Configuration

> **⚠️ TOP PRIORITY: NEVER break AI model connectivity.**
> User has explicitly flagged this. If VPN routes AI API traffic through the tunnel, the agent becomes deaf-mute. Always verify `curl -s -o /dev/null -w "%{http_code}" https://api.anthropic.com` returns 2xx/4xx (not timeout) AFTER connecting. A timeout means routing is broken — fix immediately before doing anything else.

## Context
When connecting to a corporate VPN for penetration testing, the server often pushes `redirect-gateway` which routes ALL traffic through the VPN. This breaks AI API access (and other public internet traffic). The goal is to selectively route only target internal network ranges through the VPN while everything else goes local.

## Quick Pre-Flight Checklist (run AFTER every VPN connect)

```bash
# 1. Tunnel up?
ip addr show tun0 | grep "inet "

# 2. Default route still local (NOT tun0)?
ip route | grep "^default" | grep -v tun0

# 3. AI API reachable (MUST get response, not timeout)?
curl -s -o /dev/null -w "HTTP %{http_code} %{time_total}s\n" --max-time 10 https://api.anthropic.com

# 4. No rogue routes hijacking public IPs?
ip route | grep -E "^220\.|^198\.18\." | grep tun0 && echo "BROKEN: public IP routed through VPN!"

# 5. Target internal network reachable via tun0?
ip route get 101.204.1.1 | grep tun0 && echo "OK: internal via VPN"
```

If any check fails, `sudo pkill -f openvpn` and re-diagnose before proceeding.

## Known VPN Servers

| 服务器 | IP:端口 | 用途 | 状态 |
|--------|---------|------|------|
| 太保SRM VPN | 123.57.208.95:1192 | 太保内网渗透 | ✅ 正常 |
| 深信服设备 | 120.202.175.142:1194 | 错误配置目标 | ❌ AUTH_FAILED |

> ⚠️ 账号 499092-3736/rvzJQR 对应 **太保SRM VPN (123.57.208.95)**，不是深信服设备。
> 深信服设备(120.202.175.142)用同一账号会报 AUTH_FAILED。

## Pattern (client-side config)

```
# /home/zxy/client-split.ovpn
client
dev tun
proto tcp
remote 123.57.208.95 1192
cipher AES-128-CBC
auth SHA1
resolv-retry infinite
nobind

# --- SPLIT TUNNEL CORE ---
# 1. Don't accept the server's redirect-gateway push
route-nopull

# 2. Ignore DNS redirect (avoid VPN DNS leaks)
pull-filter ignore "dhcp-option DNS"
pull-filter ignore "redirect-gateway"

# 3. Manually add routes ONLY for the target internal network ranges
route <TARGET_NET_1> 255.0.0.0 vpn_gateway
route <TARGET_NET_2> 255.0.0.0 vpn_gateway
# ... add all target ranges

# 4. Default route stays local (公网流量走本地)
```

## Common Target Network Ranges (太保内网示例)
```
101.0.0.0/8   route via VPN
103.0.0.0/8   route via VPN
112.0.0.0/8   route via VPN
116.0.0.0/8   route via VPN
121.0.0.0/8   route via VPN
180.0.0.0/8   route via VPN
58.0.0.0/8    route via VPN
182.0.0.0/8   route via VPN
```

## Verification Steps

```bash
# 1. Start VPN
sudo openvpn --config client-split.ovpn --auth-user-pass vpn-pass.txt &

# 2. Verify tunnel exists
ip addr show tun0

# 3. Verify routing - VPN should only own target ranges
ip route show

# 4. Test AI API (should go LOCAL, not through VPN)
curl -I api.minimax.chat
# Expected: normal response (308/200), NOT routed through tun0

# 5. Test target internal network (should go through tun0)
ping <TARGET_INTERNAL_IP>
# Expected: packet goes through tun0 (check with: ip route get <IP>)

# 6. Test public internet (should go LOCAL)
curl -I www.baidu.com
# Expected: normal response
```

## Critical Pitfall - 220.0.0.0/8 Route Collision

**Problem**: After connecting, you may find `220.0.0.0/8` was somehow added to the routing table and routed through VPN. This breaks public internet access (e.g., `curl www.baidu.com` hangs or fails).

**Diagnosis**:
```bash
ip route | grep 220   # if you see this, it's wrong
curl -v www.baidu.com # will hang/timeout
```

**Fix**:
```bash
sudo ip route del 220.0.0.0/8 via 192.168.216.213 dev tun0
# or if it has a different gateway:
sudo ip route del 220.0.0.0/8 dev tun0
```

**Cause**: The VPN server may push routes that inadvertently capture public IP ranges. Always check `ip route` after connecting and verify public internet still works before starting tests.

## Critical Pitfall - 198.18.x Reserved Address Range

**Problem**: AI API `api.minimax.chat` resolves to `198.18.0.183` (IETF reserved range 198.18.0.0/15, used for benchmark/CGNAT). If this range is routed through VPN, API calls fail.

**Diagnosis**:
```bash
nslookup api.minimax.chat  # check if it resolves to 198.18.x
ip route get 198.18.0.183  # should show "via 192.168.110.2 dev eth0", NOT tun0
curl -I api.minimax.chat  # will fail/timeout if routed through VPN
```

**Fix**: Ensure 198.18.0.0/15 routes through local gateway, not VPN:
```
route 198.18.0.0 255.255.0.0 192.168.110.2
```

**ROT VPN Infrastructure Fingerprint (2026-04-23)**:
- ROT VPN代理的SSL证书特征: `O=ROT Proxy, CN=*.cpic.com.cn` 或 `CN=vpn.cpic.com.cn`
- 自签名证书，O字段为"ROT Proxy"的都是VPN网关，不是业务系统
- 部分ROT设备只开放443端口但TLS握手需要客户端证书 (`tlsv1 alert internal error`)
- 探测真实业务系统方法: 检查证书O字段，排除ROT Proxy
```
echo | openssl s_client -connect $IP:443 2>/dev/null | openssl x509 -noout -subject
# O=ROT Proxy → VPN基础设施, O=中国太保/CPIC → 真实业务系统
```

**General Rule**: Always verify `nslookup api.<provider>` BEFORE and AFTER connecting VPN to catch routing conflicts.

## 内网扫描发现：ROT VPN代理识别特征

**背景**: 通过VPN进入内网后，发现大量IP是ROT VPN代理网关（O=ROT Proxy），而非太保业务系统。

**识别特征**:
- 端口: 通常只有443开放
- 证书: CN多为`vpn.cpic.com.cn`或`rot.proxy`，O字段为`ROT Proxy`
- TLS行为: `tlsv1 alert internal error (alert number 80)` = 服务器要求客户端证书认证
- 开放端口: 22/TCP filtered, 445/TCP filtered（防火墙规则一致）

**探测命令**:
```bash
# 快速识别ROT代理
echo | timeout 3 openssl s_client -connect <IP>:443 2>/dev/null | openssl x509 -noout -subject

# TLS行为分析（alert 80 = 需要客户端证书）
timeout 3 openssl s_client -connect <IP>:443 </dev/null 2>&1 | grep "alert"

# 批量识别（无O=ROT的是潜在目标）
for ip in <IP_LIST>; do
  cn=$(echo | timeout 3 openssl s_client -connect $ip:443 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
  echo "$ip: $cn"
done
```

**教训**: VPN内网扫描时，先用证书O字段过滤区分VPN基础设施和业务系统，避免浪费时间在代理网关上。

## Pitfall - Don't Assume Existing Configs Match New Credentials

When the user provides VPN credentials for a new platform (e.g., "360漏洞平台 VPN"), do NOT blindly reuse existing `.ovpn` configs from other projects. Each engagement typically has its own VPN server. The correct sequence:

1. Ask for the server address (IP:port) or the `.ovpn` config file path FIRST
2. Only then update credentials and connect
3. If the user says "find the config", search for it — but if no matching config exists, ask explicitly

Wrong approach: grab any existing .ovpn, update creds, try connecting → AUTH_FAILED, wastes time.
Right approach: "What's the VPN server address or config file for this platform?"

## VPN Credentials File Format
```
# /tmp/vpn_auth (每行一个凭据,无引号)
499092-3736
rvzJQR
```

**启动命令（必须在 /home/zxy 目录执行，因为 .ovpn 用相对路径引用 CA 证书）**:
```bash
cd /home/zxy && sudo openvpn --config client-split.ovpn --auth-user-pass /tmp/vpn_auth &
sleep 8 && ip addr show tun0
```

⚠️ **注意**: 该配置文件内有嵌入 CA 证书（`<ca>...</ca>`），必须在 `/home/zxy` 目录下执行，或使用绝对路径引用配置文件。

## 太保VPN测试结果 (2026-05-09)

### 配置验证
- VPN隧道: 192.168.246.57 → 192.168.246.58 ✓
- 默认路由: 192.168.110.2 (本地，未被VPN劫持) ✓
- 大模型API: 可达 (HTTP 403 = 正常，缺认证) ✓
- 198.18.x: 走本地网关 (保护API) ✓

### 路由分配
```
本地:  默认路由、198.18.0.0/16、API域名
VPN:   101.x/103.x/112.x/116.x/121.x/180.x/58.x/182.x (太保内网)
```

### 内网连通性测试
- 太保内网IP段 (101.x, 103.x, 112.x等) ping超时
- 测试环境域名DNS可解析但无法访问
- **结论**: 内网有防火墙限制或WAF阻断

## 360 Zhongce VPN pattern

When the user provides a 360 Zhongce VPN package, see `references/360-zhongce-vpn.md`. The observed package used `106.75.32.220:1194/udp`, `dev tun`, and pushed `redirect-gateway`; derive a split config with `pull-filter ignore "redirect-gateway"`, `pull-filter ignore "dhcp-option DNS"`, and `route-nopull`, then add only precise target routes after confirming in-scope IPs.

## Critical Pitfall - TAP Device Route Not Working (2026-05-09 深信服项目)

**Problem**: VPN uses `dev tap` (TAP layer-2) instead of `dev tun` (TUN layer-3). With `route-nopull`, the VPN assigns an IP (e.g., 10.8.16.43/16) and adds a route via the gateway (10.8.0.1), but the gateway doesn't respond to ARP requests. Result: `ping` and `curl` to target IPs hang/timeout.

**Diagnosis**:
```bash
ip addr show tap0   # IP assigned OK
ip route | grep <target_subnet>  # Route exists via 10.8.0.1
ping -c 2 <target>  # 100% packet loss
```

**Fix**: Remove `route-nopull` and let the VPN push routes normally, but use `pull-filter ignore "redirect-gateway"` to prevent default gateway hijacking:
```
# WRONG for TAP devices:
route-nopull
route <target_subnet> 255.255.255.240

# CORRECT for TAP devices:
pull-filter ignore "redirect-gateway"
pull-filter ignore "dhcp-option DNS"
# VPN server pushes routes automatically via PUSH_REPLY
```

**Key difference**: TUN devices work with `route-nopull` + manual routes because the point-to-point link handles routing. TAP devices need the server to push proper routes because they use ARP for layer-2 resolution.

**Verification after TAP VPN connect**:
```bash
ip addr show tap0                    # IP assigned
ip route | grep <target_subnet>     # Route exists
ping -c 2 <target_ip>               # Must succeed
curl -sk --max-time 10 https://target # Must get HTTP response
```

## Debug Commands
```bash
# Full routing table
ip route

# Check if AI API domain resolves to expected IP
nslookup api.minimax.chat

# Trace packet path
ip route get <TARGET_IP>

# Kill stale VPN processes
sudo pkill -f openvpn

# Check VPN process
ps aux | grep openvpn
```
