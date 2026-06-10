# 360 Zhongce VPN split-tunnel notes

Session learning from configuring the 360 Zhongce VPN for Beijing Zhongguancun Bank testing.

## Source package

The relevant VPN package was found under:

- `/home/zxy/测试配置文件.zip`

Inside the zip, the Linux OpenVPN config is:

- `测试配置文件/客户端及使用说明v2/Linux客户端/32.220config.ovpn`

The package also contains `ca.crt`, but the `.ovpn` already embeds the CA block.

## Server and credentials pattern

Observed config values:

- `remote 106.75.32.220 1194`
- `proto udp`
- `dev tun`
- Auth is username/password via `auth-user-pass`

The VPN server pushes:

- `dhcp-option DNS 114.114.114.114`
- `redirect-gateway def1 bypass-dhcp`
- `route-gateway 10.9.0.1`
- `ifconfig 10.9.x.x 255.255.0.0`

## Safe split-tunnel approach

Do not connect with the raw config as-is because the server pushes `redirect-gateway`, which can route all traffic through the VPN and break model/API connectivity.

Use a derived config that keeps the original remote/proto/dev/CA/auth settings but adds:

```ovpn
pull-filter ignore "redirect-gateway"
pull-filter ignore "dhcp-option DNS"
route-nopull
```

This preserves local default route and public internet while still bringing up `tun0`. Add only precise target routes later when the authorized target IP/netblock is known.

## Verification checklist from this session

After connection, confirm:

```bash
ip -4 addr show tun0
ip route | grep '^default'
ip route | grep -E 'tun0|198\.18|220\.'
curl -s -o /dev/null -w 'HTTP %{http_code} %{time_total}s\n' --max-time 10 https://api.anthropic.com
curl -I -s --max-time 10 https://www.baidu.com | head -1
ping -c 2 -W 2 10.9.0.1
```

Expected good state:

- `tun0` receives a `10.9.x.x/16` address.
- Default route remains local, e.g. `default via 192.0.2.2 dev eth0`.
- Anthropic/API endpoint returns a fast HTTP status, not timeout.
- Public internet still responds.
- VPN gateway `10.9.0.1` is reachable.

## Operational caution for Zhongce projects

360 Zhongce project rules may require all testing to be through VPN while prohibiting scanning/high-risk operations. With route-nopull, do not assume all target domains automatically use VPN. Resolve each in-scope target, add narrow explicit routes for the target IP/CIDR via `tun0`/VPN gateway, and verify `ip route get <target_ip>` before sending test traffic.
