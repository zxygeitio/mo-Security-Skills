# 360 SRC VPN and Verification Workflow

## Trigger
Use this whenever continuing a 360 众测 / 360 SRC target that is VPN-scoped, especially assets resolving to `198.18.x.x` or requiring the 360 OpenVPN profile.

## Key lesson
If the user says to continue 360 vulnerability hunting, do not assume normal public routing is acceptable. First bring up and verify the 360 VPN, then test the target. The user explicitly corrected this workflow: “记得使用360的vpn”.

## Safe verification sequence
1. Check whether OpenVPN is already running and whether `tun0` exists.
2. If not connected, start the 360 split-tunnel OpenVPN profile using the saved auth file or credentials supplied by the user/session memory.
3. Verify all of the following before testing:
   - `tun0` has an address, commonly `10.9.x.x/16`.
   - The target request succeeds.
   - `curl -w '%{remote_ip}'` for the target shows an internal/VPN-side address when expected, e.g. `198.18.x.x`.
   - Public LLM/API connectivity still works, proving split tunnel did not hijack the default route.
4. Only then run vulnerability validation.

## Example commands
Do not paste credentials into reports. Use an auth file with restrictive permissions.

```bash
ps aux | grep -i '[o]penvpn' || true
ip -o -4 addr show tun0 || true

# If disconnected and profile exists:
chmod 600 /tmp/360_vpn_auth
openvpn --config /home/zxy/360-vpn-split.ovpn --auth-user-pass /tmp/360_vpn_auth --log /tmp/360_openvpn.log --verb 3

# In another shell / after startup:
grep -n 'Initialization Sequence Completed' /tmp/360_openvpn.log
ip -o -4 addr show tun0
curl -sk --max-time 5 -o /dev/null -w 'api=%{http_code}\n' https://api.anthropic.com
curl -sk --connect-timeout 5 --max-time 10 -o /dev/null -w 'target=%{http_code} size=%{size_download} ip=%{remote_ip}\n' https://pms.zgcbank.com/pms/ananymous/zzqx/zhmm
```

## Reporting impact
When delivering 360 reports after VPN-scoped testing, briefly state that VPN was active and include the target routing evidence in the internal notes if useful. Do not include VPN credentials in the vulnerability report.

## Long-running continuous hunting pattern
When the user asks to continue 360 hunting for a long time or “不间断”:
1. Start with the safe verification sequence above and keep split-tunnel routes explicit for known target IPs.
2. Run low-frequency background/foreground batches rather than noisy scans: common sensitive paths, health/error pages, app/H5 safe API probes, then mine downloaded HTML/JS for additional paths.
3. Persist every run under `/tmp/<target>/longrun_<timestamp>/` with `raw/`, `summary/`, and `reports/`; keep a current pointer file such as `/tmp/<target>/current_longrun_dir`.
4. In batch probe functions, always create empty `.hdr`/`.body` files if curl times out or fails before downstream parsing (`[ -f "$out.body" ] || : > "$out.body"`). Otherwise slow/unreachable assets such as `cms`/`vpn` can spam `No such file or directory` and stall analysis.
5. Group findings by root cause before reporting. Avoid duplicate submissions for repeated Tomcat/health/script-injection symptoms unless the asset, component version, or impact boundary is meaningfully different.
6. Only produce user-facing output after validation: new confirmed reports, evidence file paths, and updated cumulative count.
7. If no new independent issue appears, say which probes ran and that all hits were duplicates/low-value; do not inflate totals.

Useful batch structure:
- Round 1: probe `www/wx/app/h5/pms/static` with common paths (`/health.html`, `/robots.txt`, config/version paths, `.well-known`, `.git/HEAD`, `actuator`, `swagger`, `druid`, random 404).
- Round 2: extract URL/path strings from downloaded bodies and static JS, then safely GET/POST no-state endpoints.
- Analyze for `brmidyrvj.php`, abnormal injected scripts, `Apache Tomcat/x`, `SRVE0190E`, Java exceptions, health-page strings, CORS/security headers, and sensitive JSON fields.

## Related 360/ZGCBank patterns
- `pms.zgcbank.com` can be reachable via VPN-side `198.18.x.x` while still returning HTTP 200.
- For registration-chain CSRF bypass reports, keep the 403 no-cookie/no-CSRF control request; it proves the defense exists before demonstrating bypass with public-page `SESSION` + form `_csrf`.
