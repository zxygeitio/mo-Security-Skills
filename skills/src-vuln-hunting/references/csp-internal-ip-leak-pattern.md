# CSP Header Internal IP/Domain Leak Pattern

## Trigger
Target returns Content-Security-Policy or Content-Security-Policy-Report-Only headers.

## Detection
```bash
curl -sk -D- "https://TARGET/" | grep -i content-security-policy
# Look for: IP addresses, internal domains, port numbers in CSP directives
```

## Common Leak Locations
- `frame-ancestors` — internal admin panels, IP-based access control
- `script-src` — CDN origins, internal analytics servers
- `connect-src` — API endpoints, websocket servers
- `default-src` — catch-all that sometimes includes internal hosts

## What to Look For
```
# Internal IPs (RFC1918 or carrier-grade NAT)
http://192.168.x.x:port
http://10.x.x.x:port
http://172.16-31.x.x:port
http://219.x.x.x:port    # Common in Chinese university networks

# Internal domains
*.internal.domain
*.local
iknow.*, ssfwrx.*, portal.*  # University internal systems

# Development/staging environments
dev.*, test.*, staging.*
```

## Impact
- Reveals internal network topology
- Identifies internal services and their ports
- Aids in targeted attacks against internal infrastructure
- May reveal development/staging environments

## Severity: Low/Informational
This is typically low severity unless it reveals:
- Credentials or API keys in CSP values
- Critical internal infrastructure details
- Development environments accessible from internet

## Real Examples
- cumt.edu.cn: CSP `frame-ancestors` leaked `http://219.219.51.168:8422` + `iknow.cumt.edu.cn` + `ssfwrx.cumt.edu.cn`
- Many Chinese university sites leak internal IPs in CSP due to iframe embedding requirements for internal systems
