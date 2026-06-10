# System Audit Checklist

Quick-reference commands for comprehensive system health assessment.

## Disk & Storage

```bash
df -h / && du -sh /root /tmp /var/log /var/cache 2>/dev/null
du -sh /root/* 2>/dev/null | sort -rh | head -20

# Large files
find /root -type f -size +5M 2>/dev/null | grep -v ".hermes" | head -15

# Cleanable caches
du -sh /root/.cache/* 2>/dev/null | sort -rh | head -10
du -sh /root/.npm /root/.cache/pip /root/.cache/uv 2>/dev/null
```

## System Versions

```bash
uname -r
cat /etc/os-release | head -5
/usr/bin/python3 --version
node --version
go version
rustc --version
java -version 2>&1 | head -1
```

## Security Tools

```bash
echo "nmap: $(nmap --version 2>/dev/null | head -1)"
echo "nuclei: $(nuclei -version 2>&1 | head -1)"
echo "sqlmap: $(sqlmap --version 2>/dev/null)"
echo "ffuf: $(ffuf -V 2>/dev/null | head -1)"
echo "hashcat: $(hashcat --version 2>/dev/null)"
echo "hydra: $(hydra -V 2>&1 | head -1)"
echo "nikto: $(nikto -Version 2>&1 | head -1)"
echo "wpscan: $(wpscan --version 2>/dev/null)"
```

## Security Hardening

```bash
# Password policy
grep -E "^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)" /etc/login.defs

# SSH config
grep -E "^(PermitRootLogin|PasswordAuthentication|Port|PubkeyAuthentication|X11Forwarding)" /etc/ssh/sshd_config

# Kernel security
sysctl -a 2>/dev/null | grep -E "(kernel.dmesg_restrict|kernel.kptr_restrict|kernel.randomize_va_space|net.ipv4.conf.all.send_redirects|net.ipv4.ip_forward)"

# Security services
systemctl status fail2ban 2>/dev/null | head -3
systemctl status auditd 2>/dev/null | head -3
```

## Performance Tuning

```bash
# Network params
sysctl -a 2>/dev/null | grep -E "(net.core.somaxconn|net.ipv4.tcp_max_syn_backlog|net.ipv4.tcp_fin_timeout|net.ipv4.tcp_tw_reuse)"

# File descriptors
ulimit -n

# Memory/CPU
free -h
lscpu | grep -E "^CPU|^Thread|^Core|^Model name"
```

## Docker & Containers

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
docker images | head -10
docker info 2>/dev/null | grep -E "(Security Options|Live Restore)"
```

## Network Exposure

```bash
# External-facing ports (exclude localhost)
ss -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1"
```

## Python Packages

```bash
/usr/bin/python3 -c "
packages = ['requests', 'urllib3', 'cryptography', 'paramiko', 'selenium', 'lxml', 'pandas', 'numpy', 'flask', 'django', 'fastapi', 'sqlalchemy', 'redis']
for pkg in packages:
    try:
        mod = __import__(pkg.replace('-', '_').split('[')[0])
        print(f'{pkg}: {getattr(mod, \"__version__\", \"unknown\")}')
    except ImportError:
        print(f'{pkg}: not installed')
"
```

## Common Issues Found

| Issue | Severity | Fix |
|-------|----------|-----|
| PASS_MAX_DAYS=99999 | High | Set to 90 in /etc/login.defs |
| kernel.dmesg_restrict=0 | Medium | Set to 1 via sysctl |
| kernel.kptr_restrict=0 | Medium | Set to 1 via sysctl |
| send_redirects=1 | Medium | Set to 0 via sysctl |
| No Fail2ban | High | apt install fail2ban |
| No auditd | Medium | apt install auditd |
| File ulimit=1024 | Medium | Set 65535 in limits.conf |
| tcp_fin_timeout=60 | Low | Set to 30 for high-concurrency |
| tcp_max_syn_backlog=512 | Low | Set to 4096 |

## System Upgrade (Kali Rolling)

Kali Rolling regularly has 1000+ package upgrades. The foreground `apt` command will **timeout at 600s** for large batches. Always use the background pattern:

```bash
# Step 1: Update package lists (foreground, fast)
apt update 2>&1 | tail -5

# Step 2: Check how many packages need upgrading
apt list --upgradable 2>/dev/null | grep -c upgradable

# Step 3: If >200 packages, use background execution
DEBIAN_FRONTEND=noninteractive apt full-upgrade -y > /tmp/apt-upgrade.log 2>&1 &
# Or via Hermes: terminal(background=true, notify_on_complete=true)

# Step 4: Monitor progress
tail -5 /tmp/apt-upgrade.log
ps aux | grep "apt full-upgrade" | grep -v grep
```

**Timing expectations (aliyun mirror, ~1-2 MB/s):**
- 100-300 packages: 3-5 minutes (foreground OK)
- 300-800 packages: 5-15 minutes (use background)
- 800-1500+ packages: 15-40 minutes (background + notify)

**Post-upgrade verification:**
```bash
# Check no broken packages
dpkg --configure -a 2>&1
apt --fix-broken install -y 2>&1 | tail -5

# Verify critical tools still work
nmap --version >/dev/null 2>&1 && echo "nmap OK" || echo "nmap BROKEN"
nuclei -version >/dev/null 2>&1 && echo "nuclei OK" || echo "nuclei BROKEN"
sqlmap --version >/dev/null 2>&1 && echo "sqlmap OK" || echo "sqlmap BROKEN"
/usr/bin/python3 --version 2>&1
node --version 2>&1
hermes --version 2>&1 | head -1
```

**Pitfalls:**
- Never run `apt full-upgrade` in foreground with 600s timeout for 500+ packages — it WILL get killed mid-install leaving broken packages.
- `DEBIAN_FRONTEND=noninteractive` prevents dpkg from blocking on config file prompts.
- After upgrade, some services may need restart (SSH, Docker, etc.); check `systemctl --failed`.
- Kernel upgrades require reboot to take effect; check with `uname -r` vs `ls /boot/vmlinuz-*`.
