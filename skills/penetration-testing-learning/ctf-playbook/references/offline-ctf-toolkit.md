# 离线CTF攻防工具包

> 完整工具包位于 `/root/ctf-toolkit/` (41文件, 9模块, 26个系统工具依赖)
> 快捷命令: `ctf <模块> [参数...]` (已注册到 /usr/local/bin/ctf)

## 架构

```
ctf-toolkit/
├── ctf.sh              # 主入口 (路由38个命令)
├── setup.sh            # 初始化 (权限+依赖检查+快捷方式)
├── web/                # 10个脚本: recon/sqli/upload/ssti/lfi/xss/jwt/cmdi/shell/exploit
├── crypto/             # 4个脚本: crypto_tool.py/rsa_attack.py/hash_crack.sh/encode_detect.py
├── pwn/                # 4个脚本: checksec.sh/exploit_template.py/pattern.py/rop_search.sh
├── reverse/            # 3个脚本: static.sh/dynamic.sh/pyc_decompile.py
├── misc/               # 5个脚本: stego.sh/forensics.sh/pcap.sh/file_analyze.sh/zip_crack.sh
├── recon/              # 4个脚本: network_scan.sh/service_enum.sh/brute.sh/fuzz.sh
├── defense/            # 4个脚本: monitor.sh/patch.sh/flag_protect.sh/detect.sh
├── scripts/            # 3个脚本: auto_attack.sh/flag_hunter.sh/batch_exploit.sh
├── payloads/           # Payload模板目录 (webshell/sqli/xss/ssti/lfi/reverse_shell)
├── wordlists/          # 离线字典 (usernames.txt/passwords.txt + 内置common_dirs.txt)
├── loot/               # 战利品输出 (按模块+时间戳分目录)
└── notes/              # 比赛笔记
```

## 命令速查

### 攻击
| 命令 | 功能 | 关键技术 |
|------|------|----------|
| `ctf web-recon <URL>` | Web侦察 | 10项: 响应头/注释/JS/敏感文件/参数FUZZ/子目录/HTTP方法/CORS/WAF |
| `ctf sqli <URL> [p]` | SQL注入 | 错误/时间/布尔盲注/WAF绕过/sqlmap自动化 |
| `ctf upload <URL> [p]` | 上传绕过 | 双扩展/Content-Type/文件头/.htaccess/.user.ini/竞争条件 |
| `ctf ssti <URL> [p]` | SSTI | 5引擎检测/7种RCE/SECRET_KEY提取/黑名单绕过 |
| `ctf lfi <URL> <p>` | 文件包含 | LFI/RFI/PHP伪协议/日志投毒/str_replace绕过 |
| `ctf xss <URL> [p]` | XSS | 13种payload/DOM/HTTP头注入/CSP分析 |
| `ctf jwt <TOKEN>` | JWT | 解码/alg:none/密钥爆破/hashcat/kid注入 |
| `ctf cmdi <URL> <p>` | 命令注入 | 17种payload/9种WAF绕过/反弹shell模板 |
| `ctf shell [type]` | 生成shell | php/jsp/python/bash + 全语言反弹shell |
| `ctf exploit <URL>` | 一键利用 | SQLi/XSS/LFI/CMDi/SSTI/CORS 全自动 |

### 密码学
| 命令 | 功能 |
|------|------|
| `ctf crypto auto <text>` | 自动识别+多层递归解码 (base64/32/hex/url/rot13/caesar/xor/morse/bacon/rail/atbash) |
| `ctf rsa small_e <e> <c>` | RSA小指数开方; `fermat`/`pollard`/`common_mod`/`hastad` |
| `ctf hash <HASH>` | 哈希识别+john/hashcat+常见密码库 |
| `ctf encode <TEXT>` | 多重编码3层递归检测 (支持binary/decimal/octal) |

### PWN / Reverse
| 命令 | 功能 |
|------|------|
| `ctf pwn-check <BIN>` | 保护检查+利用建议 (NX/Canary/PIE/RELRO) |
| `ctf pwn-exploit <BIN>` | 自动生成exploit模板 (分析函数/字符串/GOT) |
| `ctf pwn-pattern <LEN>` | 模式字符串生成+偏移查找 (无需pwntools) |
| `ctf pwn-rop <BIN>` | ROP gadget搜索 (pop rdi/rsi/rdx + /bin/sh) |
| `ctf rev <BIN>` | 静态分析 (strings/符号/段/objdump/r2) |
| `ctf rev-dynamic <BIN>` | 动态分析 (strace/ltrace/格式化字符串/溢出) |
| `ctf rev-pyc <FILE>` | Python字节码反编译 (marshal/常量池/反汇编) |

### Misc
| 命令 | 功能 |
|------|------|
| `ctf stego <FILE>` | 隐写 (binwalk/exif/zsteg/trailer/XOR暴力/高度篡改) |
| `ctf forensics <FILE>` | 取证 (文件头/签名/binwalk/嵌入检测) |
| `ctf pcap <FILE>` | 流量 (协议/HTTP对象/DNS/FTP/Flag搜索) |
| `ctf file <FILE>` | 文件深度分析 (魔数/binwalk/嵌入文件头搜索) |
| `ctf zip <FILE>` | 压缩包 (伪加密修复/bkcrack/john/hashcat/CRC暴力) |

### 侦察 / 防御 / 自动化
| 命令 | 功能 |
|------|------|
| `ctf scan <TARGET>` | masscan全端口+nmap服务版本+UDP |
| `ctf enum <TARGET>` | HTTP/SSH/FTP/MySQL/Redis/SMB/SNMP枚举 |
| `ctf brute <TARGET> <SVC>` | ssh/ftp/mysql/http-get/http-post/smb弱口令 |
| `ctf fuzz <URL>` | 目录爆破+参数发现+HTTP方法+gobuster/ffuf |
| `ctf monitor [iface]` | 连接/端口/抓包监控 |
| `ctf patch <SERVICE>` | ssh/mysql/redis/apache/nginx/ftp/smb/php加固 |
| `ctf flag-protect` | Flag文件权限加固+inotify监控+快速加固脚本 |
| `ctf detect [iface]` | 入侵检测 (连接/进程/文件/用户/日志) |
| `ctf auto <TARGET>` | 全自动5阶段攻击链 |
| `ctf flag-hunt [PATH]` | Flag搜索 (文件/内容/DB/内存/历史) |
| `ctf batch <FILE>` | 批量多目标利用 |

## 离线比赛策略

### 赛前准备 (前15分钟)
1. 确认网络拓扑和靶机IP范围
2. `ctf scan <网段>` 快速扫描所有靶机
3. 对每台靶机 `ctf auto <IP>` 跑全自动
4. 浏览所有题目, 标记简单题优先

### 攻击优先级
1. **Web题优先** (通常最多): `ctf web-recon` → `ctf exploit` → 专项深入
2. **Misc快速**: `ctf file` → `ctf stego` → `ctf forensics` → `ctf pcap`
3. **Crypto**: `ctf crypto auto` → `ctf encode` → `ctf rsa` → 5分钟没思路跳过
4. **PWN**: `ctf pwn-check` → `ctf pwn-exploit` → 简单栈溢出先做

### 防御策略
1. 开赛立即: `ctf flag-protect` + `ctf patch all`
2. 定期: `ctf detect` 检查入侵痕迹
3. 监控: `ctf monitor` 发现异常流量

### PITFALL: python3路径
- `/usr/local/bin/python3` 可能卡住 (timeout)
- 使用 `/usr/bin/python3` (系统自带)
- 所有脚本已配置为使用 `/usr/bin/python3`
