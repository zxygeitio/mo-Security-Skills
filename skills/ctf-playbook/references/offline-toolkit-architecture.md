# CTF 离线自动化工具包架构

## 工具包位置
`/root/ctf-toolkit/` — 完整离线CTF攻防工具包

## 架构: 引擎模式 (非脚本集合)

核心区别: 不是把脚本堆在一起，而是用Python引擎智能编排所有工具。

```
engine.py (Python引擎, 884行)
  ├── Recon       网络侦察 (masscan→nmap→HTTP发现→指纹)
  ├── Discovery   端点发现 (并行20线程, 30+路径)
  ├── Exploit     漏洞检测+自动利用 (10种漏洞类型)
  ├── SvcExploit  服务利用 (Redis/MySQL/FTP/SSH/Memcached/MongoDB)
  └── FlagHunter  Flag提取 (5维: 文件/环境变量/内存/数据库/战利品)
```

## 关键设计模式

### 1. 端点驱动测试
先发现所有可访问端点，再按漏洞类型分类，最后针对性测试。
```python
# 发现端点
endpoints = Discovery.discover(url, loot)  # 并行探测30+路径
cats = Discovery.categorize(endpoints)      # 按sqli/cmdi/lfi/ssti/xss分类

# 针对性测试
Exploit.sqli(url, cats.get("sqli",[]), loot)
Exploit.cmdi(url, cats.get("cmdi",[]), loot)
```

### 2. 检测→利用→提取 三步链
发现漏洞后自动利用，利用后自动提取flag。
```python
# SQLi → UNION注入 → 查flag表
# CMDi → 执行cat /flag → 提取flag{}
# LFI → 读/etc/passwd + /flag → 提取flag{}
# SSTI → RCE → 执行命令 → 提取flag{}
```

### 3. Flag提取器 (5维搜索)
```python
class FlagHunter:
    @staticmethod
    def local(loot):
        # 1. 文件搜索: find / -name '*flag*'
        # 2. 环境变量: env | grep flag
        # 3. 内存搜索: strings /proc/*/mem
        # 4. bash历史: ~/.bash_history
        # 5. 战利品递归: 从已收集数据中提取
```

### 4. HTTP请求不走shell
直接用Python urllib，避免shell转义问题。
```python
def http_get(url, timeout=8):
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.read().decode(errors="ignore"), resp.getcode()
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="ignore"), e.code
```

## 命令行使用
```bash
ctf engine <目标>         # Python引擎全自动攻击
ctf-gui                   # GUI图形界面 (一键攻击按钮)
ctf web-recon <URL>       # Web侦察 (bash脚本)
ctf exploit <URL>         # Web一键利用 (bash脚本)
ctf flag-hunt /           # Flag搜索
```

## GUI (一键攻击)
`/root/ctf-toolkit/gui/ctf_gui.py` — tkinter GUI
- 7个标签页: Web/密码学/PWN-RE/Misc/侦察/防御/一键攻击
- 顶部大按钮 "⚡ 一键攻击" 调用engine.py
- 实时输出 + 高亮 + Flag记录栏

## Pitfalls

### urllib双重编码
urllib.request.urlopen会自动编码URL中的特殊字符，导致`%27`变成`%2527`。
解决: 直接传原始URL，不要预先编码。`http_get(f"{url}?{param}={ue(payload)}")`

### SQLite错误模式
标准SQLi正则不匹配SQLite的`unrecognized token`错误。
解决: 扩展正则包含`SQL Error|unrecognized token|near .{1,20}: syntax error`

### 端点路径缺失
test_sqli等方法如果直接用`url?param=`而不是`url{path}?param=`，会漏掉漏洞路径。
解决: 先Discovery.discover()发现端点，再传入paths参数。

### SSH爆破超时
hydra SSH爆破在隔离网络可能超时导致整个引擎卡死。
解决: 给hydra设timeout，或在localhost环境跳过。
