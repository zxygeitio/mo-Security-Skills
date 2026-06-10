# 离线CTF攻防工具包架构

## 设计原则

线下CTF攻防竞赛(隔离网络/内网)工具包设计:

1. **引擎优先**: Python编排引擎 > bash脚本集合. 引擎负责工具串联、输出解析、智能决策
2. **一键自动化**: 输入目标 → 全流程自动 → 输出flag. 不要让用户一个个跑脚本
3. **结果驱动**: 每个工具的输出要被解析,结果喂给下一个工具
4. **自动利用**: 发现漏洞后自动执行利用(sqlmap/RCE/文件读取),不只是报告漏洞

## 架构: Engine模式

```
engine.py (Python主控)
  ├── Recon模块     — masscan→nmap→HTTP发现→指纹
  ├── Scanner模块   — 敏感文件→nuclei→目录爆破
  ├── Exploiter模块 — SQLi/SSTI/LFI/CMDi/XSS/CORS/Upload (发现即利用)
  ├── ServiceExploit — Redis/MySQL/FTP/SSH弱口令+未授权
  └── FlagHunter    — 文件/环境变量/内存/数据库/战利品 5维搜索
```

关键: Exploiter模块不只是检测漏洞,发现后自动利用:
- SQLi → 自动sqlmap → 自动查flag表
- SSTI → 自动RCE → 自动cat /flag
- LFI → 自动读/etc/passwd + /flag + 源码泄露
- CMDi → 自动执行find/grep搜索flag
- Redis → 自动KEYS * → GET flag
- MySQL → 自动查flag表

## GUI设计要点

用户反复强调: 不要花里胡哨,简洁美观,功能为王

```python
# 正确: ttk统一风格,功能按钮为主
s = ttk.Style()
s.theme_use("default")
s.configure("TButton", background=bg3, foreground=fg, padding=5)

# 错误: 渐变色/动画/过多装饰
```

布局:
- 顶部: 全局目标输入 + 大红色"一键攻击"按钮
- 左侧: 标签页(功能分类) + 每个标签内是按钮列表
- 右侧: 大输出区 + Flag保存栏 + 快捷命令栏
- 用PanedWindow分隔,用户可拖动调整比例

避免:
- pack和grid混用导致错位
- 过多颜色(3-4种足够:背景/前景/强调/警告)
- 嵌套太深的Frame

## 文件结构

```
ctf-toolkit/
├── engine.py          # Python自动化引擎(核心)
├── ctf.sh             # CLI入口(路由到各脚本/引擎)
├── gui/ctf_gui.py     # GUI(调用engine.py)
├── web/               # Web攻击脚本(供CLI单独调用)
├── crypto/            # 密码学工具
├── pwn/               # PWN工具
├── reverse/           # 逆向工具
├── misc/              # Misc工具
├── recon/             # 侦察脚本
├── defense/           # 防御脚本
├── scripts/           # 自动化脚本
├── wordlists/         # 离线字典
├── payloads/          # Payload模板
└── loot/              # 战利品输出
```

## 工具依赖

必备: nmap, masscan, curl, python3
推荐: sqlmap, hydra, gobuster, ffuf, nuclei, nikto, hashcat, john, steghide, binwalk, exiftool, checksec, ROPgadget, radare2, gdb, tshark, whatweb

## 注意事项

- python3路径: 优先用/usr/bin/python3,避免/usr/local/bin/python3可能卡住的问题
- 所有脚本用bash -n检查语法
- GUI用ast.parse检查Python语法
- 字典文件内置于wordlists/,不依赖外部rockyou.txt(但有的话会用)
