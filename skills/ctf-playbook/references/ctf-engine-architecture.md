# CTF 自动化引擎架构

## 设计原则
用户要求: "简洁多注重功能强化" + "能够完成自动化一体"
- 不要花里胡哨的UI，功能为王
- 输入目标 → 自动完成一切 → 输出flag
- 工具串联，结果解析，智能决策

## 引擎架构 (engine.py)

```
Engine(target)
  ├── Phase 1: Recon (网络侦察)
  │   ├── masscan 全端口扫描
  │   ├── nmap 服务版本识别
  │   └── HTTP服务发现 (并行探测)
  │
  ├── Phase 2: SvcExploit (服务利用)
  │   ├── Redis未授权 → KEYS* → GET flag
  │   ├── MySQL弱口令 → 查flag表
  │   ├── FTP匿名 → 下载flag
  │   ├── SSH弱口令 → hydra爆破
  │   ├── Memcached未授权
  │   └── MongoDB未授权
  │
  ├── Phase 3: Web攻击 (每个HTTP服务)
  │   ├── Discovery.discover() — 并行端点发现
  │   ├── Discovery.categorize() — 按漏洞类型分类
  │   ├── Exploit.sqli() — GET+POST 双测
  │   ├── Exploit.cmdi() — 6种分隔符
  │   ├── Exploit.lfi() — 7种payload
  │   ├── Exploit.ssti() — 6种模板引擎
  │   ├── Exploit.xss() — 5种payload
  │   ├── Exploit.idor() — ID遍历
  │   ├── Exploit.cors() — Origin反射
  │   ├── Exploit.upload() — multipart测试
  │   └── Exploit.auth_bypass() — 未授权访问
  │
  └── Phase 4: FlagHunter (Flag提取)
      ├── 本地文件搜索
      ├── 环境变量
      ├── 内存搜索
      ├── bash历史
      └── 战利品递归提取
```

## 关键设计决策

### 1. 端点发现优先
不要直接对根URL测试漏洞，先发现所有端点:
```python
# 错误: 直接测 http://target/?id='
# 正确: 先发现 /search /login /api 等端点，再对每个端点测试
endpoints = Discovery.discover(url, loot)  # 并行20线程
cats = Discovery.categorize(endpoints)     # 按漏洞类型分组
```

### 2. GET+POST 双测
很多CTF靶场用POST提交参数，只测GET会漏掉:
```python
# GET测试
body, code = http_get(f"{url}{path}?{param}={payload}")
# POST测试
body2, code2 = http_post(f"{url}{path}", {param: payload})
body = body if pattern in body else body2
```

### 3. 自动利用链
发现漏洞后自动深入:
- SQLi → 自动判断列数 → 找显示位 → UNION提取数据 → 查flag表
- CMDi → 自动执行 cat /flag, find, grep, env
- LFI → 自动读 /etc/passwd, /flag, .env, config.php, 源码
- SSTI → 自动尝试6种RCE payload → 提取SECRET_KEY

### 4. Flag多维提取
不要只从一个来源找flag:
```python
# 5个维度
FlagHunter.local(loot)      # 文件+环境变量+内存+历史
FlagHunter.from_loot(loot)  # 从已收集数据中递归提取
```

## 端点发现路径库
```python
PATHS = {
    "sqli":  ["/sqli","/search","/query","/user","/login","/admin","/api","/page","/item","/news","/product","/detail","/list","/member","/profile"],
    "cmdi":  ["/cmdi","/cmd","/ping","/exec","/diagnostic","/system","/tools","/debug","/test","/run"],
    "lfi":   ["/lfi","/include","/file","/page","/load","/read","/view","/show","/download","/template","/render"],
    "ssti":  ["/ssti","/template","/render","/greeting","/hello","/preview","/view","/page","/index"],
    "xss":   ["/xss","/search","/comment","/feedback","/guestbook","/post","/message","/note","/board"],
    "upload":["/upload","/api/upload","/file/upload","/api/file","/import","/attach","/image"],
    "idor":  ["/api/user/","/api/v1/user/","/api/member/","/api/order/","/api/profile/","/user/"],
    "info":  ["/.git/HEAD","/.env","/robots.txt","/sitemap.xml","/actuator/env","/swagger-ui.html","/graphql","/phpinfo.php","/flag","/debug","/console"],
}
```

## GUI设计偏好
用户明确要求: "界面清晰简洁美观无错位"
- 全部用 ttk.Style + pack 统一管理，不要混用 grid/pack
- 暗色主题但不要花哨
- 左侧标签页 + 右侧大输出区
- 顶部全局目标输入，所有按钮共享
- 一键攻击按钮要大且醒目
- 快捷命令栏 (反弹Shell/PTY/SUID等一键复制)
- Flag输入栏回车保存
