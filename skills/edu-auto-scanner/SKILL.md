---
name: edu-auto-scanner
description: >-
  教育SRC全自动化扫描工具集 — 批量探测+指纹→漏洞映射+JS安全分析+workspace持久化
domain: cybersecurity
subdomain: penetration-testing
tags:
- src
- edu
- automation
- scanner
- fingerprint
- recon
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1595
- T1190
- T1046
nist_csf:
- DE.CM-01
- ID.RA-01
---
# 教育SRC自动化扫描工具集

## 触发条件
- 用户要求对教育/高校目标进行自动化扫描
- 需要批量子域探测、指纹识别、漏洞扫描
- 需要断点续扫、状态持久化

## 工具清单

所有脚本位于 `/root/.the agent/scripts/`:

| 脚本 | 功能 | 用法 |
|------|------|------|
| `edu-batch-probe.py` | 批量子域探测+指纹 | `python3 edu-batch-probe.py subs.txt --dns -f` |
| `auto-vuln-scan.py` | 指纹→漏洞自动映射 | `python3 auto-vuln-scan.py https://target --enum` |
| `js-secrets-scanner.py` | JS安全分析 | `python3 js-secrets-scanner.py bundle.js` |
| `src-workspace.py` | 扫描状态持久化 | `python3 src-workspace.py init domain` |
| `edu-full-scan.py` | 全自动扫描主控 | `python3 edu-full-scan.py domain` |

## 使用流程

### 一键全自动
```bash
/usr/bin/python3 /root/.the agent/scripts/edu-full-scan.py target.edu.cn
```

### 分步执行(推荐，可人工干预)
```bash
# 1. 初始化workspace
/usr/bin/python3 /root/.the agent/scripts/src-workspace.py init target.edu.cn

# 2. 批量探测
/usr/bin/python3 /root/.the agent/scripts/edu-batch-probe.py subs.txt --dns -f -o alive.txt

# 3. 提取URL
awk '{print $3}' alive.txt | grep '://' > urls.txt

# 4. 自动漏洞扫描
/usr/bin/python3 /root/.the agent/scripts/auto-vuln-scan.py urls.txt --enum --workspace target.edu.cn

# 5. JS安全分析(对SPA目标)
/usr/bin/python3 /root/.the agent/scripts/js-secrets-scanner.py https://target/assets/index.js --url

# 6. 查看结果
/usr/bin/python3 /root/.the agent/scripts/src-workspace.py status target.edu.cn
```

### 断点续扫
```bash
/usr/bin/python3 /root/.the agent/scripts/src-workspace.py resume target.edu.cn
```

## 内置指纹库

auto-vuln-scan.py 内置以下产品指纹:
- 致远OA (Seeyon) — REST API、thirdpartyController、downloadServlet
- CAS统一认证 — 用户枚举、API信息泄露、微信AppID泄露
- Spring Boot Actuator — health/env/heapdump/mappings
- Druid监控 — 登录页、数据源泄露、SQL监控
- Swagger UI — API文档泄露
- 泛微OA (Weaver) — 代码数据、微信配置
- 金智教育CAS — 密钥泄露、验证码检查
- Sangfor WebVPN — 登录用户枚举、密钥登录
- Visual SiteBuilder (VSB) — 配置文件、COLLCK反爬Cookie
- 联奕CAS (Lianyi lyuapServer) — 管理后台暴露、Open Redirect、SMS用户枚举、源码信息泄露
- Liferay Portal — JSONWS API、company/virtual-host、document_library
- CoCall即时通讯 — 公网暴露、租户架构(/interface/{tenant}/)
- Apache Shiro — rememberMe Cookie
- Tomcat/Nginx — 管理页面、状态页

## 性能指标(实测)

| 场景 | 耗时 | 说明 |
|------|------|------|
| 20子域 DNS+HTTP探活+指纹 | 4.5s | DNS并行+HTTP并行 |
| 10目标 自动漏洞扫描 | ~60s | 8-10个端点/目标 |
| 单目标 JS分析(2MB) | ~3s | 25+规则匹配 |
| 用户枚举(16用户名) | ~30s | 串行避免封禁 |

## 踩坑记录 (Pitfalls)

### Python路径
- **必须用 `/usr/bin/python3`**，不要用 `python3`（可能是shim，10秒超时）
- 所有脚本shebang已设为 `#!/usr/bin/python3`
- `edu-full-scan.py` 内部subprocess也用 `/usr/bin/python3`

### DNS过滤: timeout命令会干扰subprocess输出捕获
- ❌ `subprocess.run(['timeout', '2', 'dig', '+short', sub, 'A'], capture_output=True)` → stdout为空
- ✅ `subprocess.run(['dig', '+short', sub, 'A'], capture_output=True, timeout=3)` → 正常
- **原因**: `timeout`命令的管道行为在capture_output模式下不可靠
- **正确做法**: 去掉`timeout` wrapper，只用subprocess的`timeout`参数

### 用户枚举: 单indicator不够
- CAS系统对不同用户名返回的错误信息格式不固定
- ✅ 用`exists_indicators`列表: `['登录失败', '微信扫码', '校园网外', '密码错误', '验证码']`
- ✅ 用`notexists_indicators`列表: `['账号不存在', '用户不存在', '用户名不存在']`
- 两端都不匹配时标记为UNKNOWN，不误判

### 指纹库扩展
- 新增指纹写到 `auto-vuln-scan.py` 的 `FINGERPRINT_DB` 字典
- 格式: `{name, match: {headers: [], body: [], cookies: []}, paths: [(path, method, desc, severity, is_vuln_func)]}`
- `is_vuln_func` 接收body字符串，返回bool
- 待扩展: 用友/金蝶/蓝凌/通达/浪潮/正方/强智/青果/金智/树维

### VSB博达网站群COLLCK反爬绕过
- VSB CMS设置COLLCK cookie进行反爬，curl直接请求会302循环
- ❌ `curl http://target/` → 302无限循环
- ✅ 用浏览器工具访问(cookie自动设置)，或先请求一次获取COLLCK值再带cookie重试
- ✅ 部分静态资源(JS/CSS)不需要COLLCK即可访问: `/system/resource/js/*.js`
- 指纹: `_sitegray`路径、`system/resource/js/vsbscreen.min.js`、`index.vsb.css`

### 联奕CAS (lyuapServer) 指纹和攻击面
- 联奕科技CAS是中国高校常用统一身份认证厂商
- 指纹: 路径`/lyuapServer/login`、页面含`联奕科技`、`LIANYI TECHNOLOGY`
- 管理后台: `/ly_web_casconsole/system/login!login.action` (常公网暴露)
- 管理后台无服务端验证码，验证码为客户端JS校验(`checkcaptcha`字段)
- SMS登录: `/lyuapServer/MsmInfo` 端点，响应码1=成功/2=频率限制/3=用户不存在
- Open Redirect: `service`参数接受任意URL(包括外部域名和javascript: URI)
- LT token泄露主机名: `LT-xxxxx-random-cas01.example.org`
- 源码常泄露: 内网IP、内部域名(cas.leaf.com等)、RSA公钥
- 密码找回: `/safe/findPassByOther.jsp` 暴露组织架构

### Liferay Portal JSONWS API
- 端点: `/api/jsonws/invoke` (POST)、`/api/jsonws/{path}` (GET/POST)
- 认证后可调用: `/company/get-company-by-virtual-host`、`/user/get-user-by-screen-name`
- 未认证返回: `"Authenticated access required"` (确认端点存在)
- 不存在端点返回: `"No JSON web service action associated with path"`
- CVE-2020-7961: JSONWS反序列化RCE(需认证)

### CoCall即时通讯系统
- 校园即时通讯工具，常部署在非标准端口(如65083)
- 指纹: 页面标题`CoCall`、含`download`路径、租户架构
- API路径: `/interface/{tenant}/` (返回"未找到租户信息"表示端点存在)
- 常见端口: 65083(HTTPS)、20083(内网)

### Workspace集成
- `auto-vuln-scan.py --workspace <domain>` 自动保存漏洞到workspace
- workspace目录: `/tmp/vuln_reports/<domain>/`
- `src-workspace.py list` 查看所有工作区

## 关联技能
- 指纹库和漏洞模式: 见 `src-vuln-hunting` skill
- 教育供应商识别: 见 `src-vuln-hunting` 的 `references/edu-vendor-fingerprinting.md`
- CAS漏洞模式: 见 `src-vuln-hunting` 的 `references/cas-vuln-testing-patterns.md`
- CERNET网络策略: 见 `pentest-recon-driven` 的 `references/cuit-edu-testing-patterns.md`

## 漏洞结果需人工复核，自动扫描可能有误报

## 代码质量规范 (2026-06-02优化后)

### 必须遵守
- 零`except:`裸异常 → 全部用`except Exception:`
- httpx POST用`json=`不是`json_data=`
- SSL错误不重试(直接raise)
- 路径用`os.environ.get()`或`os.path.dirname(__file__)`，不硬编码
- 公开API有docstring
- 日志脱敏(Authorization/Cookie头)
- Verifier safe_mode默认True

### 连接池配置
- 教育网慢目标: connect_timeout=8, read_timeout=8, max_connections=80, max_keepalive=20
- 不要用默认200连接池(教育网大量连接会超时)

## 渗透测试框架 v2.0 (2026-06-02)

完整框架位于 `/root/.the agent/scripts/pentest_*.py`:

| 模块 | 功能 |
|------|------|
| pentest_engine.py | HTTP引擎(httpx连接池/拦截器/代理/缓存/UA轮换) |
| pentest_session.py | Session管理(Cookie Jar/JWT/CAS/多账号) |
| pentest_fuzzer.py | Fuzzing(参数/Header/路径 + 7类58个payload) |
| pentest_verifier.py | 漏洞验证(SQLi/XSS/RCE/IDOR/SSRF/LFI + safe_mode) |
| pentest_intel.py | 情报闭环(指纹→CVE→PoC + NVD API + SQLite) |
| pentest_reporter.py | 报告(CVSS + 补天/Markdown/JSON/HTML) |
| pentest_network.py | 网络(代理链/WAF检测+绕过/Payload编码) |
| pentest_framework.py | 主控(串联全部模块 + CLI) |
| pentest_utils.py | 公共工具(HTTP/JSON/日志/路径/进度条) |
| pentest_portscan.py | 端口扫描(socket并发+服务识别+Banner抓取) |
| pentest_dnslog.py | DNSLOG/HTTPLOG回调(blind漏洞确认) |
| pentest_cve_sync.py | CVE数据库(NVD API同步+本地SQLite查询) |
| pentest_param_discover.py | 智能参数发现(JS/HTML/Swagger/GraphQL提取) |
| pentest_automation.py | 自动化增强(进度持久化+错误恢复+批量扫描) |

```bash
# 快速扫描
/usr/bin/python3 /root/.the agent/scripts/pentest_framework.py target.edu.cn --scan-type fast

# 端口扫描
/usr/bin/python3 -c "from pentest_portscan import PortScanner; print(PortScanner().scan_host('target', [22,80,443,8080]))"

# 参数发现
/usr/bin/python3 /root/.the agent/scripts/pentest_param_discover.py https://target

# CVE同步
/usr/bin/python3 /root/.the agent/scripts/pentest_cve_sync.py --sync --product "致远OA"
```

## GPT-5.5协作模式

用户有自定义GPT-5.5 provider。delegate_task的model override不生效，需直接用Python调用API。见 `references/gpt55-collaboration-notes.md`。

并行模式: threading.Thread并行3-5个请求。API不稳定时加重试(retries=3, sleep=5)。

## 优化记录
见 `references/optimization-log-20260602.md` 和 `references/pentest-framework-architecture.md`
