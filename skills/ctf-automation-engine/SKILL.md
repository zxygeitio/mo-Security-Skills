---
name: ctf-automation-engine
description: "CTF自动化攻击引擎开发 — 插件架构/结构化输出/智能爬虫/全漏洞覆盖/靶场验证"
tags: [ctf, automation, engine, plugin, pentest, tool-development]
---

# CTF自动化攻击引擎开发

## 触发条件
用户提到: CTF自动化工具/攻击引擎/漏洞扫描器开发/插件架构/一键攻击/离线渗透工具

## 架构设计

### 插件注册模式
```python
PLUGINS = []
def register(cls):
    PLUGINS.append(cls())
    return cls

class Plugin:
    name = "base"
    vuln_type = "generic"
    severity = Severity.MEDIUM
    def match(self, ctx): return True
    def detect(self, ctx): return []
    def exploit(self, finding, ctx): return []

@register
class SQLiPlugin(Plugin):
    name = "sqli"
    # ...
```

### 结构化Finding
```python
from dataclasses import dataclass, field
from enum import Enum

class Severity(str, Enum):
    INFO="info"; LOW="low"; MEDIUM="medium"; HIGH="high"; CRITICAL="critical"

@dataclass
class Finding:
    type: str; target: str; url: str=""; path: str=""; param: str=""
    severity: Severity=Severity.MEDIUM; confidence: float=0.5
    evidence: str=""; exploit_status: str="detected"
    artifacts: list=field(default_factory=list)
```

### 统一HTTP客户端
```python
import ssl, urllib.request
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

def http_req(method, url, data=None, timeout=8, headers=None):
    """返回 (body, code, headers_dict) — 必须返回headers!"""
    hdrs = {"User-Agent":"Mozilla/5.0"}
    if headers: hdrs.update(headers)
    try:
        body_enc = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
        req = urllib.request.Request(url, data=body_enc, headers=hdrs, method=method)
        resp = urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX)
        return resp.read().decode(errors="ignore"), resp.getcode(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="ignore"), e.code, dict(e.headers) if hasattr(e,'headers') else {}
    except Exception as e:
        return str(e), 0, {}
```

### 智能爬虫
从HTML提取: 链接/表单(字段名+方法)/参数/JS API路由
```python
class Crawler:
    @staticmethod
    def extract_forms(html):
        forms = []
        for fm in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.S):
            params = re.findall(r'name="([^"]*)"', fm.group(1))
            if params: forms.append({"params": params})
        return forms
```

## 关键Bug清单 (开发时必查)

| Bug | 问题 | 修复 |
|-----|------|------|
| masscan端口解析 | `parts[3]`是host不是port | 用`parts[2]` |
| http_get不返回headers | 指纹识别永远失败 | 返回`(body, code, headers)` |
| urllib双重编码 | `%27`变成`%2527` | 用`urllib.parse.quote`一次 |
| shell=True注入 | 目标含特殊字符崩溃 | 用`shell=False`+list参数 |
| base64解码用shell | `echo 'b64' \| base64 -d`注入风险 | 用`Python base64.b64decode` |
| Redis webshell默认执行 | 破坏性操作无门控 | 默认注释,需`--allow-destructive` |
| SQLi只测GET | POST表单漏检 | 同时测试GET和POST |
| 时间盲注单次 | 网络抖动误报 | 双次确认 |
| LFI绝对路径拼接 | `../../../`+`/etc/passwd`→错误 | 绝对路径不拼前缀 |
| IDOR循环break | 只测极小范围 | 移除无条件break |
| GUI颜色字典缺键 | `C["yellow"]` KeyError崩溃 | 色盘定义完整再引用 |
| GUI emoji乱码 | Linux tkinter渲染方块 | 用纯ASCII文本标签 |

## 漏洞检测最佳实践

### SQL注入
- GET+POST双测
- 多DBMS: MySQL SLEEP / MSSQL WAITFOR / PostgreSQL pg_sleep / SQLite randomblob
- 时间盲注双次确认
- UNION列数判断→显示位→DBMS感知提取

### 命令注入
- nonce标记确认: `echo CTF{timestamp}` 检测返回
- 多分隔符: `;` `|` `||` `&&` `` ` ``
- GET+POST双测

### SSTI
- 多引擎: `{{7*7}}` `${7*7}` `#{7*7}` `*{7*7}`
- RCE链: config.__class__ / lipsum.__globals__ / cycler.__init__
- SECRET_KEY提取

### XSS
- 精确payload反射检测(防误报)
- GET+POST双测

### GraphQL
- 内省查询 `{ __schema { types { name } } }`
- 数据提取: flag/users/secrets

## 插件清单 (29个 @register)

### Web漏洞插件
| 插件 | 类型 | 严重度 | 检测方法 |
|------|------|--------|----------|
| SQLiPlugin | sql_injection | CRITICAL | GET/POST错误型+时间盲注(4DBMS)+布尔盲注+UNION自动提取 |
| CMDiPlugin | command_injection | CRITICAL | nonce标记+5种分隔符(;,|,\|,\|,\|,&&,`)+GET/POST |
| LFIPlugin | local_file_inclusion | HIGH | 5种payload(遍历/伪协议/空字节/file://)+自动读敏感文件+PHP源码解码 |
| SSTIPlugin | server_side_template_injection | CRITICAL | 4引擎语法+RCE链(Jinja2)+SECRET_KEY提取 |
| XSSPlugin | cross_site_scripting | MEDIUM | 精确payload反射+3种payload+GET/POST |
| IDORPlugin | insecure_direct_object_reference | HIGH | 数字ID遍历1-5+敏感字段检测+批量dump |
| IDORAdvancedPlugin | idor | HIGH | 自动识别数字端点+对比不同ID+敏感数据检测+批量dump |
| GraphQLPlugin | graphql_introspection | HIGH | 内省查询+flag/users/secrets数据提取 |
| GraphQLAdvancedPlugin | graphql | HIGH | 路径探测+内省+敏感字段定向查询 |
| SSRFPlugin | server_side_request_forgery | HIGH | 4种payload(localhost/file/aws metadata) |
| SSRFBlindPlugin | ssrf_blind | HIGH | Canary探测(Burp Collaborator风格) |
| OpenRedirectPlugin | open_redirect | LOW | Location头检测 |
| JWTPlugin | jwt_vulnerability | HIGH | JWT提取+alg=none绕过检测 |
| DownloadTraversalPlugin | path_traversal | HIGH | 下载参数遍历(/etc/passwd,flag) |
| CORSPlugin | cors_misconfiguration | MEDIUM/HIGH | ACAO+ACAC头检测 |
| UploadPlugin | file_upload | HIGH | multipart上传+shell验证+flag搜索 |
| AuthBypassPlugin | authentication_bypass | HIGH | admin/manage/panel/dashboard未授权访问 |
| InfoLeakPlugin | information_disclosure | MEDIUM | .git/.env/actuator/swagger/backup/flag敏感文件 |
| SensitiveFilePlugin | sensitive_file | LOW | 非通用端点标记 |
| DeserializationPlugin | deserialization | CRITICAL | 6种指纹(php/java/python/node/dotnet/ruby)+Cookie检测 |
| NoSQLiPlugin | nosql_injection | HIGH | $ne/$gt/$regex bypass |
| CSRFPlugin | csrf | MEDIUM | POST表单无CSRF token检测 |
| FrameworkExploitPlugin | framework_exploit | CRITICAL | Flask debug/Spring Actuator/ThinkPHP |
| HostHeaderPlugin | host_header_injection | MEDIUM | Host头注入检测 |
| RaceConditionPlugin | race_condition | HIGH | 10线程并发竞态(redeem/transfer/vote等端点) |
| WAFDetectPlugin | waf | INFO | 12种WAF指纹(Cloudflare/Akamai/Imperva/SafeLine等)+攻击触发 |
| SubdomainEnumPlugin | subdomain | INFO | 60+常见前缀DNS爆破 |
| CredentialRelayPlugin | credential_reuse | HIGH | 已发现凭证跨服务复用检测 |
| XXEPlugin | xxe | CRITICAL | XML外部实体注入(端点+表单盲XXE) |

### 服务利用
| 服务 | 方法 |
|------|------|
| Redis | INFO server + KEYS * + GET/HGETALL/LRANGE/SMEMBERS/flag搜索 |
| MySQL/MariaDB | 3用户×7密码弱口令 |
| FTP | 匿名登录检测 |
| MongoDB | listDatabases未授权 |
| Memcached | stats未授权 + stats cachedump + get key + flag搜索 |
| Elasticsearch | /_cat/indices /_search /_nodes /_cluster/health |
| Docker API | /containers/json /images/json /version /info |
| K8s API | /api/v1/namespaces /api/v1/secrets /apis /version |
| PostgreSQL | 3用户×6密码弱口令 + 表枚举 |
| SSH | hydra暴力破解 |

### Flag提取器
搜索范围: / /home /var /tmp /opt /root /srv /etc + 环境变量 + 数据库文件(.rdb/.sql/.sqlite)
正则: `flag|FLAG|ctf|CTF|key|KEY|secret|token` + `{3-80字符}`

## 命令行设计
```python
parser = argparse.ArgumentParser()
parser.add_argument("target")
parser.add_argument("--web-only", action="store_true")
parser.add_argument("--no-brute", action="store_true")
parser.add_argument("--no-local-flags", action="store_true")
parser.add_argument("--allow-destructive", action="store_true")
parser.add_argument("--timeout", type=int, default=8)
```

## 靶场验证方法
搭建vulnlab.py(14种漏洞) → 跑引擎 → 检查检出率和flag提取

## 相关Skill
- `ctf-playbook` — CTF解题知识库
- `pentest-tool-mastery` — 渗透工具精通
- `exploit-chain` — 端到端攻击链
- `ctf-automation-toolkit` — 完整工具包架构/GUI/bash脚本

## 参考文件
- `references/gpt-hermes-diagnosis-20260603.md` — GPT协作诊断记录
- `references/plugin-expansion-20260603.md` — 插件扩展记录(16→29个,新增服务利用)
