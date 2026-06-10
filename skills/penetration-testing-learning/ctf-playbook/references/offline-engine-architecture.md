# CTF 离线自动化引擎架构 v6

> 插件架构 | 结构化输出 | 智能爬虫 | 21漏洞插件 | AWD防御

## 架构概览

```
engine.py (1113行)
├── 基础设施: http_req/http_get/http_post, normalize_target, ssl_ctx
├── 智能爬虫: Crawler (链接/表单/参数/JS路由提取)
├── 插件系统: Plugin基类 + @register自动注册 + PLUGINS列表
├── 21个漏洞插件 (按严重度分组)
├── 服务利用: Redis/MySQL/FTP/SSH/Memcached/MongoDB
├── Flag提取器: 5维搜索
└── argparse CLI (--web-only/--no-brute/--timeout等)
```

## 插件架构

```python
class Plugin:
    name = "base"
    vuln_type = "generic"
    severity = Severity.MEDIUM
    def match(self, ctx): return True
    def detect(self, ctx): return []   # -> List[Finding]
    def exploit(self, finding, ctx): return []

PLUGINS = []
def register(cls):
    PLUGINS.append(cls())
    return cls

@register
class SQLiPlugin(Plugin):
    name = "sqli"; vuln_type = "sql_injection"; severity = Severity.CRITICAL
    def detect(self, ctx):
        # ctx包含: target, url, loot, endpoints, cats, crawl, args
        ...
```

## 结构化输出

```python
@dataclass
class Finding:
    type: str          # "sqli", "cmdi", etc.
    target: str        # 目标IP
    url: str           # 完整URL
    path: str          # 路径 "/search"
    param: str         # 参数 "q"
    severity: Severity # CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence: float  # 0.0-1.0
    evidence: str      # 证据片段
    exploit_status: str # detected/exploited/failed
    artifacts: list    # 关联文件
```

## 智能爬虫

```python
class Crawler:
    @staticmethod
    def extract_links(html, base_url):   # href/action提取
    @staticmethod
    def extract_forms(html):             # 表单字段+方法
    @staticmethod
    def extract_params(html):            # name属性
    @staticmethod
    def extract_js_routes(html):         # /api/路由
    @staticmethod
    def crawl(url, max_depth=2):         # BFS爬取
```

爬虫发现的参数自动注入到SQLi/XSS/SSTI检测。

## 21个漏洞插件

| 插件 | 严重度 | 检测方法 | 自动利用 |
|------|--------|---------|---------|
| sqli | CRITICAL | GET+POST错误/时间(多DBMS)/布尔 | UNION提取+flag表 |
| cmdi | CRITICAL | nonce标记(防误报) | 6种分隔符+命令执行 |
| lfi | HIGH | 6种payload+绝对路径 | 读文件+PHP源码base64解码 |
| ssti | CRITICAL | 4种模板语法+GET+POST | 3种RCE+SECRET_KEY |
| xss | MEDIUM | 3种payload+GET+POST | 反射检测 |
| idor | HIGH | 对比1-5响应 | 批量枚举1-50 |
| graphql | HIGH | 内省查询 | flag/users/secrets查询 |
| ssrf | HIGH | localhost/file/metadata | 4种payload |
| open_redirect | LOW | Location头检测 | - |
| jwt | HIGH | token正则+alg检测 | alg=none标记 |
| download_traversal | HIGH | 绝对+相对路径 | 读flag |
| cors | MEDIUM | Origin反射+ACAC | - |
| upload | HIGH | multipart上传 | shell URL验证 |
| auth_bypass | HIGH | admin/manage/panel | 页面内容检测 |
| info_leak | MEDIUM | 50+敏感路径 | 凭证正则提取 |
| sensitive_file | MEDIUM | 端点记录 | - |
| deserialization | CRITICAL | PHP/Java/Python/Node magic bytes | - |
| nosqli | HIGH | MongoDB $ne/$gt操作符 | - |
| csrf | MEDIUM | 表单token检测 | - |
| framework_exploit | CRITICAL | Flask/Spring/ThinkPHP/Django | debug console/Actuator |
| host_header | MEDIUM | Host头注入 | - |

## 端点发现策略

```python
PATHS = {
    "sqli":  ["/sqli","/search","/query","/user","/login","/admin","/api",...],
    "cmdi":  ["/cmdi","/cmd","/ping","/exec","/diagnostic",...],
    "lfi":   ["/lfi","/include","/file","/page","/load","/read",...],
    "ssti":  ["/ssti","/template","/render","/greeting",...],
    "xss":   ["/xss","/search","/comment","/feedback",...],
    "upload":["/upload","/api/upload","/file/upload",...],
    "ssrf":  ["/redirect","/url","/fetch","/proxy",...],
    "graphql":["/graphql","/api/graphql","/gql",...],
    "jwt":   ["/api/auth","/api/login","/api/token",...],
    "xxe":   ["/api/import","/api/upload/xml","/soap",...],
    "info":  ["/.git/HEAD","/.env","/actuator/env","/swagger-ui.html",...],
}
```

并行20线程探测 + 爬虫发现的额外路径。

## Flag提取5维搜索

1. 命令执行结果 (CMDi/SSTI RCE)
2. 文件读取内容 (LFI/下载穿越/SSRF)
3. 环境变量 (env | grep flag)
4. 内存搜索 (strings /proc/*/mem)
5. 战利品递归 (loot目录所有txt)

## 命令行

```bash
python3 engine.py <target>                      # 全自动
python3 engine.py http://target --web-only      # 仅Web
python3 engine.py target --no-brute --timeout 3 # 快速
python3 engine.py target --cookie "session=abc" # 带Cookie
python3 engine.py target --header "Auth: Bearer xxx"
```

## GUI (gui/ctf_gui.py)

- ttk.Style统一主题(暗色)
- 7个标签页: 一键攻击/Web/密码学/PWN-RE/Misc/侦察/防御
- 顶部全局目标输入 + 一键攻击大按钮
- 右侧大输出区 + Flag记录栏 + 快捷命令栏
- shell=False防命令注入
- 后台线程执行不阻塞UI

## 靶场实战验证

靶场: CTF Range v2 (14种漏洞类型)
结果: 44个漏洞 / 2个flag / 3秒完成
覆盖: SQLi+CMDi+LFI+SSTI+XSS+IDOR+GraphQL+SSRF+Upload+AuthBypass+InfoLeak+NoSQLi

## PITFALL: urllib双重编码
urllib.request.urlopen会自动编码URL，导致%27变%2527。传原始字符。

## PITFALL: SQLite保留字
`desc`是保留字，用作列名时必须用反引号: SELECT id,`desc` FROM products

## PITFALL: masscan端口解析
-oL格式: `open tcp PORT HOST`，parts[2]是port不是parts[3]。

## PITFALL: http_get必须返回headers
指纹识别需要读Server/Powered-By/Set-Cookie。只返回body+code会漏掉。

## PITFALL: CMDi误报
用nonce标记确认: payload="echo CTF1234"，检查CTF1234是否在响应中。
