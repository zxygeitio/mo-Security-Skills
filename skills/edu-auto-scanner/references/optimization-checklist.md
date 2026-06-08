# 优化检查清单 (2026-06-02)

## P0: 正确性
- [x] 零`except:`裸异常 → 全部用`except Exception:` (8文件20处)
- [x] httpx POST用`json=`不是`json_data=`
- [x] SSL错误不重试(直接raise，服务器端问题)
- [x] 公开API有docstring

## P1: 性能
- [x] 连接池调优: 教育网 max_connections=80, max_keepalive=20
- [x] httpx替代subprocess+curl (auto-vuln-scan.py)
- [x] DNS过滤并行化 (ThreadPoolExecutor)

## P2: 架构
- [x] 公共模块 pentest_utils.py (safe_request/load_json/save_json/setup_logging)
- [x] 去硬编码路径 → os.environ.get() 或 os.path.dirname(__file__)
- [x] SSL错误检测 → 不重试直接抛出

## P3: 功能
- [x] Reporter: generate_html() 专业HTML报告
- [x] Verifier: safe_mode=True 默认禁用破坏性payload
- [x] PortScanner: socket并发端口扫描
- [x] DNSLOG: blind漏洞回调确认
- [x] CVE Sync: NVD API同步+本地SQLite
- [x] Param Discover: JS/HTML/Swagger/GraphQL参数提取
- [x] Automation: 进度持久化+错误恢复+批量扫描

## P4: 安全
- [x] 日志脱敏: Authorization/Cookie头脱敏
- [x] safe_mode默认开启
- [x] SSL验证可配置(默认关闭用于pentest场景)

## 代码质量指标
- 47个脚本, 15679行, 568KB
- 语法检查: 47/47 PASS
- 模块导入: 14/14 OK (零Fallback)
- 功能覆盖: 37/38 (97%)
- 综合能力: 85/100
