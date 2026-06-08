# 优化记录 (2026-06-02)

## P0: 空except修复
- 所有`except:`必须改为`except Exception:`
- 涉及8个文件20处
- 原因: 空except吞掉KeyboardInterrupt等系统异常

## P1: 性能优化
- HTTP引擎连接池: 200/50 → 80/20 (适配教育网慢环境)
- auto-vuln-scan.py: httpx替代subprocess+curl (每请求省50-100ms)
- DNS过滤: 并行dig + 去掉timeout wrapper

## P2: 架构优化
- 新增 `pentest_utils.py` 公共模块: safe_request, load_json, setup_logging, get_workspace, ProgressBar
- 硬编码路径改为环境变量: PENTEST_WORKSPACE, PENTEST_CACHE, PENTEST_LOGS

## P3: 功能增强
- Reporter: 新增 generate_html() — 专业HTML报告
- Verifier: 新增 safe_mode 参数 — 默认禁用破坏性payload

## P4: 安全加固
- Engine: _sanitize_headers() 日志脱敏
- Verifier: safe_mode=True 默认开启

## 全局验证
- 42个脚本语法: 42/42 PASS
- 空except: 0
- 模块导入: 9/9 OK
- 总代码量: 12750行, 483KB
