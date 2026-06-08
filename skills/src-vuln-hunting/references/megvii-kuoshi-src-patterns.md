# Megvii/Kuoshi SRC Testing Patterns

**Forwarding:** 本文件是跨skill引用占位符。

完整内容请见 `education-src-blueprint` skill 的 `references/megvii-kuoshi-src-patterns.md`（如存在）或从session历史检索。

## 核心模式（简要）

- **Prometheus metrics泄露**: `/metrics` 端点暴露内部指标
- **Vue.js config.js**: `/js/config.js` 或 `__NEXT_DATA__` 提取API endpoint
- **CORS*+credentials**: 测试 `Origin: https://evil.com` + `Access-Control-Allow-Credentials: true`
- **SPA fallback误报**: 404返回200+HTML时检查`<title>`和实际内容长度
- **api-escort认证**: cappkey+ctimestamp自定义签名机制

## 关联记忆

旷视SRC(06-02): 9报告+5新. OpenRASP WAF. /tmp/vuln_reports/megvii/.
