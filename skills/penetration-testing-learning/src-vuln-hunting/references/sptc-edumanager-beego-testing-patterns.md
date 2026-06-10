# SPTC EduManager Beego Testing Patterns

**Forwarding:** 完整内容见 `education-src-blueprint` skill 的 `references/sptc-edumanager-beego-testing-patterns.md`。

## 核心模式（简要）

- **Beego框架指纹**: `beego` 字符在响应头/X-Powered-By/静态路径
- **用户枚举**: `/api/user/check?username=xxx` 返回不同状态码
- **凭证URL泄露**: `/api/download?file=xxx` 路径遍历
- **内网探测**: SSRF via `url=` 或 `target=` 参数
- **Coremail**: 邮件系统指纹和已知漏洞模式

## 工具命令

```bash
# Beego指纹
curl -sI https://target/ | grep -i "beego\|x-powered-by"

# 用户枚举
curl -s "https://target/api/user/check?username=admin" | jq .
```
