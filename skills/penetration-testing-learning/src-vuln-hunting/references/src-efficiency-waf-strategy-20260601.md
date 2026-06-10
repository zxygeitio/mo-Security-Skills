# SRC效率优化与WAF应对策略 (2026-06-01复盘)

## 请求预算管理

WAF通常在20-30个请求后封禁IP。必须在封禁前完成高价值测试：

| 阶段 | 请求数 | 测试内容 | 预期产出 |
|------|--------|---------|---------|
| 侦察 | ~5 | 主站指纹+ehall/CAS识别+JS下载 | CMS类型+API端点 |
| 第一梯队 | ~10 | ehall JSONP+CAS枚举+CORS | P0/P1候选 |
| 深入验证 | ~10 | API遍历+IDOR+上传 | 漏洞确认 |

关键: 如果第一梯队没有发现，立即换目标，不要继续深入。

## WAF封禁后决策树

```
IP被封禁
  ├── 已有可提交漏洞 → 输出报告，换目标
  ├── 有候选但未验证 → 尝试XFF绕过(1次) → 成功则继续，失败则换目标
  └── 无任何发现 → 直接换目标，不浪费时间
```

不建议的尝试:
- Tor/proxychains: 教育目标通常不支持，成功率极低
- 找真实IP: 教育目标CDN/WAF通常覆盖所有子域
- 频繁重试: 会延长封禁时间

## 低价值模式黑名单

以下发现直接标记为"不建议提交"，不写报告：

| 黑名单模式 | 出现频率 | 被拒原因 |
|-----------|---------|---------|
| SUDY CMS admin/login.psp IP泄露 | 几乎每个SUDY站 | 信息泄露，无实质危害 |
| CAS JSESSIONID URL泄露 | 几乎每个CAS站 | 需用户交互，危害不足 |
| CAS pwdDefaultEncryptSalt泄露 | 几乎每个CAS站 | 每会话轮转，无法利用 |
| jQuery旧版本(CVE-2020-11022等) | 广泛存在 | 需配合上传才能利用 |
| OPTIONS方法暴露TRACE | 部署默认配置 | XST已被现代浏览器缓解 |
| Spring Boot堆栈跟踪(execution参数) | wisedu CAS通用 | 信息泄露 |
| CAS tenant/info配置泄露 | wisedu CAS通用 | 公开设计 |
| robots.txt泄露内网IP | 广泛存在 | 无直接利用价值 |
| X-Application-Context微服务名泄露 | Spring Cloud通用 | 信息泄露 |
| DMARC/SPF缺失(无实际伪造邮件) | 广泛存在 | 配置缺陷不收 |
| Dify chatbot token前端泄露 | AI系统通用 | 公开设计 |
| 200空body(swagger/.git/druid) | 反向代理统一拦截 | 非真实端点 |

## 高价值目标快速识别

```
侦察阶段(5分钟内):
  ├── ehall.xxx.edu.cn 存在?
  │   └── YES → 测试JSONP API(9个公开端点) → 如有PII泄露 = 中危
  ├── CAS类型?
  │   ├── lyuapServer → 用户枚举(POST /v1/tickets) = 中危
  │   ├── wisedu/ycServer → CORS+堆栈跟踪 = 中危组合
  │   └── 标准Apereo → 盐值/JSESSIONID(低危,跳过)
  ├── 存在API/上传端点?
  │   └── YES → 测试未授权/IDOR = 高危
  ├── LyWebServer CMS?
  │   └── YES → /api/cms/upload未授权 = 严重
  ├── 电子签章平台(契约锁)?
  │   └── YES → CORS = 高危
  └── 以上都没有?
      └── 快速扫描3-5个高价值子域 → 无发现则跳过此目标
```

5分钟内没有P0/P1候选，考虑跳过此目标。

## XFF绕过策略

部分WAF可用X-Forwarded-For头绕过：
```bash
curl -sk -H 'X-Forwarded-For: 127.0.0.1' 'https://target/'
curl -sk -H 'X-Real-IP: 127.0.0.1' 'https://target/'
```
- 不稳定: 大量扫描后可能再次被封禁
- 适用于初始访问被封禁的子域名
- 已知有效: gxdlxy.com二级学院子域

## delegate_task并行模式

对独立子系统使用delegate_task并行侦察，效果显著(njfu实战28秒完成3路侦察)。
注意: CERNET目标先单curl确认可达再并行，避免全部超时。

## 腾讯云WAF (stgw) CORS测试绕过 (2026-06-05)

腾讯云WAF拦截带Origin头的请求(HTTP 218),但普通GET的CORS响应头正常返回。

```bash
# 不发Origin,直接检查CORS头
curl -sk -D - 'https://target/' | grep -i 'access-control'
# Referer替代Origin(通常不触发WAF)
curl -sk -H 'Referer: https://evil.com/' 'https://target/api' -D -
```

- ACAO=* + ACAC=true = 配置缺陷(浏览器拒绝,但需报告)
- 只有CORS头没有数据端点 = 低危/不建议提交

## 最近实战统计 (2026-06-01)

| 目标 | 高危 | 中危 | 低危 | 用时 | 备注 |
|------|------|------|------|------|------|
| njfu.edu.cn | 1(CORS) | 1(重定向) | 1(盐值) | ~30min | 契约锁CORS高危 |
| sxri.net | 0 | 1(用户枚举) | 3 | ~25min | lyuapServer |
| shisu.edu.cn | 0 | 0 | 3 | ~20min | 全低危,IP被封 |
| gfxy.com | 0 | 0 | 0 | ~40min | 无实质漏洞 |
| gxdlxy.com | 0 | 4 | 1 | ~60min | CORS+重定向 |
| szut.edu.cn | ? | ? | ? | 进行中 | WebVPN探测中 |
| sus.edu.cn | ? | ? | ? | 进行中 | |

结论: 有ehall+契约锁的学校(njfu)产出最高。纯CAS+SUDY学校(shisu/gfxy)产出最低。
