# SHEIN SRC渗透测试记录 (2026-04实测)

## 目标范围
- *.sheincorp.cn (核心)
- *.dotfashion.cn
- *.geiwohuo.com
- *.ytengvip.com
- *.biz.sheincorp.cn (禁止测试)

## 高价值目标清单
| 系统 | 域名 | 内网IP | 业务 |
|------|------|--------|------|
| 开放平台 | open.sheincorp.cn | 公网可达 | Next.js+Java Spring Boot,HTTP/3可绕过Akamai |
| API网关 | openapi.sheincorp.cn | 公网可达 | Java Spring Boot AWS K8s,版本1.1.1.15-RELEASE |
| API网关(Alt) | openapi.sheincorp.com | 公网可达 | HTTP/3可绕过Akamai直连源站 |
| GSP系统 | br.sheingsp.com | 公网可达 | 全球卖家平台,HTTP/3绕过EdgeOne |
| API门户 | openapi-portal.sheincorp.cn | 公网可达 | HTTP/3绕过Akamai,与openapi同后端 |
| APISIX网关 | ms-us.sheincorp.com | 公网可达 | Apache APISIX(OpenResty) |
| GitLab | gitlab.sheincorp.cn | 198.18.x.x | 代码仓库 |
| OA | oa.sheincorp.cn | 198.18.x.x | 办公自动化 |
| SCM | scm.sheincorp.cn | 198.18.20.136 | 供应链管理 |
| 物流 | logistics.sheincorp.cn | 198.18.20.110 | 物流门户 |
| 供应商 | sps.sheincorp.cn | 198.18.20.143 | 供应商门户 |
| PLM | plm.dotfashion.cn | - | 产品生命周期 |
| SSO | sso.geiwohuo.com | - | 统一认证 |

## GSRM WAF识别
- 错误页包含 `class="da-error-wrapper"` + `GSRM Security` 关键字
- 阿里云SLB代理: `via-shein-gateway`, `header-cmdb-*` 系列自定义头
- 内部IP段: `198.18.x.x` 属于SHEIN ROT/CDN出口IP

## 已知内网IP段
- 198.18.20.x — ROT VPN网关/出口SLB VIP (scm/logistics/sps/ptc等)
- 198.18.19.x — ytengvip.com相关内网系统

## HTTP/3绕过Akamai CDN (实测有效)
```bash
curl -sk --http3 --connect-timeout 5 --max-time 10 "https://openapi-portal.sheincorp.cn/路径"
curl -sk --http3 --connect-timeout 5 --max-time 10 "https://br.sheingsp.com/路径"
# 已验证可绕过: Akamai CDN, Tencent Cloud EdgeOne
# 无效对付: GSRM WAF(阿里云应用防火墙)仍完全阻断
```

## 证书SAN字段资产发现
```bash
openssl s_client -connect open.sheincorp.cn:443 -servername open.sheincorp.cn </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
# SHEIN证书中发现的内部域名: openapi.sheincorp.cn, ms-us.sheincorp.com,
# sbn-prod01.sheincorp.cn, sso.sheincorp.com, sps-oms.sheincorp.cn, fms.sheincorp.cn,
# openapi-portal.sheincorp.cn, gsp-api.sheincorp.cn, sso-api.sheincorp.cn
```

## 工具限制
- nuclei/ffuf对GSRM WAF完全无效(全部被拦截,无输出)
- 环境中`curl`是Python CLI版,非projectdiscovery版
- 使用`curl`替代httpx,配合`--max-time`和`--connect-timeout`

## 严格验证命令(误报教训深刻)
```bash
# 1. 获取真实title,必须非Error Page才算业务系统
curl -sk "https://target/" | grep -oP '(?<=<title>)[^<]+'
# 2. 验证body包含业务关键字
curl -sk "https://target/" | grep -qi "shein\|SHEIN\|GSP\|seller\|portal"
# 3. IP伪造测试 - X-Forwarded-For/X-Real-IP均无效
curl -sk -H "X-Forwarded-For: 10.0.0.1" "https://target/" | grep -oP '(?<=<title>)[^<]+'
```

## 误报清单(必须验证后才能写报告)
| 误报类型 | 真实情况 |
|---------|---------|
| supply-admin IP限制绕过 | WAF统一403,IP伪造无效 |
| GSRM指纹信息泄露 | 标准WAF错误页,非敏感信息 |
| Actuator未授权访问 | /api/health故意开放,返回status=UP无敏感数据 |
| campus/sheincorp.cn 200 | 返回200但内容是WAF Error Page |
| jira.dotfashion.cn 200 | AkamaiGHost返回200但内容是WAF |

## 已确认漏洞
| 编号 | 系统 | 漏洞描述 | 等级 |
|------|------|---------|------|
| V001 | openapi.sheincorp.com | /health端点暴露K8s容器ID、版本号(1.1.1.15-RELEASE)、AWS区域(us-west-7)、启动时间等架构信息 | 中危 |

### V001验证命令
```bash
curl -sk --http3 --connect-timeout 5 "https://openapi.sheincorp.com/health"
# 响应:
# {"name":"open_platform-aws","startTime":"2026-04-22 20:28:26","id":"openapi-java-uswest7-prod-aws-7f99d54d4b-rtdzw","version":"1.1.1.15-RELEASE","status":"UP","group":"open_platform-aws"}
```
