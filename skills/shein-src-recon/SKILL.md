---
name: shein-src-recon
description: >-
  SHEIN SRC 渗透测试标准化流程 - 子域名枚举 + 内网探测 + GSRM WAF识别
domain: cybersecurity
subdomain: penetration-testing
tags:
- security
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1595
- T1046
nist_csf:
- ID.RA-01
---
# SHEIN SRC 渗透测试 - 子域名枚举 + 内网探测

## 适用场景
SHEIN SRC (sheincorp.cn/dotfashion.cn/geiwohuo.com/ytengvip.com) 授权渗透测试的侦察阶段。

## 测试范围
- *.sheincorp.cn
- *.dotfashion.cn
- *.geiwohuo.com
- *.ytengvip.com
- *.biz.sheincorp.cn (禁止测试)

## 子域名枚举流程

### 第一步：多工具并行枚举
```bash
# 四个域名并行枚举
subfinder -d sheincorp.cn -silent > /tmp/subs/sheincorp.txt &
subfinder -d dotfashion.cn -silent > /tmp/subs/dotfashion.txt &
subfinder -d geiwohuo.com -silent > /tmp/subs/geiwohuo.txt &
subfinder -d ytengvip.com -silent > /tmp/subs/ytengvip.txt &

# amass被动枚举
amass enum -passive -d sheincorp.cn -o /tmp/subs/amass.txt

# assetfinder
assetfinder --subs-only sheincorp.cn > /tmp/subs/assetfinder.txt

# crt.sh证书透明度
curl -s "https://crt.sh/?q=%.sheincorp.cn&output=json" | jq -r '.[].name_value' | sort -u
```

### 第二步：合并去重
```bash
cat /tmp/subs/*.txt | grep -v '^\*$' | sort -u > /tmp/all_subs.txt
wc -l /tmp/all_subs.txt
```

## 存活检测

⚠️ **注意**: 环境中可能安装的是 `curl -sk https://...` 工具而非 projectdiscovery/httpx，后者不支持 `-l` 列表参数。

```bash
# 正确方式：用Python多线程curl检测存活
python3 << 'EOF'
import subprocess, concurrent.futures, json

with open('/tmp/all_subs.txt') as f:
    subs = [l.strip() for l in f if l.strip()]

def check(url, port):
    proto = "https" if port in [443, 8443] else "http"
    r = subprocess.run(['curl', '-sk', '-L', '--max-time', '4', '--connect-timeout', '3',
                       '-o', '/dev/null', '-w', '%{http_code}|%{content_type}',
                       f"{proto}://{url}:{port}"], capture_output=True, text=True, timeout=8)
    out = r.stdout.strip()
    if out:
        code = out.split('|')[0]
        if code not in ['000', '']:
            return (url, port, code)

with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
    futures = {ex.submit(check, s, p): (s,p) 
               for s in subs for p in [80, 443, 8080, 8443]}
    for f in concurrent.futures.as_completed(futures, timeout=120):
        r = f.result()
        if r: print(f"ALIVE {r[0]}:{r[1]} -> {r[2]}")
EOF
```

## 关键指纹特征

### GSRM WAF识别
- 错误页包含 `class="da-error-wrapper"` + `GSRM Security` 关键字
- 阿里云SLB代理: `via-shein-gateway`, `header-cmdb-*` 系列自定义头
- 内部IP段: `198.18.x.x` 属于SHEIN ROT/CDN出口IP

### 内网IP探测
```bash
# 子域名解析到198.18.x.x即说明是内网系统
nslookup supply-admin.geiwohuo.com  # -> 198.18.20.136

# 内网段可直连(不需VPN)，属于SHEIN办公网段
ping 198.18.20.136  # 可达

# nmap快速端口扫描
nmap -p 22,80,443,3306,5432,6379,27017,9200,11211 --open -oG - 198.18.20.x
```

### 高价值目标识别
| 系统 | 域名 | 内网IP | 业务 |
|------|------|--------|------|
| GitLab | gitlab.sheincorp.cn | 198.18.x.x | 代码仓库 |
| OA | oa.sheincorp.cn | 198.18.x.x | 办公自动化 |
| SCM | scm.sheincorp.cn | 198.18.20.136 | 供应链管理 |
| 物流 | logistics.sheincorp.cn | 198.18.20.110 | 物流门户 |
| 供应商 | sps.sheincorp.cn | 198.18.20.143 | 供应商门户 |
| PLM | plm.dotfashion.cn | - | 产品生命周期 |
| SSO | sso.geiwohuo.com | - | 统一认证 |
| **开放平台** | **open.sheincorp.cn** | **公网可达** | SHEIN开发者平台，Next.js+Java Spring Boot，HTTP/3绕过Akamai |
| **开放平台API网关** | **openapi.sheincorp.cn** | **公网可达** | Java Spring Boot AWS K8s，版本1.1.1.15-RELEASE，/health端点泄露K8s架构 |
| **开放平台API(Alt)** | **openapi.sheincorp.com** | **公网可达** | 同openapi.sheincorp.cn，HTTP/3可绕过Akamai直连源站 |
| **GSP系统** | **br.sheingsp.com** | **公网可达** | 全球卖家平台，HTTP/3绕过EdgeOne，需登录 |
| **API门户** | **openapi-portal.sheincorp.cn** | **公网可达** | HTTP/3绕过Akamai，与openapi相同后端Java系统 |
| **SSMS** | **ssms.biz.sheincorp.cn** | biz子域 | 排班管理系统，端点需认证 |
| **APISIX网关** | **ms-us.sheincorp.com** | 公网可达 | Apache APISIX (OpenResty)，管理API可能有IP限制 |
| **供应商OMS** | **sps-oms.sheincorp.cn** | 证书SAN发现 | 供应商订单管理系统 |
| **FMS系统** | **fms.sheincorp.cn** | 证书SAN发现 | 财务管理相关 |
| **GSP API** | **gsp-api.sheincorp.cn** | 证书SAN发现 | GSP后端API |
| **SSO API** | **sso-api.sheincorp.cn** | 证书SAN发现 | SSO统一认证API |
| **毅腾系统** | **www.ytengvip.com** | 198.18.19.74 | 外部关联公司，与SHEIN主站分开 |

### 已知内网IP段
- 198.18.20.x — ROT VPN网关/出口SLB VIP（scm/logistics/sps/ptc等）
- 198.18.19.x — ytengvip.com相关内网系统（www/mail/cdn等解析至此段），端口指纹与198.18.20.x一致（同为SLB VIP）
- 两个内网段均可直连ping通，属于SHEIN办公网段

### WAF绕过技巧
- **CDN别名绕过**: open.sheincorp.cn 的API被IP限制，但 open.sheincorp.com (Akamai CDN别名) 可访问相同API
- **HTTP/3 (QUIC) 绕过Akamai CDN**: `curl --http3` 可直接建立UDP QUIC连接，绕过Akamai CDN层，部分源站对HTTP/3请求返回真实后端JSON
  ```bash
  # HTTP/3绕过CDN示例（2026-04实测有效）
  curl -sk --http3 --connect-timeout 5 --max-time 10 "https://openapi-portal.sheincorp.cn/路径"
  curl -sk --http3 --connect-timeout 5 --max-time 10 "https://br.sheingsp.com/路径"
  # 已验证可绕过: Akamai CDN, Tencent Cloud EdgeOne
  # 无效对付: GSRM WAF（阿里云应用防火墙）仍完全阻断
  ```
- **证书SAN字段资产发现**: 当DNS枚举被GSRM WAF阻挡时，SSL证书的Subject Alternative Name (SAN) 字段包含大量内部域名，可直接用openssl提取
  ```bash
  # 从已知域名提取证书SAN（无需子域名枚举，直接发现内部域名群）
  openssl s_client -connect open.sheincorp.cn:443 -servername open.sheincorp.cn </dev/null 2>/dev/null | \
    openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
  # 或用curl获取完整证书链SAN
  curl -sk "https://open.sheincorp.cn" | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
  # SHEIN证书中发现的内部域名（部分）：openapi.sheincorp.cn, ms-us.sheincorp.com,
  # sbn-prod01.sheincorp.cn, sso.sheincorp.com, sps-oms.sheincorp.cn, fms.sheincorp.cn,
  # openapi-portal.sheincorp.cn, gsp-api.sheincorp.cn, sso-api.sheincorp.cn
  ```
- **nuclei批量扫描对GSRM WAF完全无效**: nuclei所有HTTP请求被GSRM统一拦截，返回空输出，无法用于SHEIN SRC测试
- **ffuf目录扫描对GSRM WAF完全无效**: common.txt词表扫描全部超时，被WAF统一拦截，无输出
- 核心系统(SCM/Logistics/GitLab等)使用GSRM WAF，无已知绕过方法

## 常见问题

### 1. 所有核心系统返回403/302
- **原因**: GSRM WAF保护，外部IP被拦截
- **验证**: 查看错误页是否包含"GSRM Security" → 是则说明被WAF拦
- **绕过尝试**: X-Forwarded-For/X-Real-IP伪造 → 均无效

### 2. 误将CDN错误页当作200
- **判断方法**: 检查返回内容是否包含 `<title>Error Page</title>`
- **正确方式**: `curl -sI "https://target/" | grep title` 获取真实title
- **严格验证**: `curl -sk "https://target/" | grep -oP '(?<=<title>)[^<]+'` 取title，非"Error Page"才是真实业务

### 3. httpx工具不可用
- 环境中`httpx`是Python CLI版，非projectdiscovery版
- 使用`curl`替代，配合`--max-time`和`--connect-timeout`

### 4. 所有系统返回200但内容是错误页
- **原因**: GSRM WAF在某些配置下返回200而非403，错误页内容为HTML
- **筛选方法**: Python多线程检测时同时获取title或body关键字，排除Error Page/WAF页
- **示例**: `curl -sk "https://target/" | grep -q "SHEIN\|shein\|GSP\|seller\|portal"` 只有包含业务关键字才是真200

## 漏洞验证规则 (重要!)

⚠️ **必须验证后才能写报告，未经验证的发现必须删除**。本轮SHEIN测试写了3份报告，全部误报，教训深刻。

### 验证流程
1. **严格判断是否WAF页** — 返回200不代表是业务系统，检查body内容是否包含真实业务关键字(SHEIN/shein/GSP/seller/portal等)
2. **验证IP伪造无效** — X-Forwarded-For/X-Real-IP/Host头混淆均无法绕过GSRM WAF
3. **区分故意开放和未授权** — `/api/health`返回status=UP是故意开放，不算漏洞
4. **可利用性验证** — 必须能实际利用才算漏洞，仅"返回信息"不够

### 常见误报
| 误报类型 | 真实情况 |
|---------|---------|
| supply-admin IP限制绕过 | WAF统一403，IP伪造无效 |
| GSRM指纹信息泄露 | 标准WAF错误页，非敏感信息 |
| Actuator未授权访问 | /api/health故意开放，返回status=UP无敏感数据 |
| campus/sheincorp.cn 200 | 返回200但内容是WAF Error Page |
| jira.dotfashion.cn 200 | AkamaiGHost返回200但内容是WAF |

### 严格验证命令
```bash
# 1. 获取真实title，必须非Error Page才算业务系统
curl -sk "https://target/" | grep -oP '(?<=<title>)[^<]+'
# 2. 验证body包含业务关键字
curl -sk "https://target/" | grep -qi "shein\|SHEIN\|GSP\|seller\|portal"
# 3. 验证Actuator端点内容是否有敏感数据
curl -sk "https://target/api/health"
# 4. IP伪造测试 - 必须两个都测
curl -sk -H "X-Forwarded-For: 10.0.0.1" "https://target/" | grep -oP '(?<=<title>)[^<]+'
```

## 已确认漏洞 (2026-04实测)

| 编号 | 系统 | 漏洞描述 | 等级 | 路径 |
|------|------|---------|------|------|
| V001 | openapi.sheincorp.com | /health端点暴露K8s容器ID、版本号(1.1.1.15-RELEASE)、AWS区域(us-west-7)、启动时间等架构信息，可稳定复现 | 中危 | /tmp/shein_reports/SHEIN-SRC-V001-20260429.md |

### V001 验证命令 + 证据截图
```bash
# HTTP/1.1直连（可能被Akamai缓存）
curl -sk "https://openapi.sheincorp.com/health"
# HTTP/3绕过Akamai CDN直连源站（推荐）
curl -sk --http3 --connect-timeout 5 "https://openapi.sheincorp.com/health"

# 响应:
# {"name":"open_platform-aws","startTime":"2026-04-22 20:28:26","id":"openapi-java-uswest7-prod-aws-7f99d54d4b-rtdzw","version":"1.1.1.15-RELEASE","status":"UP","group":"open_platform-aws"}

# 证据截图（可用chromium headless生成）
xvfb-run --auto-servernum chromium --headless=new --disable-gpu --no-sandbox \
  --screenshot=/tmp/shein_reports/evidence/v001_final.png \
  --window-size=1280,900 \
  "file:///tmp/shein_reports/evidence/v001_report.html"

# 证据文件：
# /tmp/shein_reports/evidence/v001_final.png        (86KB 漏洞截图)
# /tmp/shein_reports/evidence/v001_screenshot.png    (浏览器截图)
# /tmp/shein_reports/evidence/v001_health_response.json (原始JSON)
# /tmp/shein_reports/evidence/v001_report.html       (HTML报告)
# /tmp/shein_reports/SHEIN-SRC-V001-20260429.md      (正式报告)
```

## 报告模板
```
路径: /tmp/vuln_reports/VXXX-漏洞名.md
头信息: VXXX-SHEIN-SRC-YYYYMMDD-NNN | 项目 | 域名 | IP | 端口 | CVE | 等级 | 时间 | 状态
结构: 概述 → 目标信息 → 指纹特征 → 技术分析 → 验证过程 → 影响 → 修复建议 → 状态说明
```
