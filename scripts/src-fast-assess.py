#!/usr/bin/python3
"""
SRC Fast Assessment - 一键目标快筛
60秒内判断目标是否值得深挖，输出优先攻击面

用法:
  src-fast-assess.py <domain>
  src-fast-assess.py <domain> --deep        # 深度模式(含nuclei)
  src-fast-assess.py <domain> --out /tmp/x   # 指定输出目录

输出:
  /tmp/src_assess_<domain>/
    subs.txt          - 子域名列表
    alive.txt         - 存活Web服务
    fingerprints.txt  - 指纹识别结果
    attack_surface.md - 攻击面报告(优先级排序)
    first_hits.sh     - 推荐的第一轮测试命令
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

# ─── 高价值指纹模式库 ───────────────────────────────────────────────
FINGERPRINT_MAP = {
    # CMS/Framework → (priority, vuln_types, test_commands)
    "ehall": {
        "priority": "P0",
        "name": "金智教育办事大厅",
        "vulns": ["JSONP未授权API(9端点)", "教职工PII泄露"],
        "tests": [
            'curl -sk "{base}/jsonp/serviceCenterData.json?searchKey=&containLabels=true"',
            'curl -sk "{base}/jsonp/school.json"',
            'curl -sk "{base}/jsonp/userInfo.json"',
        ]
    },
    "lyuapServer": {
        "priority": "P0",
        "name": "联创天空CAS",
        "vulns": ["用户枚举(POST /v1/tickets)", "验证码未生效", "密码错误计数泄露"],
        "tests": [
            'curl -sk -X POST "{base}/lyuapServer/v1/tickets" -d "username=admin&password=test"',
            'curl -sk -X POST "{base}/lyuapServer/v1/tickets" -d "username=nonexistent999&password=test"',
            'curl -sk "{base}/lyuapServer/kaptcha"',
        ]
    },
    "lywebserver": {
        "priority": "P0",
        "name": "LyWebServer CMS",
        "vulns": ["未授权文件上传(CVSS 10.0)", "CORS系统性漏洞", "站点结构泄露"],
        "tests": [
            'curl -sk "{base}/" | grep -oP \'lysid="[^"]*"\'',
            'curl -sk -D- "{base}/api/cms/captchaImage" -H "Origin: https://evil.com" | grep -i access-control',
        ]
    },
    "qiyuesuo": {
        "priority": "P0",
        "name": "契约锁电子签章",
        "vulns": ["CORS任意Origin+Credentials", "/health内网IP泄露", "SDK API端点泄露"],
        "tests": [
            'curl -sk -D- "{base}/" -H "Origin: https://evil.com" | grep -i access-control',
            'curl -sk "{base}/health"',
        ]
    },
    "wisedu_cas": {
        "priority": "P1",
        "name": "金智教育CAS(wisedu)",
        "vulns": ["CORS预检反射", "Spring Boot堆栈跟踪", "CAS Open Redirect", "DEFAULT_SALT"],
        "tests": [
            'curl -sk "{base}/authserver/login" | grep -oP \'pwdDefaultEncryptSalt\\s*=\\s*"[^"]*"\'',
            'curl -sk -D- "{base}/authserver/login" -H "Origin: https://evil.com" | grep -i access-control',
        ]
    },
    "sudy": {
        "priority": "P2",
        "name": "SUDY WebPlus CMS",
        "vulns": ["搜索API未授权", "admin IP泄露(低危)"],
        "tests": [
            'curl -sk "{base}/admin/login.psp" | grep -oP \'ipAddress[^>]*value="[^"]*"\'',
            'curl -sk "{base}/_web/_search/restful/api/search.rst?keyword=test&pageSize=5&pageNo=1"',
        ]
    },
    "vsb": {
        "priority": "P2",
        "name": "博达CMS(Visual SiteBuilder)",
        "vulns": ["搜索API", "getSession.jsp未授权会话"],
        "tests": [
            'curl -sk "{base}/_sitegray/_sitegray.js"',
            'curl -sk "{base}/_web/_search/api/search/new.rst" -d "keyword=test"',
        ]
    },
    "apereo_cas": {
        "priority": "P2",
        "name": "Apereo CAS",
        "vulns": ["JSESSIONID URL泄露(低危)", "盐值泄露(低危)"],
        "tests": [
            'curl -sk "{base}/cas/login" | grep -i jsessionid',
        ]
    },
    "tongda_oa": {
        "priority": "P1",
        "name": "通达OA",
        "vulns": ["已知RCE(需登录)", "文件上传"],
        "tests": [
            'curl -sk "{base}/" | grep -i "通达\\|tongda\\|Office"',
        ]
    },
    "seeyon_oa": {
        "priority": "P1",
        "name": "致远OA",
        "vulns": ["REST Token泄露", "管理后台暴露", "反序列化"],
        "tests": [
            'curl -sk "{base}/seeyon/index.jsp" | head -20',
            'curl -sk "{base}/seeyon/management/index.jsp" -o /dev/null -w "%{http_code}"',
        ]
    },
    "weaver_oa": {
        "priority": "P1",
        "name": "泛微OA",
        "vulns": ["BshServlet RCE", "API未授权", "SQL注入"],
        "tests": [
            'curl -sk "{base}/api/ec/dev/crud/queryBySql"',
            'curl -sk "{base}/weaver/bsh/servlet/BshServlet"',
        ]
    },
    "spring_boot": {
        "priority": "P1",
        "name": "Spring Boot",
        "vulns": ["Actuator泄露(env/heapdump)", "Swagger暴露", "堆栈跟踪"],
        "tests": [
            'curl -sk "{base}/actuator" -o /dev/null -w "%{http_code}"',
            'curl -sk "{base}/swagger-ui.html" -o /dev/null -w "%{http_code}"',
            'curl -sk "{base}/druid/login.html" -o /dev/null -w "%{http_code}"',
        ]
    },
    "thinkphp": {
        "priority": "P1",
        "name": "ThinkPHP",
        "vulns": ["RCE(命令注入)", "日志泄露"],
        "tests": [
            'curl -sk "{base}/?s=/index/\\think\\app/invokefunction&function=phpinfo&args[0]=1"',
        ]
    },
    "sangfor_vpn": {
        "priority": "P2",
        "name": "深信服VPN",
        "vulns": ["信息泄露", "已知CVE"],
        "tests": [
            'curl -sk "{base}/por/login_psw.csp" | grep -i version',
        ]
    },
    "webvpn": {
        "priority": "P2",
        "name": "WebVPN(网瑞达/深信服)",
        "vulns": ["登录页面暴露", "版本信息泄露"],
        "tests": [
            'curl -sk "{base}/login" | head -30',
        ]
    },
    "dify": {
        "priority": "SKIP",
        "name": "Dify AI Chatbot",
        "vulns": ["前端token公开设计(非漏洞)"],
        "tests": []
    },
    "coremail": {
        "priority": "P2",
        "name": "Coremail邮件系统",
        "vulns": ["版本泄露", "用户枚举(需正确API)"],
        "tests": [
            'curl -sk "{base}/coremail/" | head -10',
        ]
    },
}

# ─── 高价值子域模式 ─────────────────────────────────────────────────
HIGH_VALUE_SUBS = [
    "ehall", "portal", "cas", "sso", "auth", "authserver", "ids",
    "oa", "xoa", "vpn", "webvpn", "mail", "email",
    "jw", "jwxt", "jwc", "jwgl", "yjsc", "yjs",
    "pay", "zf", "ykt", "ecard",
    "api", "open", "sdk", "app",
    "zs", "admission", "bkzs",  # 招生
    "lib", "library",  # 图书馆
    "eseal", "contract",  # 签章
    "ai", "chat", "bot",  # AI
]

# ─── WAF指纹 ──────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "访问禁止": "WAF(访问禁止页)",
    "检测到可疑访问": "WAF(事件编号拦截)",
    "acw_tc": "阿里云WAF",
    "yundunwaf": "云盾WAF",
    "HWWAFSESID": "华为云WAF",
    "saaswaf.com": "SaaS WAF",
    "ADG-200": "安恒WAF",
    "NNUTC CLOUD": "NNUTC WAF",
    "宝塔网站防火墙": "宝塔WAF",
    "rump/": "博达CMS反代",
    "GSRM Security": "GSRM WAF",
    "Powered by APISIX": "APISIX网关",
}


def run_cmd(cmd, timeout=15):
    """Run a command and return stdout. Accepts string or list."""
    try:
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)
        r = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        return f"ERROR: {e}"


def subdomain_enum(domain, outdir):
    """Enumerate subdomains using subfinder + crt.sh."""
    subs = set()

    # Always add www variant
    subs.add(f"www.{domain}")
    subs.add(domain)

    # subfinder (increased timeout)
    r = run_cmd(f"subfinder -d {domain} -silent -timeout 25 2>/dev/null", timeout=40)
    for line in r.split('\n'):
        line = line.strip()
        if line and '.' in line:
            subs.add(line)

    # crt.sh
    r = run_cmd(f"curl -sk --max-time 20 'https://crt.sh/?q=%.{domain}&output=json' 2>/dev/null", timeout=25)
    try:
        data = json.loads(r)
        for entry in data:
            for name in entry.get('name_value', '').split('\n'):
                name = name.strip().lower()
                # Strict FQDN validation: must be valid hostname ending with domain
                if name and '*' not in name and name.endswith(f'.{domain}') and re.match(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$', name):
                    subs.add(name)
    except Exception:
        pass

    subs_list = sorted(subs)
    with open(f"{outdir}/subs.txt", 'w') as f:
        f.write('\n'.join(subs_list) + '\n')

    return subs_list


def probe_alive(subs, outdir, max_workers=20):
    """Probe subdomains for alive HTTP services."""
    alive = []

    def probe_one(sub):
        for proto in ['https', 'http']:
            r = run_cmd(f"curl -sk --max-time 8 -o /dev/null -w '%{{http_code}}|%{{size_download}}|%{{redirect_url}}' '{proto}://{sub}/' 2>/dev/null", timeout=12)
            parts = r.split('|')
            if len(parts) >= 2:
                code = parts[0]
                size = parts[1] if len(parts) > 1 else '0'
                redir = parts[2] if len(parts) > 2 else ''
                if code not in ('', '000'):
                    return (sub, proto, code, size, redir)
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe_one, sub): sub for sub in subs}
        for f in as_completed(futures):
            try:
                result = f.result()
                if result:
                    alive.append(result)
            except Exception:
                pass  # Skip failed probes silently

    alive.sort(key=lambda x: (int(x[2]) if x[2].isdigit() else 999, x[0]))

    with open(f"{outdir}/alive.txt", 'w') as f:
        for sub, proto, code, size, redir in alive:
            f.write(f"{proto}://{sub} | {code} | {size}B | {redir}\n")

    return alive


def fingerprint_target(url, headers_raw):
    """Fingerprint a target from headers and body."""
    fingerprints = []
    body_sample = ""

    # Get body sample
    body_sample = run_cmd(f"curl -sk --max-time 8 '{url}' 2>/dev/null | head -c 5000", timeout=12)

    combined = (headers_raw + " " + body_sample).lower()

    # Match against fingerprint map
    for key, fp in FINGERPRINT_MAP.items():
        patterns = {
            "ehall": ["ehall", "金智", "servicecenterdata"],
            "lyuapServer": ["lyuapserver", "ly-iap-cas", "ly-sky.com"],
            "lywebserver": ["lywebserver", "var lysid=", "var lycid="],
            "qiyuesuo": ["qiyuesuo", "契约锁", "qiyuesuo.com"],
            "wisedu_cas": ["wisedu", "authserver/login", "unified identity", "minos"],
            "sudy": ["sudy", "sudy-jquery", "sudyNavi", ".psp"],
            "vsb": ["visual sitebuilder", "_sitegray", "vsbscreen"],
            "apereo_cas": ["/cas/login", "apereo", "jasig"],
            "tongda_oa": ["通达", "tongda", "office anywhere"],
            "seeyon_oa": ["seeyon", "致远", "/seeyon/"],
            "weaver_oa": ["weaver", "泛微", "ecology", "e-cology"],
            "spring_boot": ["spring", "actuator", "whitelabel error"],
            "thinkphp": ["thinkphp", "think\\app"],
            "sangfor_vpn": ["sangfor", "easyconnect", "sangine"],
            "webvpn": ["webvpn", "wengine_vpn", "wrdvpn"],
            "dify": ["difychatbotconfig", "chatbotconfig"],
            "coremail": ["coremail", "mailtech"],
        }

        for pattern in patterns.get(key, []):
            if pattern.lower() in combined:
                fingerprints.append(key)
                break

    # WAF detection
    waf_detected = []
    for sig, name in WAF_SIGNATURES.items():
        if sig.lower() in combined:
            waf_detected.append(name)

    # SPA detection
    spa = False
    random_path = f"/nonexistent_{int(time.time())}"
    body2 = run_cmd(f"curl -sk --max-time 6 '{url}{random_path}' 2>/dev/null | head -c 500", timeout=10)
    if body_sample[:200] == body2[:200] and len(body_sample) > 100:
        spa = True

    return fingerprints, waf_detected, spa


def generate_attack_surface(domain, alive, fingerprints_db, outdir):
    """Generate prioritized attack surface report."""
    lines = []
    first_hits = []
    lines.append(f"# {domain} 快速评估报告")
    lines.append(f"评估时间: {time.strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"存活服务: {len(alive)}")
    lines.append("")

    # Group by priority
    priority_groups = {"P0": [], "P1": [], "P2": [], "P3": [], "SKIP": []}

    for sub, proto, code, size, redir in alive:
        url = f"{proto}://{sub}"
        headers = run_cmd(f"curl -skI --max-time 8 '{url}/' 2>/dev/null", timeout=12)
        fps, wafs, spa = fingerprint_target(url, headers)

        entry = {
            "url": url, "code": code, "size": size, "redir": redir,
            "fingerprints": fps, "wafs": wafs, "spa": spa,
            "headers": headers
        }

        # Determine highest priority
        best_priority = "P3"
        for fp in fps:
            fp_info = FINGERPRINT_MAP.get(fp, {})
            p = fp_info.get("priority", "P3")
            if p == "SKIP":
                best_priority = "SKIP"
                break
            priority_order = ["P0", "P1", "P2", "P3"]
            if priority_order.index(p) < priority_order.index(best_priority):
                best_priority = p

        # High-value subdomain bonus
        sub_name = sub.split('.')[0]
        if sub_name in HIGH_VALUE_SUBS and best_priority == "P3":
            best_priority = "P2"

        entry["priority"] = best_priority
        priority_groups[best_priority].append(entry)

    # Output report
    for p in ["P0", "P1", "P2", "P3", "SKIP"]:
        entries = priority_groups[p]
        if not entries:
            continue

        lines.append(f"## {p} 优先级 ({len(entries)}个)")
        lines.append("")

        for e in entries:
            fp_names = [FINGERPRINT_MAP[f]["name"] for f in e["fingerprints"] if f in FINGERPRINT_MAP]
            waf_str = f" [WAF: {', '.join(e['wafs'])}]" if e['wafs'] else ""
            spa_str = " [SPA]" if e['spa'] else ""
            fp_str = f" [{', '.join(fp_names)}]" if fp_names else ""

            lines.append(f"  {e['url']} → {e['code']} ({e['size']}B){fp_str}{waf_str}{spa_str}")

            # Generate first-hit commands
            for fp in e["fingerprints"]:
                fp_info = FINGERPRINT_MAP.get(fp, {})
                if fp_info.get("priority") in ("P0", "P1"):
                    for test in fp_info.get("tests", []):
                        cmd = test.replace("{base}", e["url"].rstrip('/'))
                        first_hits.append(f"# {fp_info['name']}: {fp_info['vulns'][0] if fp_info.get('vulns') else ''}")
                        first_hits.append(cmd)
                        first_hits.append("")

        lines.append("")

    # Summary
    p0_count = len(priority_groups["P0"])
    p1_count = len(priority_groups["P1"])
    lines.append("## 结论")
    lines.append("")
    if p0_count > 0:
        lines.append(f"  🔥 发现 {p0_count} 个P0高价值目标，立即深入测试！")
    elif p1_count > 0:
        lines.append(f"  ⚡ 发现 {p1_count} 个P1目标，值得投入15-20分钟")
    else:
        lines.append("  ⚠️ 无高价值目标，建议5分钟快速扫描后换目标")
    lines.append("")

    # Write files
    report = '\n'.join(lines)
    with open(f"{outdir}/attack_surface.md", 'w') as f:
        f.write(report)

    with open(f"{outdir}/first_hits.sh", 'w') as f:
        f.write("#!/bin/bash\n")
        f.write(f"# {domain} - 推荐第一轮测试命令\n")
        f.write(f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M')}\n\n")
        f.write('\n'.join(first_hits) + '\n')
    os.chmod(f"{outdir}/first_hits.sh", 0o755)

    return report


def main():
    parser = argparse.ArgumentParser(description="SRC Fast Assessment - 一键目标快筛")
    parser.add_argument("domain", help="目标域名 (如 example.edu.cn)")
    parser.add_argument("--deep", action="store_true", help="深度模式(含nuclei扫描)")
    parser.add_argument("--out", help="输出目录")
    parser.add_argument("--max-subs", type=int, default=100, help="最大子域名数(默认100)")
    args = parser.parse_args()

    domain = args.domain.replace("https://", "").replace("http://", "").rstrip('/')
    # Extract hostname safely: strip paths, ports, query strings
    if '/' in domain:
        domain = domain.split('/')[0]
    if ':' in domain:
        domain = domain.split(':')[0]
    # FQDN validation: only allow hostname chars
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$', domain):
        print(f"[!] Invalid domain: {domain}")
        sys.exit(1)
    outdir = args.out or f"/tmp/src_assess_{domain}"
    os.makedirs(outdir, exist_ok=True)

    print(f"[*] 目标: {domain}")
    print(f"[*] 输出: {outdir}")
    print()

    # Phase 1: Subdomain enumeration
    print("[1/4] 子域名枚举...")
    t0 = time.time()
    subs = subdomain_enum(domain, outdir)
    # Always include the main domain
    if domain not in subs:
        subs.insert(0, domain)
    subs = subs[:args.max_subs]
    print(f"      发现 {len(subs)} 个子域名 ({time.time()-t0:.1f}s)")

    # Phase 2: HTTP probing
    print("[2/4] HTTP探活...")
    t0 = time.time()
    alive = probe_alive(subs, outdir)
    print(f"      {len(alive)} 个存活服务 ({time.time()-t0:.1f}s)")

    if not alive:
        print("[!] 无存活服务，目标不可达")
        sys.exit(1)

    # Phase 3: Fingerprinting + Attack surface
    print("[3/4] 指纹识别 + 攻击面评估...")
    t0 = time.time()
    report = generate_attack_surface(domain, alive, FINGERPRINT_MAP, outdir)
    print(f"      完成 ({time.time()-t0:.1f}s)")

    # Phase 4: Deep scan (optional)
    if args.deep:
        print("[4/4] Nuclei深度扫描...")
        targets = '\n'.join([f"{proto}://{sub}" for sub, proto, _, _, _ in alive[:20]])
        targets_file = f"{outdir}/nuclei_targets.txt"
        with open(targets_file, 'w') as f:
            f.write(targets)
        nuclei_out = f"{outdir}/nuclei_results.txt"
        run_cmd(f"nuclei -l {targets_file} -severity medium,high,critical -silent -nc -o {nuclei_out} 2>/dev/null", timeout=120)
        if os.path.exists(nuclei_out):
            with open(nuclei_out) as f:
                results = f.read().strip()
            if results:
                print(f"      Nuclei发现:\n{results}")
            else:
                print("      Nuclei无发现")
    else:
        print("[4/4] 跳过深度扫描(使用 --deep 启用)")

    # Print report
    print()
    print("=" * 60)
    print(report)
    print("=" * 60)
    print(f"\n[*] 完整报告: {outdir}/attack_surface.md")
    print(f"[*] 推荐命令: {outdir}/first_hits.sh")
    print(f"[*] 子域名: {outdir}/subs.txt")
    print(f"[*] 存活服务: {outdir}/alive.txt")


if __name__ == "__main__":
    main()
