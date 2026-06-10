#!/usr/bin/python3
"""
js-secrets-scanner.py - JS/前端安全分析器
从JS bundle中提取API端点、密钥、内部URL、硬编码凭据

用法:
  python3 js-secrets-scanner.py bundle.js
  python3 js-secrets-scanner.py bundle.js --json -o results.json
  python3 js-secrets-scanner.py https://target/assets/index.js --url
  cat bundle.js | python3 js-secrets-scanner.py -

输出: 分类的安全发现(端点/密钥/URL/IP/密码)
"""

import re
import sys
import os
import json
import hashlib
import argparse
from collections import defaultdict


# ============================================================
# 检测规则
# ============================================================
RULES = {
    'api_endpoints': {
        'name': 'API端点',
        'severity': 'info',
        'pattern': r'["\']/(api|rest|v[12]/|graphql|auth|oauth|sso|login|admin|user|token|service)[/a-zA-Z0-9._-]*["\']',
        'description': '后端API端点路径',
        'dedupe': True,
    },
    'internal_urls': {
        'name': '内部URL',
        'severity': 'medium',
        'pattern': r'https?://[a-zA-Z0-9._-]+\.(internal|local|intra|corp|priv|test|dev|staging|pre)\.[a-zA-Z]{2,}[^"\'>\s]*',
        'description': '内部/测试环境URL',
    },
    'internal_ips': {
        'name': '内网IP',
        'severity': 'medium',
        'pattern': r'(?<![0-9.])(?:(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3}))(?![0-9.])',
        'description': 'RFC1918内网IP地址',
    },
    'aws_access_key': {
        'name': 'AWS Access Key',
        'severity': 'critical',
        'pattern': r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
        'description': 'AWS Access Key ID',
    },
    'aws_secret_key': {
        'name': 'AWS Secret Key',
        'severity': 'critical',
        'pattern': r'(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
        'description': 'AWS Secret Access Key',
    },
    'generic_secrets': {
        'name': '硬编码密钥',
        'severity': 'high',
        'pattern': r'(?:appKey|appSecret|appId|apiKey|api_key|secretKey|secret_key|clientSecret|client_secret|accessKey|access_key|privateKey|private_key|encryptKey|encrypt_key)\s*[:=]\s*["\']([A-Za-z0-9+/=_\-]{8,})["\']',
        'description': '硬编码的API密钥/Secret',
    },
    'hardcoded_passwords': {
        'name': '硬编码密码',
        'severity': 'high',
        'pattern': r'(?:password|passwd|pwd|pass)\s*[:=]\s*["\']([^"\']{6,})["\']',
        'description': '硬编码的密码',
        'filter': lambda m: not any(x in m.group(1).lower() for x in
            ['password', 'placeholder', 'example', 'test', 'null', 'none',
             'empty', 'default', 'input', 'form', 'label', 'type', 'name']),
    },
    'jwt_tokens': {
        'name': 'JWT Token',
        'severity': 'high',
        'pattern': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        'description': '硬编码的JWT Token',
    },
    'bearer_tokens': {
        'name': 'Bearer Token',
        'severity': 'high',
        'pattern': r'(?:Bearer|bearer|BEARER)\s+[A-Za-z0-9._\-]{20,}',
        'description': '硬编码的Bearer Token',
    },
    'private_keys': {
        'name': '私钥',
        'severity': 'critical',
        'pattern': r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----',
        'description': '嵌入的私钥',
    },
    'base64_long': {
        'name': '长Base64串',
        'severity': 'low',
        'pattern': r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/=])',
        'description': '可能是编码的密钥或配置',
        'max_matches': 10,
    },
    'hex_secrets': {
        'name': '十六进制密钥',
        'severity': 'medium',
        'pattern': r'(?:key|secret|token|salt|iv|nonce)\s*[:=]\s*["\']([0-9a-fA-F]{16,})["\']',
        'description': '硬编码的十六进制密钥',
    },
    'sm4_keys': {
        'name': 'SM4密钥',
        'severity': 'high',
        'pattern': r'(?:SM4|sm4|secretKey|key_enc)\s*[^\n]*?[0-9A-Fa-f]{16}',
        'description': 'SM4加密密钥',
    },
    'wechat_appid': {
        'name': '微信AppID',
        'severity': 'low',
        'pattern': r'(?:appid|appId|app_id)\s*[:=]\s*["\']?(wx[0-9a-f]{16})["\']?',
        'description': '微信AppID',
    },
    'alipay_key': {
        'name': '支付宝密钥',
        'severity': 'high',
        'pattern': r'(?:alipay|ali)\s*(?:public|private)?\s*(?:key|Key)\s*[:=]\s*["\']([A-Za-z0-9+/=\n]{20,})["\']',
        'description': '支付宝公钥/私钥',
    },
    'database_urls': {
        'name': '数据库连接',
        'severity': 'critical',
        'pattern': r'(?:mysql|postgres|mongodb|redis|jdbc|mssql|oracle)(?:://|:)[^\s"\']{10,}',
        'description': '数据库连接字符串',
    },
    'debug_mode': {
        'name': '调试模式',
        'severity': 'medium',
        'pattern': r'(?:debug|DEBUG)\s*[:=]\s*(?:true|True|TRUE|1|on)',
        'description': '调试模式开启',
    },
    'test_accounts': {
        'name': '测试账号',
        'severity': 'medium',
        'pattern': r'(?:test(?:user)?|admin|root|demo)\s*[:=]\s*["\']([^"\']{4,})["\']',
        'description': '可能的测试账号密码',
        'filter': lambda m: len(m.group(1)) >= 4,
    },
    'webhook_urls': {
        'name': 'Webhook URL',
        'severity': 'medium',
        'pattern': r'https://hooks\.[a-zA-Z0-9.-]+\.com/[^\s"\']+',
        'description': 'Webhook回调URL',
    },
    'cloud_storage': {
        'name': '云存储URL',
        'severity': 'medium',
        'pattern': r'https?://[a-zA-Z0-9.-]+\.(oss|s3|cos|bos|qiniu|upyun)\.[a-zA-Z]{2,}/[^\s"\']+',
        'description': '云存储OSS/S3/COS URL',
    },
    'cdn_assets': {
        'name': 'CDN资源',
        'severity': 'info',
        'pattern': r'https?://[a-zA-Z0-9.-]+\.(cdn|static|assets|img|media)\.[a-zA-Z]{2,}/[^\s"\']+',
        'description': 'CDN资源URL',
        'max_matches': 5,
    },
    'local_paths': {
        'name': '本地路径泄露',
        'severity': 'medium',
        'pattern': r'(?:C:\\|D:\\|/home/|/var/|/opt/|/usr/|/etc/|/root/|/tmp/)[^\s"\']{5,}',
        'description': '开发者本地路径泄露',
    },
    'sentry_dsn': {
        'name': 'Sentry DSN',
        'severity': 'medium',
        'pattern': r'https?://[a-f0-9]+@[a-zA-Z0-9.-]+/\d+',
        'description': 'Sentry错误追踪DSN',
    },
    'firebase_config': {
        'name': 'Firebase配置',
        'severity': 'medium',
        'pattern': r'(?:firebase|firebaseConfig)\s*[:=]\s*\{[^}]*(?:apiKey|authDomain|projectId)[^}]*\}',
        'description': 'Firebase配置信息',
    },
    'graphql_introspection': {
        'name': 'GraphQL Introspection',
        'severity': 'medium',
        'pattern': r'(?:__schema|__type|introspectionQuery|IntrospectionQuery)',
        'description': 'GraphQL Introspection端点',
    },
    'vue_config': {
        'name': 'Vue环境变量',
        'severity': 'low',
        'pattern': r'VUE_APP_[A-Z_]+\s*[:=]\s*["\'][^"\']+["\']',
        'description': 'Vue.js环境变量',
    },
    'react_env': {
        'name': 'React环境变量',
        'severity': 'low',
        'pattern': r'REACT_APP_[A-Z_]+\s*[:=]\s*["\'][^"\']+["\']',
        'description': 'React环境变量',
    },
    'next_public': {
        'name': 'Next.js公开变量',
        'severity': 'low',
        'pattern': r'NEXT_PUBLIC_[A-Z_]+\s*[:=]\s*["\'][^"\']+["\']',
        'description': 'Next.js公开环境变量',
    },
    'aliyun_access_key': {
        'name': '阿里云AccessKey',
        'severity': 'high',
        'pattern': r'(?<![A-Z0-9])LTAI[a-zA-Z0-9]{12,20}(?![A-Z0-9])',
        'description': '阿里云AccessKey ID泄露',
    },
    'tencent_secret_id': {
        'name': '腾讯云SecretId',
        'severity': 'high',
        'pattern': r'(?<![A-Z0-9])AKID[a-zA-Z0-9]{13,20}(?![A-Z0-9])',
        'description': '腾讯云SecretId泄露',
    },
    'huawei_cloud_ak': {
        'name': '华为云AK',
        'severity': 'high',
        'pattern': r'(?<![A-Z0-9])AK[0-9A-Z]{20}(?![A-Z0-9])',
        'description': '华为云Access Key泄露',
    },
    'dingtalk_webhook': {
        'name': '钉钉Webhook',
        'severity': 'high',
        'pattern': r'https://oapi\.dingtalk\.com/robot/send\?access_token=[a-zA-Z0-9]+',
        'description': '钉钉机器人Webhook泄露',
    },
    'wecom_webhook': {
        'name': '企业微信Webhook',
        'severity': 'high',
        'pattern': r'https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9-]+',
        'description': '企业微信机器人Webhook泄露',
    },

}


def load_extra_rules():
    """从JSON文件加载额外规则"""
    extra_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'extra-js-rules.json')
    if os.path.exists(extra_file):
        try:
            with open(extra_file) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


# 合并额外规则
EXTRA_RULES = load_extra_rules()
RULES.update(EXTRA_RULES)


def scan_js(content, rules=None):
    """扫描JS内容"""
    if rules is None:
        rules = RULES

    findings = defaultdict(list)
    seen = defaultdict(set)

    for rule_id, rule in rules.items():
        pattern = rule['pattern']
        max_matches = rule.get('max_matches', 50)
        custom_filter = rule.get('filter')
        dedupe = rule.get('dedupe', False)

        try:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                if custom_filter and not custom_filter(match):
                    continue

                value = match.group(0).strip()

                # 去重
                if dedupe:
                    vhash = hashlib.md5(value.encode()).hexdigest()[:8]
                    if vhash in seen[rule_id]:
                        continue
                    seen[rule_id].add(vhash)

                # 上下文: 匹配前后各50字符
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace('\n', ' ').strip()

                findings[rule_id].append({
                    'value': value,
                    'context': context,
                    'position': match.start(),
                })

                if len(findings[rule_id]) >= max_matches:
                    break
        except re.error:
            pass

    return dict(findings)


def extract_api_routes(content):
    """提取Vue/React路由定义"""
    routes = []

    # Vue Router
    vue_routes = re.findall(r'path:\s*["\']([^"\']+)["\']', content)
    routes.extend(('vue_route', r) for r in vue_routes)

    # Express/Koa routes
    express_routes = re.findall(r'(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', content)
    routes.extend(('express_route', f'{m.upper()} {r}') for m, r in express_routes)

    # Fetch/Axios URLs
    fetch_urls = re.findall(r'(?:fetch|axios|request)\s*\(\s*["\']([^"\']+)["\']', content)
    routes.extend(('fetch_url', u) for u in fetch_urls)

    # Axios baseURL
    base_urls = re.findall(r'baseURL\s*:\s*["\']([^"\']+)["\']', content)
    routes.extend(('base_url', u) for u in base_urls)

    return routes


def format_report(findings, routes=None):
    """格式化报告"""
    lines = []
    total = sum(len(v) for v in findings.values())

    lines.append("JS安全分析报告")
    lines.append(f"{'='*60}")
    lines.append(f"总发现: {total}")
    lines.append("")

    # 按严重性分组
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    by_severity = defaultdict(list)

    for rule_id, items in findings.items():
        rule = RULES[rule_id]
        sev = rule['severity']
        by_severity[sev].append((rule_id, rule['name'], rule['description'], items))

    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        if sev not in by_severity:
            continue

        lines.append(f"[{sev.upper()}] ({sum(len(x[3]) for x in by_severity[sev])} items)")
        lines.append(f"{'-'*40}")

        for rule_id, name, desc, items in by_severity[sev]:
            lines.append(f"  {name}: {desc}")
            for item in items:
                val = item['value']
                # 截断过长的值
                if len(val) > 200:
                    val = val[:200] + '...'
                lines.append(f"    - {val}")
            lines.append("")

    # API路由
    if routes:
        lines.append(f"[INFO] API路由 ({len(routes)} items)")
        lines.append(f"{'-'*40}")
        for route_type, route in routes:
            lines.append(f"  [{route_type}] {route}")
        lines.append("")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='JS security scanner')
    parser.add_argument('input', help='JS file path or URL (use - for stdin)')
    parser.add_argument('--url', action='store_true', help='Input is a URL, fetch it first')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--rules', help='Custom rules JSON file')
    parser.add_argument('--severity', default='info',
                        choices=['critical', 'high', 'medium', 'low', 'info'],
                        help='Minimum severity to show')
    parser.add_argument('--no-routes', action='store_true', help='Skip route extraction')
    args = parser.parse_args()

    # 读取内容
    if args.url:
        import subprocess
        r = subprocess.run(['curl', '-sk', '--max-time', '15', args.input],
                         capture_output=True, text=True, timeout=20)
        content = r.stdout
    elif args.input == '-':
        content = sys.stdin.read()
    else:
        with open(args.input, 'r', errors='ignore') as f:
            content = f.read()

    if not content:
        print("[-] No content to scan")
        sys.exit(1)

    print(f"[*] Scanning {len(content)} bytes...")

    # 加载自定义规则
    rules = RULES
    if args.rules:
        with open(args.rules) as f:
            custom = json.load(f)
            rules.update(custom)

    # 扫描
    findings = scan_js(content, rules)

    # 提取路由
    routes = []
    if not args.no_routes:
        routes = extract_api_routes(content)

    # 过滤严重性
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    min_sev = severity_order.get(args.severity, 4)
    filtered = {}
    for rule_id, items in findings.items():
        rule_sev = severity_order.get(RULES[rule_id]['severity'], 4)
        if rule_sev <= min_sev:
            filtered[rule_id] = items

    # 输出
    if args.json:
        result = {
            'findings': {k: [{'value': i['value'], 'position': i['position']}
                           for i in v] for k, v in filtered.items()},
            'routes': [(t, r) for t, r in routes],
            'stats': {k: len(v) for k, v in findings.items()},
            'total': sum(len(v) for v in findings.values()),
        }
        output = json.dumps(result, indent=2, ensure_ascii=False)
    else:
        output = format_report(filtered, routes)

    print(output)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"\n[+] Written to {args.output}")


if __name__ == '__main__':
    main()
