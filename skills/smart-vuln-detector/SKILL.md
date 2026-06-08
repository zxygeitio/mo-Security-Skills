---
name: smart-vuln-detector
description: >-
  智能漏洞检测框架 - 基于指纹的漏洞特征匹配、自动选择检测方式
domain: cybersecurity
subdomain: vulnerability-management
tags:
- security
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1190
- T1595
nist_csf:
- DE.CM-01
- ID.RA-01
---
# Smart Vulnerability Detector

智能漏洞检测框架，根据服务指纹自动选择合适的检测方式。

## 核心概念

```
服务指纹 (Service Fingerprint)
    ├── service: ssh/http/mysql/redis
    ├── product: openssh/apache/nginx
    ├── version: 9.0/2.4.49/6.0
    └── port: 22/80/3306/6379
            ↓
    VulnSignatureDB (漏洞特征库)
            ↓
    版本匹配 (Version Match)
            ↓
    选择检测方式 (Detection Method)
    ├── nuclei: CVE扫描
    ├── sqlmap: SQL注入
    ├── dalfox: XSS扫描
    └── custom: 自定义检测
```

## 核心组件

### 1. VulnSignature 漏洞特征

```python
from dataclasses import dataclass

@dataclass
class VulnSignature:
    name: str           # 漏洞名称
    cve: str           # CVE编号
    severity: str      # critical/high/medium/low
    product: str       # 产品名称
    version_pattern: str  # 版本模式: "<=2.0", "1.0-2.5", "*"
    port: int          # 常用端口
    service: str       # 服务类型
    detection_method: str  # nuclei/sqlmap/dalfox/custom
    detection_rule: str    # 检测规则
    description: str
    remediation: str
```

### 2. VulnSignatureDB 漏洞特征数据库

```python
import sqlite3

class VulnSignatureDB:
    def __init__(self, db_path: str = "signatures.db"):
        self.db_path = db_path
        self.init_db()
        self.load_signatures()
    
    def query_by_fingerprint(self, service: str, product: str = None,
                           version: str = None, port: int = None) -> list:
        """根据指纹查询匹配的漏洞"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        query = "SELECT * FROM signatures WHERE 1=1"
        params = []
        
        if service:
            query += " AND service = ?"
            params.append(service)
        if product:
            query += " AND product = ?"
            params.append(product)
        if port:
            query += " AND port = ?"
            params.append(port)
        
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        
        return [self._row_to_signature(row) for row in rows]
    
    def version_match(self, version: str, pattern: str) -> bool:
        """版本匹配"""
        if pattern == "*":
            return True
        
        # 支持 <=, <, >=, >, 范围
        import re
        if '<=' in pattern:
            target = pattern.split('<=')[1].strip()
            return self._compare_versions(version, target) <= 0
        elif '<' in pattern:
            target = pattern.split('<')[1].strip()
            return self._compare_versions(version, target) < 0
        # ... 其他模式
        return version == pattern
```

### 3. 内置漏洞特征库 (19个)

| 产品 | CVE | 严重性 | 检测方式 |
|------|-----|--------|----------|
| openssh | CVE-2024-6387 | critical | nuclei |
| openssh | CVE-2018-15473 | medium | nuclei |
| apache | CVE-2021-41773 | high | nuclei |
| apache | CVE-2021-42013 | critical | nuclei |
| nginx | CVE-2017-7529 | medium | nuclei |
| mysql | - | high | sqlmap |
| postgresql | - | high | sqlmap |
| mongodb | - | high | custom |
| redis | - | critical | custom |
| elasticsearch | CVE-2015-1427 | critical | nuclei |
| struts | CVE-2017-5638 | critical | nuclei |
| spring | CVE-2022-22965 | critical | nuclei |
| tomcat | CVE-2020-1938 | high | nuclei |
| fortios | CVE-2024-21762 | critical | nuclei |
| cisco-asa | CVE-2018-0296 | high | nuclei |
| wordpress | - | high | wpscan |
| drupal | CVE-2014-3704 | critical | sqlmap |
| ssti | - | critical | tplmap |
| xss | - | high | dalfox |
| sqli | - | critical | sqlmap |
| cmdi | - | critical | commix |
| lfi | - | high | custom |
| xxe | - | high | custom |
| ssrf | - | high | custom |
| deserialization | - | critical | ysoserial |
| kerberos | - | high | kerbrute |
| ad_cert | - | high | Certipy |
| ad_coercion | - | high | Coercer |
| smb | - | high | enum4linux-ng |
| winrm | - | high | evil-winrm |
| responder | - | high | Responder |
| bloodhound | - | high | BloodHound |
| tunnel | - | high | chisel + ligolo-ng |

### 4. SmartVulnScanner 智能扫描器

```python
class SmartVulnScanner:
    def __init__(self, sig_db: VulnSignatureDB):
        self.sig_db = sig_db
    
    def scan_host(self, host: str, port: int, service: str,
                 product: str = None, version: str = None) -> list:
        """根据指纹扫描主机"""
        vulns = []
        
        # 查询匹配的漏洞
        signatures = self.sig_db.query_by_fingerprint(
            service=service, product=product, port=port
        )
        
        for sig in signatures:
            # 版本检查
            if sig.version_pattern != "*" and version:
                if not self.sig_db.version_match(version, sig.version_pattern):
                    continue
            
            vulns.append({
                'host': host,
                'port': port,
                'signature': sig,
                'scan_command': self._build_command(sig, host, port),
                'method': sig.detection_method
            })
        
        return vulns
    
    def group_by_method(self, vulns: list) -> dict:
        """按检测方法分组"""
        grouped = {'nuclei': [], 'sqlmap': [], 'dalfox': [], 'custom': []}
        for v in vulns:
            method = v.get('method', 'custom')
            if method in grouped:
                grouped[method].append(v)
        return grouped
```

## 使用示例

```python
#!/usr/bin/env python3
"""智能漏洞检测示例"""
from vuln_signatures import VulnSignatureDB, SmartVulnScanner

# 初始化
sig_db = VulnSignatureDB()
scanner = SmartVulnScanner(sig_db)

# 扫描SSH服务
vulns = scanner.scan_host('192.168.1.1', 22, 'ssh', 'openssh', '9.0')
print(f"Found {len(vulns)} potential vulns")

for v in vulns:
    print(f"  - {v['signature'].name} ({v['signature'].cve})")
    print(f"    Method: {v['method']}")
    print(f"    Command: {v['scan_command']}")

# 分组执行
grouped = scanner.group_by_method(vulns)
for method, items in grouped.items():
    if items:
        print(f"\n{method.upper()}: {len(items)} vulns")
        # 执行检测...
```

## 扩展自定义特征

```python
# 添加自定义漏洞特征
sig_db.add_signature(VulnSignature(
    name="Custom App RCE",
    cve="CVE-2024-99999",
    severity="critical",
    product="custom-app",
    version_pattern="<3.0",
    port=8080,
    service="http",
    detection_method="nuclei",
    detection_rule="cves/2024/CVE-2024-99999.yaml",
    description="Custom App RCE",
    remediation="Upgrade to 3.0+"
))
```

## 适用场景
- 自动化渗透测试
- 安全评估扫描
- 漏洞优先级排序
- 基于指纹的精准检测

## 优势
1. **减少误报**: 只检测实际存在的版本漏洞
2. **提高效率**: 按方法分组避免重复扫描
3. **可扩展**: 支持添加自定义漏洞特征
4. **可维护**: 特征与检测逻辑分离
