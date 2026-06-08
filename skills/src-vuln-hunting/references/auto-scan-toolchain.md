# 自动化漏洞扫描工具链 (2026-06-02)

## 工具部署位置
所有脚本: ~/.agent/scripts/
渗透框架: ~/.agent/scripts/pentest_*.py

## 教育SRC标准流程
```bash
# 1. 初始化workspace
/usr/bin/python3 ~/.agent/scripts/src-workspace.py init target.edu.cn

# 2. 批量探测(20域/4.5秒)
/usr/bin/python3 ~/.agent/scripts/edu-batch-probe.py subs.txt --dns -f -o alive.txt

# 3. 提取URL并漏洞扫描
awk '{print $3}' alive.txt | grep '://' > urls.txt
/usr/bin/python3 ~/.agent/scripts/auto-vuln-scan.py urls.txt --enum --workspace target.edu.cn

# 4. JS安全分析(对SPA目标)
/usr/bin/python3 ~/.agent/scripts/js-secrets-scanner.py https://target/assets/index.js --url

# 5. 查看结果
/usr/bin/python3 ~/.agent/scripts/src-workspace.py status target.edu.cn
```

## 渗透验证流程
```bash
# 漏洞验证(SQLi/XSS/RCE/IDOR)
/usr/bin/python3 ~/.agent/scripts/pentest_verifier.py https://target/api id --type=sqli,xss

# 完整扫描(指纹+漏洞+验证+报告)
/usr/bin/python3 ~/.agent/scripts/pentest_framework.py target.edu.cn --scan-type full
```

## 内置指纹库覆盖
22个产品, 96个漏洞路径:
致远OA, CAS, Spring Boot, Druid, Swagger, 泛微OA, 金智CAS, WebVPN, Tomcat, Nginx, VSB, Shiro,
用友U8/NC, 金蝶云星空, 蓝凌OA, 通达OA, 浪潮GS, 正方教务, 强智教务, 青果教务, 金智教育Wisedu, 树维教务

## JS检测规则(35+条)
API端点/密钥/JWT/内网IP/数据库连接/云存储/本地路径/阿里云AK/腾讯云SID/华为云AK/钉钉Webhook/企业微信Webhook/SMTP密码/MySQL/Redis/MongoDB连接串/JWT签名密钥
