# WAF探测与绕过 + 上传能力评估 模式库

## WAF探测工具链

### 快速WAF检测
```bash
# wafw00f - 最快
wafw00f http://TARGET

# 自定义WAF指纹 (20+国内外WAF)
python3 /opt/redteam-toolchain/waf-recon-bypass.py http://TARGET --detect

# 完整规则探测 (SQL/XSS/CMD/LFI关键字逐个测试)
python3 /opt/redteam-toolchain/waf-recon-bypass.py http://TARGET --probe
```

### WAF规则探测关键指标
- SQL关键字: 哪些被拦截(UNION/SELECT/AND/OR)、哪些可绕过
- 特殊字符: < > ' " ; -- /* */ 哪些被拦截
- XSS模式: <script> alert( eval( 哪些被拦截
- 命令注入: ; | && ` $( 哪些被拦截
- 编码绕过: URL/双重URL/Unicode/HTML/十六进制/Base64 哪些有效

### 常见WAF特征速查
| WAF | 响应头 | 拦截特征 |
|-----|--------|---------|
| Cloudflare | cf-ray | attention required |
| 阿里云WAF | eagleid | cc protection |
| 腾讯云WAF | x-nws-log-uuid | waf protection |
| 长亭雷池 | server: openresty | chaitin |
| ModSecurity | server: apache | mod_security |
| AWS WAF | x-amzn-requestid | 403 Forbidden |

## 上传能力评估

### 快速测试
```bash
python3 /opt/redteam-toolchain/upload-capability-scanner.py http://TARGET /upload
```

### 手动测试清单
1. 扩展名: php/jsp/asp/phtml/php5/phar/htaccess/user.ini
2. Content-Type: image/jpeg image/png application/pdf
3. 文件头: GIF89a + PHP代码
4. 双扩展名: shell.php.jpg shell.php%00.jpg
5. 配置文件: .htaccess (AddType) .user.ini (auto_prepend_file)
6. 目录穿越: ../../../shell.php
7. 竞争条件: 并发上传+立即访问

### 绕过字典生成
```bash
# 上传绕过字典
python3 /opt/redteam-toolchain/waf-bypass-generator.py upload -o /tmp/upload_bypass.txt

# 针对特定WAF的SQL注入绕过
python3 /opt/redteam-toolchain/waf-bypass-generator.py sql --waf cloudflare -o /tmp/sqli.txt

# URL编码变体
python3 /opt/redteam-toolchain/waf-bypass-generator.py sql --encode url -o /tmp/sqli_url.txt
```

## 工具链位置
`/opt/redteam-toolchain/` 包含5个工具:
- waf-recon-bypass.py: WAF指纹+规则探测+绕过策略
- upload-capability-scanner.py: 上传能力评估
- redteam-attack-chain.py: 完整攻击链自动化
- waf-bypass-generator.py: 绕过字典生成器
- quick-attack.sh: 一键部署脚本
- README.md: 快速参考手册

## 一键部署
```bash
bash /opt/redteam-toolchain/quick-attack.sh http://TARGET /upload
```
报告输出: /tmp/{waf_analysis,upload_analysis,redteam_attack}/
