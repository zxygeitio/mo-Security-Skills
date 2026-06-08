# hnca.edu.cn 河南农业职业学院 测试记录 (2026-05-29)

## 目标概况
- 主站: www.hnca.edu.cn -> 61.163.83.34 (rump/c + OpenResty)
- 认证/办事: authserver/ehall -> 61.163.83.35 (OpenResty, 外部封锁)
- 子域名: www, authserver, ehall, xljk, foodsec, dns, dns2, tsg, zsw, jxjyzx, cxcyxy, kyc, jwc, rsc, lyxq
- 内网: 172.16.2.103 (CMS编辑), 172.16.2.203 (食品系统)
- CMS: 金智教育(iEDU)系列, uploads/ieduimg路径
- 端口: 80/81/443/8081(filtered)/8082(filtered)
- SSL: *.hnca.edu.cn 通配证书 (Xcc Trust OV SSL CA)
- DNS: 通配符生效(198.18.x.x), 真实IP需通过nmap确认

## 发现的漏洞

### [中危] API信息泄露 - 内网IP + 配置
- 端点: POST /api/login, POST /api/search
- 泄露: article_edit_ip_kuayu=172.16.2.103, domain_ssl, domain_url
- 任意参数均可触发

### [低危] DNS内网IP泄露
- foodsec.hnca.edu.cn -> 172.16.2.203 (内网)

### [低危] xljk平台DES弱加密
- xljk.hnca.edu.cn 心理健康教育大数据平台
- des.js 前端加密, 密钥硬编码
- 登录: /user/login.do -> loginVerify.do

### [信息] robots.txt泄露 /system/* 和 /fenxiang/*
### [信息] .env文件存在(403保护)
### [信息] DNS递归查询已启用, DNSSEC未配置

## 关键教训
1. DNS通配符: hnca.edu.cn全面启用通配符(198.18.x.x), fierce/amass/dnsrecon结果需过滤
2. IP封锁: 约1h主动扫描后目标封锁了攻击者IP，所有连接重置
3. authserver/ehall对外部IP直接拒绝连接(非WAF拦截而是TCP RST)
4. 该CMS的API信息泄露是"每次请求都返回"模式，无需特殊权限
5. 教育网WAF封锁通常有时间限制，可等待后重试

## 报告位置
/tmp/vuln_reports/hnca/vuln-report-v2.txt
