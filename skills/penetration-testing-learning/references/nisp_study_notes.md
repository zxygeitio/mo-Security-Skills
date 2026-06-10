# NISP 国家信息安全水平考试 学习笔记

> 整理时间：2026-05-16
> 目标：达到NISP三级（专家级）水平

---

## NISP概述

**NISP**（National Information Security Professional Certification）是中国信息安全测评中心组织的信息安全专业认证体系，与CISP（注册信息安全专业人员）衔接。

| 级别 | 定位 | 证书名称 |
|------|------|----------|
| 一级 | 基础级 | NISP一级 |
| 二级 | 专业级 | NISP二级 |
| 三级 | 专家级 | NISP三级（多方向） |

---

## NISP一级（基础级）

### 考试要求
- 题型：选择题（100道）
- 时长：90分钟
- 及格：70分

### 知识模块

#### 1. 信息安全基本概念
- 信息与信息安全定义
- 信息安全属性（机密性、完整性、可用性）
- 信息安全威胁与攻击类型
- 病毒、木马、蠕虫区别

#### 2. 信息安全法律法规
- 《网络安全法》核心内容
- 《数据安全法》
- 《个人信息保护法》
- 《密码法》
- 信息安全相关法规体系

#### 3. 信息安全管理基础
- 信息安全管理体系（ISMS）
- 安全组织结构
- 安全策略与制度
- 风险管理基本流程
- 应急响应流程

#### 4. 基本安全技能
- 密码学基础（对称/非对称加密、Hash）
- 身份认证与访问控制
- 操作系统安全配置
- 网络安全基础（防火墙、IDS/IPS）
- Web安全基础（XSS、SQL注入等常见漏洞）

---

## NISP二级（专业级）

### 考试要求
- 题型：选择题 + 简答题
- 课时要求：80学时
- 与CISP知识体系一致

### 知识模块

#### 1. 信息安全保障与网络安全

##### 1.1 信息安全保障体系
- 信息安全保障内涵
- 安全保障框架（PCDRR、IATF）
- 等级保护制度（1.0 → 2.0演进）

##### 1.2 网络安全独立防御
- OSI七层模型安全
- 各层攻击与防御
- 网络设备安全（路由器、交换机）
- 无线网络安全

#### 2. 密码学应用

##### 2.1 密码学基础
- 对称加密算法（AES、DES、3DES）
- 非对称加密算法（RSA、ECC）
- Hash算法（MD5、SHA-1、SHA-256）
- 数字签名原理

##### 2.2 PKI公钥基础设施
- 数字证书结构（X.509）
- 证书颁发机构（CA）
- 证书注册机构（RA）
- 证书信任链

##### 2.3 密码学应用场景
- SSL/TLS协议
- VPN加密（IPSec、SSL VPN）
- 电子签名
- 区块链与密码学

#### 3. 操作系统安全

##### 3.1 Windows安全
- Windows安全架构
- 用户账户控制（UAC）
- 权限管理
- 注册表安全
- 安全策略配置
- 日志分析

##### 3.2 Linux安全
- Linux权限模型（rwx、SUID、SGID）
- PAM认证模块
- SELinux/AppArmor
- 系统服务加固
- 日志管理（/var/log）
- 网络安全加固

#### 4. 数据库安全

##### 4.1 数据库安全机制
- 访问控制（RBAC）
- 视图与存储过程安全
- 审计日志
- 加密存储

##### 4.2 SQL注入与防御
- 注入类型（联合、布尔、报错、时间盲注）
- 宽字节注入、绕过技巧
- 预编译防御

#### 5. Web安全

##### 5.1 Web安全威胁
- OWASP Top 10
- XSS（存储、反射、DOM）
- SQL注入
- CSRF
- SSRF
- 文件上传/下载漏洞
- 命令注入

##### 5.2 Web安全防护
- Web应用防火墙（WAF）
- 安全编码规范
- 输入验证
- 输出编码
- HTTP头安全（CSP、HSTS）

#### 6. 信息安全风险管理

##### 6.1 风险评估
- 资产识别与赋值
- 威胁分析
- 脆弱性识别
- 风险计算（矩阵法）
- 风险处置策略

##### 6.2 安全管理体系
- ISO 27001体系
- 等级保护2.0
- 安全管理制度建设
- 人员安全管理

---

## NISP三级（专家级）

NISP三级分多个专业方向，渗透测试相关重点方向：

### NISP-PT（渗透测试方向）

#### 1. 渗透测试方法论

##### 1.1 PTES渗透测试标准
- 前期交互
- 情报收集
- 威胁建模
- 漏洞分析
- 渗透攻击
- 后渗透
- 报告

##### 1.2 OWASP测试指南
- 信息收集
- 配置管理测试
- 身份认证测试
- 授权测试
- 会话管理测试
- 输入验证测试
- 错误处理测试
- 加密传输测试
- Web服务测试
- 客户端测试

##### 1.3 Kali Linux渗透测试平台
- 信息收集工具（nmap、masscan、Recon-ng）
- 漏洞扫描（Nessus、OpenVAS、Nuclei）
- 漏洞利用（Metasploit、sqlmap）
- 密码攻击（John、Hydra、Hashcat）
- 无线攻击（aircrack-ng）
- Web渗透（Burp Suite、OWASP ZAP）
- 逆向工程（IDA Pro、Ghidra）

#### 2. 信息收集技术

##### 2.1 OSINT开源情报
- 域名信息收集（Whois）
- 子域名枚举（subfinder、Amass）
- IP信息收集
- 技术栈识别（Wappalyzer、WhatWeb）
- 历史快照（Wayback Machine）
- 邮箱收集（theHarvester）

##### 2.2 网络扫描
- 主机发现（ICMP扫描、ARP扫描）
- 端口扫描（全连接、半连接、SYN、UDP）
- 服务识别
- 操作系统指纹识别
- 漏洞扫描与验证

#### 3. Web渗透测试

##### 3.1 靶场与实验室
- DVWA（Damn Vulnerable Web App）
- WebGoat
- HackTheBox
- VulnHub
- CTFHub

##### 3.2 漏洞利用深度

###### SQL注入
- MySQL注入（UNION、布尔、时间盲注）
- MSSQL注入（xp_cmdshell、OOB）
- Oracle注入
- 报错注入原理
- SQLMAP深入使用

###### XSS深入
- XSS绕过过滤（大小写、编码、多重混合）
- XSS Framework（BeEF）
- XSS蠕动
- HTTPOnly绕过
- CSP Bypass

###### CSRF
- Token绑定机制
- CSRF Bypass
- JSON Request
- Flash CSRF

###### 文件上传
- MIME绕过
- 扩展名绕过（.php5、.phtml）
- 内容绕过（图片马、竞争上传）
- .htaccess/apache/nginx配置利用
- 解析漏洞（00截断、ASP %u伪编码）

###### SSRF
- 内部服务探测
- Redis/FTP/MySQL等协议利用
- Gopher协议利用
- URL Bypass

###### XXE
- XML外部实体注入
- Blind XXE
- XXE OOB读取文件

###### 反序列化
- PHP反序列化（魔法函数）
- Java反序列化（Apache Commons Collections）
- Python pickle反序列化
- 漏洞利用链构建

##### 3.3 业务逻辑漏洞
- 越权操作（水平/垂直）
- 条件竞争
- 验证码绕过
- 支付漏洞
- 密码找回漏洞

#### 4. 内网渗透

##### 4.1 网络嗅探与欺骗
- ARP欺骗
- DNS欺骗
- 中间人攻击
- Wireshark/Tcpdump抓包分析

##### 4.2 网络协议攻击
- SMB协议攻击
- NetBIOS攻击
- LLMNR/NBT-NS欺骗
- Kerberos认证攻击
- Pass The Hash

##### 4.3 域渗透
- Active Directory枚举
- 域权限维持（黄金票据、白银票据）
- 域横向移动
- DCSync攻击
- BloodHound分析

##### 4.4 持久化控制
- 操作系统后门
- Webshell管理（冰蝎、哥斯拉、蚁剑）
- 端口复用
- Rootkit基础

#### 5. 溢出与逆向

##### 5.1 缓冲区溢出
- 栈溢出原理
- 堆溢出
- SEH覆盖
- ASLR/DEP绕过
- ROP（Return-Oriented Programming）

##### 5.2 逆向工程基础
- 汇编语言（x86/x64）
- 反汇编工具（IDA Pro、Ghidra、Radare2）
- 动态调试（OllyDbg、x64dbg、GDB）
- 软件壳识别与脱壳

#### 6. 无线网络安全

##### 6.1 无线协议安全
- WiFi加密（WEP、WPA、WPA2、WPA3）
- WPA2握手捕获与暴力破解
- KRACK攻击
- 恶意热点攻击

##### 6.2 蓝牙安全
- 蓝牙扫描与枚举
- 蓝牙协议漏洞

#### 7. 渗透报告编写

##### 7.1 报告结构
- 执行概要
- 渗透范围与方法
- 发现漏洞详情（CVSS评分）
- 漏洞利用过程
- 风险评级与建议

##### 7.2 漏洞验证标准
- PoC编写规范
- 影响评估
- 修复建议

---

## NISP三级 其他专业方向

### NISP-D（安全运维方向）
- 安全运营中心（SOC）建设
- SIEM日志分析
- 入侵检测与防御（IDS/IPS）
- 流量分析与异常检测
- 安全自动化响应（SOAR）

### NISP-S（安全软件开发方向）
- 安全开发生命周期（SDL）
- 代码审计
- 威胁建模
- 安全编码规范
- 第三方组件安全

### NISP-IS（应急响应方向）
- 应急响应流程
- 数字取证技术
- 恶意代码分析
- 溯源分析
- 事件调查与报告

---

## 附录：认证衔接

### NISP与CISP衔接
- NISP二级 → CISP免培训（需工作经验）
- NISP三级 → 对应CISP专业方向认证

### 相关认证对比
| 认证 | 机构 | 方向 |
|------|------|------|
| CISP | 中国信息安全测评中心 | 综合安全 |
| CISP-PTE | 中国信息安全测评中心 | 渗透测试 |
| CISP-A | 中国信息安全测评中心 | 审计 |
| CISSP | (ISC)² | 信息安全 |
| OSCP | Offensive Security | 渗透测试 |
| CEH | EC-Council | 伦理黑客 |

---

## 学习资源推荐

### 书籍
- 《Web应用安全权威指南》
- 《Web前端黑客技术揭秘》
- 《黑客攻防技术宝典：Web实战篇》
- 《Metasploit渗透测试指南》
- 《内网安全攻防：渗透测试实战》
- 《逆向工程核心原理》

### 在线平台
- HackTheBox
- TryHackMe
- VulnHub
- CTFHub
- 攻防世界
- 掌控者安全教育平台

### 工具集
| 阶段 | 工具 |
|------|------|
| 信息收集 | Nmap、Masscan、Subfinder、Amass、Recon-ng |
| 漏洞扫描 | Nessus、OpenVAS、Nuclei、Xray |
| Web渗透 | Burp Suite、SQLMAP、Dirbuster、蚁剑、冰蝎 |
| 密码攻击 | Hashcat、John、Hydra |
| 流量分析 | Wireshark、Tcpdump |
| 逆向分析 | IDA Pro、Ghidra、Radare2 |
| 域渗透 | BloodHound、Mimikatz、Impacket |

---

*笔记整理完毕，建议结合靶场实战加深理解。*
