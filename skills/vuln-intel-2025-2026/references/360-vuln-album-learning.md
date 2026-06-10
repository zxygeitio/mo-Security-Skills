# 360漏洞研究院专辑学习笔记 (209篇)

## 来源
- 微信公众号: 360漏洞研究院
- 专辑: 漏洞风险通告 (209篇)
- 学习时间: 2026-06-10
- 镜像: cn-sec.com (可直接提取)

## 高价值漏洞清单 (按时间倒序)

### 1. CVE-2026-40519 - Nginx Proxy Manager 命令注入
- CVSS: 7.7, 已认证RCE
- 影响: 2.9.14 ~ 2.15.1
- 原理: backend/setup.js → setupCertbotPlugins() → dns_provider_credentials 直接拼入 child_process.exec()，无转义
- 利用: 管理员创建DNS证书时注入payload，以root权限执行任意命令
- 默认凭据: admin@example.com/changeme
- 修复: 升级 > 2.15.1 或从 develop 分支编译

### 2. CVE-2025-47981 - Windows NEGOEX 蠕虫级RCE
- CVSS: 9.8 严重！堆缓冲区溢出
- 无需认证、无需用户交互、可远程触发
- 影响: SPNEGO扩展协商协议, SMB(445)/RDP(3389)/RPC(135)
- 蠕虫级: 可在未打补丁系统间自动传播
- 缓解: 禁用 PKU2U 认证

### 3. CVE-2025-33053 - Windows WebDAV RCE (在野利用)
- 已被APT组织武器化，PoC已公开
- 强制设备从恶意WebDAV服务器远程执行代码，无需本地落地文件

### 4. CVE-2025-5120 - smolagents AI智能体沙箱逃逸RCE
- CVSS: 9.8, Hugging Face smolagents 1.14.0
- local_python_executor.py 沙箱绕过，通过内置函数访问受限模块

### 5. 微信Windows客户端 目录穿越+RCE
- 影响: 微信 3.9 及以下版本
- 攻击链: 发送恶意文件→自动下载→目录穿越到启动目录→开机自启动→RCE
- 用户无感知

### 6. SonicWall SMA 100 多漏洞 (CVE-2025-40596/97/98)
- 全部认证前漏洞，无需凭据
- 栈溢出/堆溢出/XSS

### 7. CVE-2025-6514 - mcp-remote OAuth代理RCE
- 影响超43万环境，窃取API key/云凭据

## 2025-2026 漏洞趋势

1. **命令注入仍主流**: NPM/Gogs/DataEase 因拼接用户输入到 exec()
2. **AI Agent新攻击面**: smolagents沙箱逃逸/mcp-remote OAuth劫持
3. **蠕虫级漏洞回归**: NEGOEX CVSS 9.8 无需认证自动传播
4. **国产软件高危**: 用友U8Cloud/泛微E-cology9/契约锁频繁未授权RCE/SQLi
5. **在野利用加速**: WebDAV漏洞已被APT武器化
6. **认证前漏洞占比高**: SonicWall 3个漏洞全部无需凭据
7. **客户端攻击复苏**: 微信目录穿越+RCE，用户无感知
