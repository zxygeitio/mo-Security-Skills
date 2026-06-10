---
name: penetration-testing-learning
description: >-
  渗透测试系统学习路径 — 聚合侦察、漏洞利用、CTF、报告等子技能的学习型 bundle，
  强调实际 CVE/exploit 验证而非版本指纹匹配，并衔接 NISP/CISP/OSCP 知识体系。
---
# Penetration Testing Learning Path

## 核心原则 (2026-05-04 用户强调)
- **不追求快，追求准确**: 不要只做指纹识别，要实际利用CVE/exploit验证
- **寻找最新漏洞特征**: 关注最新CVE和POC包，不接受版本匹配作为漏洞证明
- **多工具验证**: 指纹+CVE+nuclei+searchsploit+手动验证多管齐下
- **实际危害**: 必须能证明真实危害，不是理论上的漏洞

## 环境信息
- Kali 2026.1, IP: 192.168.110.137, Docker运行中
- 项目: PentAGI (~/pentagi/), HexStrike AI (~/hexstrike-ai/)

## 学习计划

### NISP 学习路径
详细笔记见 `references/nisp_study_notes.md`，涵盖：
- NISP一级（基础级）：信息安全基本概念、法律法规、管理基础、基本技能
- NISP二级（专业级）：密码学、操作系统安全、数据库安全、Web安全、风险管理
- NISP三级（专家级）：渗透测试（PT）、安全运维（D）、应急响应（IS）等方向
- 认证衔接：NISP与CISP/OSCP/CEH对比
- 学习资源：书籍、靶场平台、工具集

### 阶段1: 环境准备 (完成)
- [x] 安装 nuclei, dalfox, gdb, checksec
- [ ] 安装其他缺失安全工具 (rustscan, dirsearch等)
- [ ] 配置 PentAGI 可观测性栈
- [ ] 用户手动配置 LLM API (不使用Ollama)

#### 安装方法 (2026-04-22 补充)
**gdb/checksec:** `apt-get install -y gdb checksec`
**nuclei/dalfox/subfinder/httpx/naabu/shuffledns/dnsx/amass:** 先 `apt-get install -y golang-go`，然后 go install：
```
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/hahwul/dalfox/v2/cmd/dalfox@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/owasp-amass/amass/v3/...@latest
export PATH=$PATH:/root/go/bin  # 加入 ~/.bashrc
```
**rustscan:** 需要先 `apt-get install -y cargo`（Rust 工具链），然后 `cargo install rustscan`，安装在 `/root/.cargo/bin/rustscan`
**dirsearch:** `git clone https://github.com/maurosoria/dirsearch.git /tmp/dirsearch && ln -sf /tmp/dirsearch/dirsearch.py /usr/local/bin/dirsearch`
**ffuf/gobuster:** `apt-get install -y gobuster ffuf`（ffuf 也可用 go install）
**HexStrike 需要重启** 以检测新安装的工具: `pkill -f hexstrike_server.py` 然后 `cd ~/hexstrike-ai && source hexstrike-env/bin/activate && python hexstrike_server.py &`

#### dpkg 损坏修复
如果 `apt-get install` 报 `dpkg was interrupted` 错误：
```
DEBIAN_FRONTEND=noninteractive dpkg --configure -a
apt-get install -fy
```
不要用交互式 whiptail/prompt，用 noninteractive mode 强制完成。系统高负载时避免同时 apt/pip/Go 编译。

#### 常见坑 (2026-04-22 发现 / 更新)

**HexStrike 工具健康检查机制:**
- Health check 执行 `which X` 对每个工具，所有 Go/pip 安装的 binaries 建议做符号链接到 `/usr/local/bin/`
- Health check 结果被服务器缓存，**每次安装新工具后必须重启 HexStrike** 才能更新状态
- 重启后工具数会明显增加（如 76→80），是因为缓存刷新
- **无需重启也能刷新：直接调用 `curl -X POST http://127.0.0.1:8888/api/cache/clear` 清理工具缓存**，然后 `curl http://127.0.0.1:8888/health` 验证

**符号链接清单（2026-04-22 确认需要）：**
```
/usr/local/bin/exploit-db     → /usr/bin/exploitdb
/usr/local/bin/shodan-cli     → /usr/bin/shodan
/usr/local/bin/volatility3    → /usr/local/bin/vol  (vol 是 volatility3 的 pip CLI)
/usr/local/bin/metasploit    → /usr/bin/msfconsole
/usr/local/bin/sherlock       → /usr/bin/sherlock
/usr/local/bin/searchsploit  → /usr/bin/searchsploit
/usr/local/bin/bulk-extractor → /usr/bin/bulk_extractor  (apt包的下划线版本)
/usr/local/bin/Stegsolve.jar → (JAR文件本身，Java运行)
/usr/local/bin/stegsolve     → /usr/local/bin/Stegsolve.jar
```
hashcat-utils 的所有 .bin 文件：`ln -sf /usr/lib/hashcat-utils/*.bin /usr/local/bin/`
sleuthkit 无主命令，创建 wrapper `/usr/local/bin/sleuthkit` 调用 `mmls`/`fls`/`icat`

**pip 安装后 CLI wrapper 缺失:**
- `one-gadget` pip 包只安装 Python module，无 CLI 命令。创建 wrapper：
  ```
  cat > /usr/local/bin/one-gadget << 'EOF'
  #!/usr/bin/python3
  import sys
  from one_gadget import main
  sys.exit(main())
  EOF
  chmod +x /usr/local/bin/one-gadget
  ```
- `social-analyzer`: `pip install social-analyzer --break-system-packages`，提供 CLI `snscrape`（注意：安装的是 `snscrape` 不是 `social-analyzer`）
- `volatility3` pip 包提供了 `vol` CLI 但没有 `volatility3` 命令：
  `ln -sf /usr/local/bin/vol /usr/local/bin/volatility3`
- `bulk-extractor` apt 包安装的二进制是 `bulk_extractor`（下划线），需要：
  `ln -sf /usr/bin/bulk_extractor /usr/local/bin/bulk-extractor`

**pip 依赖冲突:**
- `angr` 与 debian 的 `mpmath` 冲突：`Cannot uninstall mpmath 1.4.1, no RECORD file found`
  解决：`pip install angr --break-system-packages --force-reinstall`
  注意：大量依赖安装耗时，可能超时
- `trivy` Go 打包方式变化，最新版需要 `encoding/json/v2`，Go 1.26 不支持

**apt 包名与命令名不同:**
- `sleuthkit`: 提供 `mmls`, `fls`, `tsk_recover` 等命令，但 `which sleuthkit` 返回空
- `autopsy`: 安装为 `/usr/bin/autopsy`
- `metasploit-framework`: 提供 `msfconsole`, `msfvenom`, `msfdb` 等

**GitHub 下载被 block / 限速:**
- `trivy` 下载返回 9 字节 HTML 错误页（不是 0 字节），工具安装在 /tmp 失败
- Go install 对 github.com 某些子包路径格式有要求：`go install github.com/aquasecurity/trivy/cmd/trivy@v0.57.0` 而非 `go install github.com/aquasecurity/trivy@v0.57.0`
- GitHub 网络受限时，直接 `curl https://github.com/...` 返回 0-9 字节文件，wget 同样
- **stegsolve**: 从 `https://github.com/e1r0nd/Stegsolve` 下载 JAR（不是 caesum.com 等其他源），Java 运行需要：`java -jar /usr/local/bin/Stegsolve.jar`
- Cloud 安全工具（trivy、checkov、prowler、scout-suite、clair、falco、kube-hunter、kube-bench、docker-bench-security、terrascan）全部因 GitHub 阻塞无法安装，暂无替代方案
- **nuclei templates 空目录问题（2026-04-22）**：
- GitHub网络受限时，`~/nuclei-templates/` 目录存在但为空
- 运行 `nuclei -l targets.txt` 报错: `[FTL] Could not run nuclei: no templates provided for scan`
- 临时解决方案：无（需等待GitHub网络恢复）
- 建议：使用 ffuf + 自定义字典进行目录爆破作为替代方案

**ffuf 后台运行警告（可忽略）**：
```
bash: 无法设定终端进程组 (-1): 对设备不适当的 ioctl 操作
bash: 此 shell 中无任务控制
```
- 这是容器/无tty环境的正常警告，不影响ffuf后台运行
- ffuf进程仍会正常执行，结果会写入输出文件

**Kali 缺少的工具（2026-04-22 状态）:**
已安装: zaproxy, dotdotpwn, xsser, paramspider, maltego, sherlock, autorecon, feroxbuster, bulk-extractor, stegsolve(Stegsolve.jar), ropper, one-gadget, httpie, uro, social-analyzer, gau
仍缺失（GitHub阻塞）: outguess, trivy, checkov, prowler, scout-suite, clair, falco, kube-hunter, kube-bench, docker-bench-security, terrascan, x8, jaeles, hakrawler, graphql-scanner, api-schema-analyzer, have-i-been-pwned

**Go 工具路径问题:**
- nuclei/dalfox/subfinder 等 `go install` 安装到 `/root/go/bin/`，不在 `/usr/local/bin/`
- Health check 的 `which` 可能找不到，建议：
  `ln -sf /root/go/bin/nuclei /usr/local/bin/nuclei`

**系统高负载时 HexStrike 无响应:**
- curl --max-time 30 http://127.0.0.1:8888/health 会超时 30s，但服务进程本身正常，重启服务可缓解

**PentAGI Neo4j 密码:**
- .env 中 `NEO4J_PASSWORD` 值不能包含被截断的 `***` 字符，正确格式为 `NEO4J_AUTH=neo4j/<password>`

**dpkg 损坏修复:**
如果 `apt-get install` 报 `dpkg was interrupted` 错误：
```
DEBIAN_FRONTEND=noninteractive dpkg --configure -a
apt-get install -fy
```
不要用交互式 whiptail/prompt，用 noninteractive mode 强制完成。

### 阶段2: 网络渗透
- [ ] nmap 高级扫描 (NSE脚本)
- [ ] masscan 高速扫描
- [ ] ffuf/gobuster 目录爆破
- [ ] nikto Web漏洞扫描

### CAS/LYUAP统一认证平台深度渗透 (2026-05-04 实测)
**适用场景**: 高校/企业常见灵雀云(lyuapServer)统一认证平台，基于Shiro框架。

**CAS系统识别特征**:
- Server头: nginx/Apache + 自定义
- 登录路径: `/lyuapServer/v1/tickets`, `/auth/login`, `/checkAccount`
- JS泄露: 前端app.xxx.js (可达数百KB)包含完整API端点列表
- API前缀: `/lyuapServer`, `/api/uap`
- 第三方登录: QQ/钉钉/微信/OAuth/指纹/扫码

**lyuapServer API端点 (从JS提取)**:
```
认证:
- POST /lyuapServer/v1/tickets        # TGT票据，参数username/password
- POST /lyuapServer/login             # JSON格式登录
- POST /auth/login, POST /auth/logout # 认证登出
- GET  /login/pwStrategy             # 密码策略

第三方登录:
- /qq/login, /dingding/login, /wechat/login, /finger/login
- /oauth2/code, /cam/v1/MMDLQrCode   # OAuth和扫码

验证码:
- POST /login/mobile/generateCode    # 手机验证码
- POST /login/email/generateCode     # 邮箱验证码

其他:
- POST /checkAccount                  # 账户检查
- GET  /kaptcha                      # 验证码
```

**测试流程**:
```bash
# 1. 识别CAS入口
curl -sk -I https://cas.target.edu.cn/ | grep -E "server|set-cookie"

# 2. 下载JS源码进行API枚举
curl -sk "https://cas.target.edu.cn/assets/js/app.xxx.js" -o /tmp/cas_app.js
grep -oP '"/[a-zA-Z0-9/_-]+"' /tmp/cas_app.js | sort -u

# 3. 测试TGT票据申请 (注意需要POST表单，非JSON)
curl -sk -X POST "https://cas.target.edu.cn/lyuapServer/v1/tickets" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test"
# 成功响应包含TGT，失败返回CODEFALSE

# 4. 用户枚举测试 (lyuapServer可能通过CODEFALSE区分用户是否存在)
# 注意: 需要确定正确的参数格式，错误格式会返回500

# 5. 第三方登录接口探测
curl -sk "https://cas.target.edu.cn/qq/qqLoginURL"
curl -sk "https://cas.target.edu.cn/dingding/dingdingLoginURL"
```

**CAS系统常见路径结构**:
```
/lyuapServer/v1/tickets        # 核心认证API
/lyuapServer/login             # JSON登录
/auth/login, /auth/logout     # 认证
/cas/login, /cas/logout       # 标准CAS
/oauth2/code                   # OAuth2
/cam/v1/MMDLQrCode            # 扫码登录
/login/pwStrategy              # 密码策略
/login/mobile/generateCode    # 手机验证码
/login/email/generateCode     # 邮箱验证码
/checkAccount                  # 账户检查
/kaptcha                       # 验证码
```

**高校CAS子系统**:
- jwc (教务处), cwc (财务处), rsc (人事处), tsg (图书馆)
- /system/index.jsp 需要登录
- /info/index.jsp 需要登录

**已知问题**:
- WAF拦截: 备份文件/www.zip等返回7957字节HTML WAF页
- API返回CODEFALSE: 表示认证失败，但可能用于用户枚举
- Shiro CVE被WAF阻断: CVE-2020-1957等路径穿越均被拦截

#### OpenVPN Split Tunnel 配置 (2026-04-22 实测)

**目标场景**：渗透测试时需要同时访问：
- 太保内网 IP 段（走 VPN）
- AI API 等公网服务（不走 VPN，保留本地路由）

**关键配置语法**：
```
# 忽略服务器推送的默认网关（不要加引号！否则 tun0 无法创建）
pull-filter ignore redirect-gateway

# 忽略 VPN DNS 推送（保留本地 DNS）
pull-filter ignore "dhcp-option DNS"

# 手动添加需要走 VPN 的内网段
route 101.0.0.0 255.0.0.0
route 103.0.0.0 255.0.0.0
route 112.0.0.0 255.0.0.0
route 116.0.0.0 255.0.0.0
route 121.0.0.0 255.0.0.0
route 180.0.0.0 255.0.0.0
route 58.0.0.0 255.0.0.0
route 182.0.0.0 255.0.0.0

# 排除公网 IP 段不走 VPN（否则会导致部分公网 IP 路由错误）
route 220.0.0.0 255.0.0.0 vpn_gateway 100
```

**常见错误**：
1. `pull-filter ignore "redirect-gateway"` (带引号) → 导致 tun0 无法创建，所有流量异常
2. 正确语法是 `pull-filter ignore redirect-gateway` (无引号)

**验证方法**：
```bash
# 检查 VPN 路由表
ip route | grep tun

# 测试内网是否走 VPN
ping -c 2 <内网IP>

# 测试公网是否走本地（不受 VPN 影响）
curl -I https://api.minimax.chat/

# DNS 应该保持本地
cat /etc/resolv.conf | grep nameserver
```

**太保内网 IP 段参考**（2026-04-22）：
- 101.0.0.0/8 - 多个内网系统
- 103.0.0.0/8 - 部分服务
- 112.0.0.0/8 - 部分服务
- 116.0.0.0/8 - 部分服务
- 182.0.0.0/8 - 部分服务

**内网系统探测发现（2026-04-22）**：
- VPN可达的内网IP：101.204.252.197 (ping正常)、103.230.110.220、182.150.61.109
- 101.204.252.197: 443开放，nmap扫描显示https服务，但curl无响应
- SSL握手失败特征：
  ```
  error:0A000438:SSL routines:ssl3_read_bytes:tlsv1 alert internal error
  ssl3_read_bytes:SSL alert number 80
  ```
  可能原因：服务端要求客户端证书认证，或TLS版本不匹配
- 部分IP (112.64.185.32等) ping丢包但443开放，说明有防火墙过滤ICMP

**公网系统WAF限速现象**：
- www.cpic.com.cn ping正常(51ms)但HTTP请求超时
- 可能是WAF/负载均衡器对源IP限速
- 等待30秒后可能恢复

**内网端口扫描结果（太保101.204.252.197）**：
```
PORT      STATE  SERVICE
25/tcp   filtered smtp
42/tcp   filtered nameserver
53/tcp   filtered domain
69/tcp   filtered tftp
135/tcp  filtered msrpc
139/tcp  filtered netbios-ssn
443/tcp  open     https
445/tcp  filtered microsoft-ds
```
仅443开放，其他端口被防火墙过滤。

### 阶段2补充: WAF行为与IP封锁（2026-04-23）
- 快速扫描/目录爆破会触发WAF封锁，导致该IP无法访问所有太保域名
- 封锁可能是临时性的（几分钟后自动解除）
- 不同子域名可能解析到不同IP段（gtm/gslb），但WAF封锁的是源IP
- 应对：用极低速率（-rl 5）、随机延迟、或挂代理池
- WAF封锁表现：curl返回000（连接建立但无HTTP响应），nuclei报"unresponsive 30 times"

### ROT代理路由发现技术（2026-05-16 实测）
通过对比不同Host header的响应content-length，可以发现ROT代理路由表：
```python
# ROT代理路由发现 - 对比不同Host的content-length
test_hosts = ['www.cpic.com.cn', 'one.cpic.com.cn', 'property.cpic.com.cn', 'api.cpic.com.cn', 'open.cpic.com.cn']
for host in test_hosts:
    # 发送相同请求，对比响应长度
    # 相同长度=相同后端，不同长度=不同后端路由
```
实测发现ROT代理对不同域名返回不同content-length，证明路由不同。

### CPIC太保内网IP段参考（2026-05-16 更新）
通过VPN发现的内网段：
```
58.246.0.0/16    - service.cpic.com.cn及ROT代理
101.204.0.0/16   - SIT环境(onesit.cpic.com.cn)
103.230.0.0/16   - 统一认证/开放平台
103.230.110.x    - 团体险/多个业务系统 (全443开放)
112.64.0.0/16    - 部分服务
116.228.0.0/16   - health.cpic.com.cn
121.28.0.0/16    - 部分服务
180.169.0.0/16   - 部分服务
182.150.0.0/16   - 部分服务
198.18.0.0/16    - 集团主站(ROT代理,WAF保护)
```

### ROT Proxy架构对渗透的影响（2026-05-16 CPIC太保）：
```
发现:
- 198.18.0.120-123 全部是ROT Proxy (不是真实后端)
- one.cpic.com.cn (103.230.111.221) 是ROT Proxy
- service.cpic.com.cn (58.246.171.102) 是ROT Proxy

测试结果:
- CVE-2026-42926 (HTTP/2请求注入): ROT代理无HTTP/2支持 → 无效
- CVE-2026-42945 (Rewrite溢出): 无法直接访问后端 → 无效
- CVE-2024-24989/24990 (HTTP/3 RCE): HTTP/3未启用 → 无效
- WebDAV被ROT代理禁用(403) → CVE-2026-27654无效
```

**应对策略：**
1. 测试ROT代理本身是否有已知CVE（代理软件漏洞）
2. 寻找能绕过ROT代理直接访问后端的方法（Host header端口转发等）
3. 关注ROT代理的配置错误（如Host header注入）
4. 尝试VPN直接路由绕过ROT代理（如果VPN能通达内网）

### ROT代理架构（2026-05-16 CPIC太保实测）

**ROT Proxy架构识别：**
```
用户 → ROT Proxy (SSL终端, O=ROT Proxy) → 真实后端 (WAF保护)
```

**识别特征：**
- TLS握手返回"tlsv1 alert internal error" (alert 80) = 需要客户端证书
- SSL证书 O=ROT Proxy CN=xxx — ROT VPN网关，不是业务系统
- 自签名证书且CN=IP本身 — 大概率代理基础设施
- 同一IP对不同Host header返回不同内容长度 → 反向代理

**ROT Proxy架构下漏洞测试限制：**
- ROT Proxy是SSL终端，真实后端Nginx无法直接访问
- 所有CVE测试必须针对ROT Proxy本身，无法触发后端漏洞
- ROT Proxy可能路由到不同后端（通过Host header区分）
- ROT代理路由发现方法：对比不同Host header的响应content-length

### HTTP/3 协议绕过云WAF/CDN (2026-04-29 实测)
**适用场景**: Akamai CDN、Tencent EdgeOne、阿里云GSRM WAF 保护的系统，`curl` 默认请求被拦截返回 WAF 错误页。

**关键发现**:
```bash
# HTTP/3 请求绕过 CDN 直接连接后端源站
curl --http3 -k "https://target.sheincorp.com/health"

# 对比：
curl -k "https://target.sheincorp.com/health"  # 返回 WAF 拦截页
curl --http3 -k "https://target.sheincorp.com/health"  # 返回源站真实响应
```

**实测效果**:
| 系统 | CDN/WAF | curl默认 | curl --http3 |
|------|---------|----------|-------------|
| open.sheincorp.cn | Akamai | WAF页 | 真实JSON |
| br.sheingsp.com | EdgeOne | WAF页 | 真实JSON |
| ssms.biz.sheincorp.cn | GSRM | WAF页 | 真实业务JSON |
| openapi.sheincorp.com | Akamai | 正常 | 正常 |

**原理**: HTTP/3 (QUIC) 走 UDP 443 端口，CDN/WAF 的 HTTP 过滤规则无法识别，ALT-SVC 头指示客户端直接用 HTTP/3 连接源站。

**限制**:
- 源站必须在 DNS/ALT-SVC 中声明 HTTP/3 支持
- 并非所有 CDN 后的系统都支持 HTTP/3

### SSL证书SAN枚举发现内网系统 (2026-04-29 实测)
**适用场景**: ROT代理背后的内网系统，通过公网域名的SSL证书的Subject Alternative Names发现。

**方法**:
```bash
# 提取目标证书的所有SAN域名
openssl s_client -connect open.sheincorp.cn:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -text \
  | grep -A1 "Subject Alternative Name" \
  | grep -v "Subject Alternative Name"

# 批量处理
for ip in $(cat rot_ips.txt); do
  echo "=== $ip ==="
  openssl s_client -connect $ip:443 </dev/null 2>/dev/null \
    | openssl x509 -noout -text 2>/dev/null \
    | grep -A5 "Subject Alternative Name" | grep "<DNS:"
done
```

**SHEIN实测发现** (2026-04-29):
- `openapi.sheincorp.com` → SAN中包含: openapi-portal.sheincorp.com, ms-us.sheincorp.com, sbn-prod01.sheincorp.com
- `ms-us.sheincorp.com` → Apache APISIX API Gateway
- ROT内网段 198.18.20.x 的SSL证书包含大量内部系统CN

**与crt.sh对比**: crtsh查询可能返回空（被过滤），直接连接提取证书更可靠。

### 漏洞验证核心原则 (2026-04-23 实测教训)
**版本匹配 ≠ 实际可利用**
- 指纹识别只是初筛，必须通过实际exploit验证才能报告
- CVE-2008-3844 (OpenSSH 4.3): 指纹显示版本匹配，但漏洞要求SSH-1协议，目标仅支持SSH-2 → 不可利用
- 海康NVR CVE-2021-36260: PUT请求返回405 Method Not Allowed → 路径不通或已被防护
- Hillstone CVE-2023-42115/42116: 目标无响应超时 → 无法验证

**验证失败不等于安全**:
- 可能是网络不稳定(masscan发现host但实际不通)
- 可能是WAF/IPS过滤了探测流量
- 可能是漏洞已在补丁版本修复但版本号未更新

**正确报告流程**:
1. 指纹识别(版本检测) → 提出假设
2. 实际exploit/验证脚本测试 → 确认/排除
3. 仅报告通过实际验证的漏洞

### 子域名扫描流程
```bash
# 1. 收集
subfinder -d cpic.com.cn -silent -o subs.txt
# 2. 去重
cat subs.txt | sort -u > all_subs.txt
# 3. 批量检测(优先HTTP 80绕过ROT)
for domain in $(cat all_subs.txt); do
  code=$(curl -sI --connect-timeout 2 -o /dev/null -w "%{http_code}" http://$domain/)
  [ "$code" != "000" ] && echo "$code $domain"
done
# 4. ffuf目录爆破（极低速率）
ffuf -u https://target/FUZZ -w wordlist.txt -mc 200,301,302 -t 3
```

### 高校/教育网子域名特征 (2026-05-04 新发现)
```bash
# 常见高校业务系统子域名
OA办公: oa, ehall, ehall2, newoa
教务: jwc, jxpgcp.edu.cn, xsxk
教学: lms, jpkc, jpkca, course
邮件: mail, webmail
招生: zs, zsbm, zsgcp.edu.cn, apply
党建: dangjian
信息: xxgk, ids, idp
移动: my, wap
其他: bm(部门), dj(档案), ky(科研), yx(院系), pg(评估)
```

### FFUF WAF拦截应对 (2026-05-04 实测)
- ffuf扫描时大量 Errors → WAF正在拦截
- 表现: Progress计数器停止增长，Errors持续增加
- 应对: 降低速率 `-t 1`，增加延时，或换用其他系统测试
- nuclei扫描同理，目标不响应时换其他可达系统

### 阶段3: Web渗透
- [ ] SQLMap SQL注入
- [ ] burpsuite 抓包/重放
- [ ] XSS/CSRF 测试

### 阶段4: 密码攻击
- [ ] Hydra 暴力破解
- [ ] John 密码哈希破解
- [ ] Hashcat GPU加速破解

### 阶段5: 权限维持/横向移动
- [ ] msfvenom 生成木马
- [ ] msfconsole 利用
- [ ] 横向移动技术

### 工具速查
```
nmap -sV -sC target        # 版本+默认脚本扫描
masscan --rate=10000 -p1-65535 target  # 高速扫描
ffuf -w wordlist -u target/FUZZ       # Web fuzz
sqlmap -u target --batch --risk=3     # SQL注入
hydra -l user -P pass.txt ssh://target # SSH破解
```
