# 教育CMS API信息泄露模式库

## 模式一: article_edit_ip_kuayu 内网IP泄露

**发现时间**: 2026-05-29 (hnca.edu.cn)
**CMS类型**: 国产教育CMS (疑似"润普/rump"系列)
**泄露字段**: `article_edit_ip_kuayu`

### 触发端点
```
POST /api/login  (任意username/password均可触发)
POST /api/search (任意keyword均可触发)
```

### 响应结构
```json
{
  "code": 0,
  "msg": "验证未通过",
  "site": null,
  "is_change_menu": 0,
  "is_change_user_menu": null,
  "domain_ssl": "https://",
  "domain_url": "www.target.edu.cn",
  "article_edit_ip_kuayu": "http://172.16.2.103"
}
```

### 泄露内容
- `article_edit_ip_kuayu`: 文章编辑服务器内网IP+端口
- `domain_ssl`/`domain_url`: 域名配置
- `is_change_menu`/`is_change_user_menu`: 功能开关状态

### 指纹识别
- Server头: `rump/c` (主站)
- 反代: OpenResty
- SSL证书: 通配符 *.target.edu.cn
- robots.txt中包含 `/system/*` 和 `/fenxiang/*`

### 验证命令
```bash
curl -sk -X POST "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'
```

### 同类目标特征
- 搜索: `intitle:"河南" site:edu.cn inurl:/api/login`
- Server头: `rump/c` 或类似自定义代理
- robots.txt中包含 `/system/*` 路径

### 危害论证
内网IP泄露 → 推断内网网段 → 结合DNS中内网A记录 → 横向渗透前提条件

---

## 模式二: 子域名DNS解析暴露内网IP

**场景**: 内部服务在公网DNS中有A记录指向私有IP
**示例**: foodsec.target.edu.cn → 172.16.2.203

### 验证命令
```bash
dig +short foodsec.target.edu.cn
nslookup foodsec.target.edu.cn
```

### 组合利用
当同时发现多个内网IP时，可推断:
- 内网网段 (如 172.16.2.0/24)
- 活跃主机角色 (编辑服务器、业务系统等)
- 为后续内网渗透提供目标清单

---

## 模式三: .env文件存在但被WAF保护

**场景**: .env返回403(文件存在)而非404(文件不存在)
**验证**: `curl -sk -I "https://TARGET/.env"` → 403 Forbidden

**说明**: 虽然当前被WAF保护，但WAF规则可能被绕过。
报告时标注为"建议性修复"而非直接漏洞。

---

## 模式四: DNS通配符干扰子域名枚举

**发现时间**: 2026-05-29 (hnca.edu.cn)
**场景**: 域名启用了DNS Wildcard，所有不存在子域名解析到ISP劫持IP

### 识别方法
```bash
# 查询不存在的子域名，如果返回非空IP则存在通配符
dig +short doesnotexist12345.hnca.edu.cn
# 返回 198.18.x.x → 通配符生效

# fierce会显示通配符状态
fierce --domain target.edu.cn | grep -i wildcard
```

### 应对策略
1. **过滤ISP劫持IP**: 198.18.x.x / 114.114.114.x 等是常见DNS劫持地址
2. **用真实IP验证**: 已知真实IP用 `dig @真实IP 子域名` 验证
3. **对比DNS服务器**: 用 `8.8.8.8` 和学校自有DNS对比查询
4. **先扫再判**: nmap扫描确认端口开放的IP才是真实IP
5. **--resolve绕过**: `curl --resolve "host:443:真实IP"` 直连真实服务器

### DNS配置分析
```bash
dnsrecon -d target.edu.cn  # 获取SOA/NS/MX/TXT记录
# 关注:
# - NS服务器是否递归查询已启用 (安全隐患)
# - DNSSEC是否配置
# - MX是否使用第三方邮件(如腾讯企业邮箱mxbiz1.qq.com)
```

---

## 模式五: 教育平台DES弱加密+前端密钥泄露

**发现时间**: 2026-05-29 (xljk.hnca.edu.cn 心理健康平台)
**场景**: 登录页面使用DES加密密码，密钥硬编码在前端JS

### 识别特征
- 登录页面引用 `des.js` 文件
- 表单调用 `strEnc(data, key1, key2, key3)` 加密
- URL模式: `/user/login.do`, `/loginVerify.do`
- 多见于: 心理健康平台、教务系统、老旧OA

### 验证命令
```bash
# 获取DES JS文件
curl -sk "http://target/user/jsxlyCommon/des.js"

# 获取登录页面，检查加密调用
curl -sk "http://target/user/login.do" | grep -i "strEnc\|des\|encrypt"

# 登录接口测试
curl -sk -X POST "http://target/loginVerify.do" \
  -d "name=admin&pwd=test&hp="
```

### 危害
- DES密钥56位，可暴力破解
- 密钥在前端JS中硬编码，直接可获取
- 所有用户密码传输可被解密

---

## 模式六: 目标IP封锁/WAF触发检测

**场景**: 大量扫描后目标对攻击者IP进行封锁

### 识别信号
- curl返回空响应或code:000
- SSL握手失败 (unexpected eof while reading)
- DNS从真实IP切换到ISP劫持IP (198.18.x.x)
- 之前可达的服务突然全部Connection Reset

### 应对策略
1. **降低扫描强度**: 减少并发，增加延时
2. **切换User-Agent**: 使用正常浏览器UA
3. **使用代理**: 通过不同出口IP继续测试
4. **被动信息收集**: 切换到Wayback Machine、crt.sh等被动源
5. **等待解封**: 教育网WAF通常IP封锁有时间限制(30min~2h)

### 被动信息源
```bash
# Wayback Machine - 历史URL和API端点
curl -sk "https://web.archive.org/cdx/search/cdx?url=*.target.edu.cn/api/*&output=text&fl=original&collapse=urlkey&limit=50"

# crt.sh - 证书透明度日志中的子域名
curl -sk "https://crt.sh/?q=%.target.edu.cn&output=json" | python3 -c "..."

# Whois - IP归属和网段信息
whois 61.163.83.34 | grep -iE "netname|descr|country"
```

---

## 通用测试流程

1. **API端点枚举**: 测试 `/api/login`, `/api/search`, `/api/user`, `/api/config` 等
2. **POST方法测试**: 许多信息泄露仅在POST请求中触发
3. **响应字段审查**: 关注非业务字段 (ip, config, debug, internal等)
4. **DNS记录检查**: 所有子域名的A记录，识别内网IP
5. **robots.txt分析**: 识别敏感目录结构
6. **DNS通配符检测**: 先用随机子域名判断是否启用通配符
7. **被动信息收集**: crt.sh + Wayback Machine 在主动扫描前后都要做
