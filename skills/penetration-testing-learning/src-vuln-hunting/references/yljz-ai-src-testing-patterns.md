# 原力金智(YLJZ) AI SRC 测试模式 (2026-05-28)

## 目标范围
- 核心业务: api.yljz.com, api-idn.yljz.com (返回404, 需认证)
- 普通业务: www.yljz.com (FinAuth), aidoc-console.yljz.com (FinDocx)
- 一般业务: 其他yljz.com域名

## 资产清单 (10子域)
| 域名 | IP/CDN | 状态 | 说明 |
|------|--------|------|------|
| global.yljz.com | Tengine | 200 | 国际官网(FinAuth+FinDocX) |
| account-global.yljz.com | - | 301→200 | OAuth2账户系统(ORY Hydra) |
| aidoc-console-global.yljz.com | - | 301→200 | FinDocX控制台 |
| aidoc-global.yljz.com | nginx | 404 | FinDocX API |
| api.yljz.com | 阿里云WAF | 404 | 核心API(受保护) |
| api-idn.yljz.com | - | 404 | IDN API(受保护) |
| assets*.yljz.com | 阿里云OSS | 403 | 静态资源 |
| email.yljz.com | Mailgun | CNAME | 邮件服务 |
| ws.yljz.com | bjpub01 | A | WebSocket端点 |

## 技术栈
- CDN: 阿里云CDN (Tengine)
- WAF: 阿里云WAF (acw_tc cookie)
- 存储: 阿里云OSS (北京+新加坡)
- 认证: OAuth2 (ORY Hydra)
- 邮件: 飞书(mx1/2/3.feishu.cn) + Mailgun
- 前端: React SPA (webpack)
- AI: 旷视科技FaceID
- 联系人: Artibot.ai (chatbot)

## 已确认漏洞

### 1. 无DMARC记录 (中危)
```bash
dig @8.8.8.8 +short _dmarc.yljz.com TXT  # 空=无记录
dig @8.8.8.8 +short yljz.com TXT          # SPF存在
```
- SPF: `v=spf1 +include:_netblocks.m.feishu.cn include:mailgun.org -all`
- DKIM: 无(selector检查均超时/空)
- 影响: 可伪造@yljz.com邮件进行钓鱼

### 2. 订阅API无速率限制 (低危)
```bash
# 连续10次全部成功, 无验证码
for i in $(seq 1 10); do
  curl -sk -X POST "https://yljz.com/api/official/outer/subscribe" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"test${i}@example.com\",\"newsletter\":true}"
done
```

## 关键API端点

### account-global.yljz.com (ORY Hydra OAuth2)
```
GET  /v1/captcha?endpoint=register    # 获取注册验证码(biz_id+image_base64)
GET  /v1/captcha?endpoint=login       # 获取登录验证码
POST /v1/register                     # 注册(需biz_id+image_code)
POST /v1/login                        # 登录(需biz_id+image_code)
GET  /v1/check_login_status           # 检查登录状态(需login_challenge)
POST /v1/reset_password               # 重置密码
POST /v1/bind_phone                   # 绑定手机
GET  /api/v1/jump_login               # 跳转登录(302→OAuth2 auth)
```

**OAuth2配置:**
- client_id: YLJZ (主账户), Findocx (FinDocX)
- response_type: code
- scope: openid+offline+profile
- redirect_uri白名单校验严格(外部域/子域均被拒)
- 错误响应: `redirect_uri does not match any of the OAuth 2.0 Client's pre-registered redirect urls`

### aidoc-console-global.yljz.com (FinDocX)
```
GET  /api/findocx/console/account/info      # 401 LOGIN_EXPIRED
POST /api/findocx/console/account/oauth_login   # 302(重定向)
POST /api/findocx/console/account/oauth_register # 302(重定向)
```

### aidoc-global.yljz.com (FinDocX API)
```
POST /anydoc/v1/extract  # 需api_key+api_secret参数
# 无凭据: {"error_message":"MISSING_ARGUMENTS: api_key"}
# 错误凭据: {"error_message":"AUTHENTICATION_ERROR"}
```

### global.yljz.com (FaceID后端)
```
GET /globalapi/                          # Face++首页(9128 bytes)
GET /globalapi/login                     # FaceID登录页(1445 bytes)
GET /globalapi/accounts/*                # 401 {"redirect_url":"/login"}
GET /globalapi/ip/country                # IP地理信息(无需认证)
GET /globalapi/user/login                # 405 Method Not Allowed
POST /api/official/outer/subscribe       # 订阅(无速率限制)
```

### 受保护API (存在但需认证)
```
/faceid/v1, /faceid/v2                   # 403 (44945 bytes WAF页)
/generalocr                              # 403
/api/faceid, /api/ocr, /api/v1/faceid   # 403
```

## JS分析发现

### 配置模块 (module 2)
```javascript
{
  baseUrl: "https://global.yljz.com",
  zhBaseUrl: "https://yljz.com",
  contactUrl: "https://yljz.com/api",
  findocxUrl: "https://aidoc-console-global.yljz.com",
  findocxLogin: "https://aidoc-console-global.yljz.com/api/findocx/console/account/oauth_login?locale=",
  findocxRegister: "https://aidoc-console-global.yljz.com/api/findocx/console/account/oauth_register?locale="
}
```

### 注册页JS关键发现
- 验证码endpoint参数: `endpoint:"register"` / `endpoint:"login"`
- biz_id从验证码响应获取
- 注册参数: `{username, password, email, biz_id, image_code}`
- 用户名规则: 6-20位字母或数字, 不可纯数字
- 密码规则: 8-16位字母/数字/符号最少两种

## 测试限制
- 核心API(api/api-idn)返回404, 需VPN/内网
- 注册需图形验证码(自动化困难)
- 阿里云WAF对敏感路径拦截(405)
- 无测试账号无法测试业务逻辑漏洞

## 深挖方向
1. 申请测试账号 → IDOR/越权/业务逻辑
2. FinDocX api_key认证机制逆向
3. WebSocket端点(ws.yljz.com)测试
4. Mailgun配置审计(子域mailgun配置)
5. FaceID API认证绕过
