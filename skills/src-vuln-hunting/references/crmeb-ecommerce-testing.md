# CRMEB 电商系统测试模式 (2026-05-28 华中农业大学实战)

## 指纹识别
- Server: Tengine (阿里云)
- Set-Cookie: `PHPSESSID`, `cb_lang=zh-cn`
- 前端: Nuxt.js SSR (Vue)
- 后端: PHP
- 管理后台: `/admin/` (Vue SPA, 含 manifest.json)
- 关键字: `CRMEB 新零售社交电商`

## 高价值未授权API端点

```bash
# 商品列表(含价格/库存/图片/分类)
curl -sk 'https://TARGET/api/products'
# 返回: {"status":200,"msg":"success","data":[{"id":64,"store_name":"xxx","price":"6.90","stock":2000,...}]}

# 商品分类树(含图片URL)
curl -sk 'https://TARGET/api/category'
# 返回: {"status":200,"data":[{"id":3,"cate_name":"粮油调味","children":[...]}]}

# 验证码配置(泄露bcrypt hash key!)
curl -sk 'https://TARGET/api/verify_code'
# 返回: {"status":200,"data":{"key":"$2y$10$HASH","expire_time":"5"}}

# 团购数据
curl -sk 'https://TARGET/api/pink'

# 用户信息(需登录)
curl -sk 'https://TARGET/api/user'
# 返回: {"status":401,"msg":"请登录"}
```

## CORS漏洞模式

CRMEB 默认CORS配置反射任意Origin + Credentials:true:

```bash
curl -sk -D- 'https://TARGET/api/products' -H 'Origin: https://evil.com'
```

响应头:
```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Headers: Authori-zation,Authorization, Content-Type, ...
Access-Control-Allow-Methods: GET,POST,PATCH,PUT,DELETE,OPTIONS,DELETE
Access-Control-Max-Age: 1728000
Access-Control-Allow-Credentials: true
```

注意: `Authori-zation` 和 `Invalid-zation` 是CRMEB特有的自定义header名(防CSRF)。

## 管理后台
- 路径: `/admin/` (Vue SPA)
- 静态资源: `/admin/system_static/js/app.*.js`, `/admin/system_static/css/app.*.css`
- 含 manifest.json (PWA配置)

## 攻击面评估

### 高价值
- CORS反射 + 已登录用户 → 可跨域读取用户订单/地址/个人信息
- /api/verify_code 泄露 bcrypt hash key → 离线破解风险

### 中价值
- /api/products 未授权访问 → 商品数据泄露(通常为公开数据，价值有限)
- /api/category 未授权访问 → 分类结构泄露

### 低价值
- /admin/ SPA 可访问 → 需进一步测试后端API是否鉴权

## 报告角度
- 主报告: "xxx系统存在CORS配置不当漏洞致跨域数据窃取风险" [中危]
- 若有认证态测试: 证明CORS可跨域读取用户敏感数据 → 升级高危
- verify_code key泄露: 单独提交价值有限，作为CORS报告的补充证据

## 已知CRMEB版本
- CRMEB JAVA版 (Spring Boot + Vue)
- CRMEB PHP版 (ThinkPHP/Laravel + Vue) — shop.hzau.edu.cn 使用此版本

## 实战记录
- hzau.edu.cn shop.hzau.edu.cn: Tengine + PHP, CORS反射, /api/products未授权, /api/verify_code hash key泄露
