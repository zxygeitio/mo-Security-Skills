# CRMEB 电商系统测试模式 (2026-05-28 成都理工/华中农实战)

## 指纹识别
- Server: Tengine + PHP (PHPSESSID cookie)
- HTML: `<meta name="keywords" content="CRMEB 新零售社交电商"`
- 后台: `/admin/` (Vue SPA, /admin/system_static/js/app.*.js)
- API前缀: `/api/`

## 已确认未授权端点 (无需登录)
```
GET /api/products → 商品列表(id/store_name/price/stock/image/cate_id/spec_type)
GET /api/category → 分类树(id/cate_name/pic/children)
GET /api/pink → 团购数据(pink_count/avatars)
GET /api/verify_code → 验证码配置(bcrypt key + expire_time)
```

## CORS 配置缺陷
CRMEB 默认 CORS 配置反射任意 Origin + Credentials:true:
```
Access-Control-Allow-Origin: https://evil.com  (反射)
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET,POST,PATCH,PUT,DELETE,OPTIONS,DELETE
```

**报告角度**: 需要证明已登录用户的敏感数据可被跨域读取。仅公开商品数据的CORS价值有限。
**关键**: /api/user 返回 `{"status":401,"msg":"请登录"}` — 如果登录态API也反射Origin+Credentials，可升级为中危。

## 需认证端点 (返回401)
- /api/user — 用户信息
- /api/cart — 购物车
- /api/order — 订单
- /api/address — 收货地址
- /api/collect — 收藏
- /api/sign — 签到

## /api/verify_code 泄露
返回 `{"status":200,"data":{"key":"$2y$10$...","expire_time":"5"}}`
- key 是 bcrypt hash，用于前端验证码加密
- 单独价值有限，配合CORS可辅助攻击

## 管理后台
/admin/ 返回 Vue SPA，JS路径: /admin/system_static/js/app.*.js
搜索: admin, token, password, api, config, secret

## 报告定级
- CORS反射+公开数据API: 低危(不建议单独提交)
- CORS反射+认证态API可读取用户数据: 中危
- /api/products 未授权访问: 低危(公开商品数据设计如此)
- /admin/ 后台SPA可访问: 需进一步验证是否有未授权API

## 实战案例
- shop.hzau.edu.cn: 华中农业大学校园商城, CORS+未授权商品API
