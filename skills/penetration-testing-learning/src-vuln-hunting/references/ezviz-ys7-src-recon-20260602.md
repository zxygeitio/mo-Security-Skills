# 萤石SRC (EZVIZ/YS7) 侦察与测试记录 — 2026-06-02

## 防护评估 (关键!)

三重WAF防护，极高安全水平：
- openRASP: 拦截ThinkPHP RCE/Actuator等(返回403)
- 阿里云WAF: 拦截SQL注入/XSS/命令注入(返回418:6357)
- Cloudflare: store-front等前端应用(返回418)
- Tengine: HTTP走私返回400

**结论: 无账号/APK逆向凭证情况下，无法突破WAF获取高危漏洞。**

## 新发现子域名 (2026-06-02 枚举)

### ys7.com 高价值新目标
| 子域名 | 状态 | 发现 |
|--------|------|------|
| openapicn.eziot.com | 200/404 | **IoT中国站API! Swagger UI暴露, API端点可用** |
| store-front.ys7.com | 200 | 萤石派B2B平台, config.js泄露内部地址 |
| ezm.ys7.com | 200 | 觅讯视频会议, 内部路径泄露+debug模式 |
| test12open.ys7.com | 404 | Kubernetes default backend |
| npm.ys7.com | - | 未存活 |
| open.xy3.ys7.com | 302 | 区域开放平台 |
| open.xy4.ys7.com | 302 | 区域开放平台 |
| shop.ys7.com | 302 | 跳转auth.ys7.com |

### ezvizlife.com 高价值新目标
| 子域名 | 状态 | 发现 |
|--------|------|------|
| ifttt.ezvizlife.com | 200 | **Spring Security + OAuth2! Druid 302存在** |
| ezvizinsider.ezvizlife.com | 200 | CloudFront, CSP保护 |
| partner.ezvizlife.com | 302 | 经销商门户 |
| testusopen.ezvizlife.com | - | 未存活 |
| testusjsdecoder.ezvizlife.com | 403 | JS解码器 |

### eziot.com
| 子域名 | 状态 | 发现 |
|--------|------|------|
| openapicn.eziot.com | 200/404 | **IoT API CN站! Swagger UI + API端点** |
| resource.eziot.com | 200 | 默认Tengine页面 |
| iot.eziot.com | - | 未存活 |

## openapicn.eziot.com — IoT API (最高价值目标)

### Swagger UI
- URL: https://openapicn.eziot.com/swagger-ui.html
- 版本: Springfox 2.8.0-SNAPSHOT
- API文档路径不可用(/v2/api-docs等返回404)

### API端点测试
```
POST /api/lapp/token/get → {"msg":"appkey和appsecret不匹配","code":"10030"}
POST /api/lapp/device/list → {"msg":"accessToken过期或异常","code":"10002"}
```

### 关键发现: appKey数据库差异
- open.ys7.com: appKey不存在返回 code:10017
- openapicn.eziot.com: appKey存在但secret不匹配返回 code:10030
- **测试的at8ksszsss/at9d3d4sad等在openapicn上返回10030，说明这些appKey在CN站存在!**
- 需要正确的appSecret才能利用

### appKey格式
- 前缀: at + 8位小写字母数字
- 示例: at8ksszsss, at9d3d4sad, at79fqsszs, at9rfsax3s

## ifttt.ezvizlife.com — OAuth2服务

### 技术栈
- Spring Security + OAuth2
- Tengine + Tomcat
- Alibaba Druid (WebStatFilter)
- SiteMesh

### 端点
- /oauth/authorize → 200 (接受任意client_id)
- /oauth/token → 401
- /login.jsp → 500 NullPointerException (堆栈泄露)
- /druid → 302 (Druid监控存在但403)

### 堆栈泄露
login.jsp泄露完整Spring Security过滤器链:
- com.hikvision.oauth2.web.filter.CustomSecurityContextPersistenceFilter
- 完整FilterChainProxy配置

## openauth.ys7.com — OAuth2认证

### OAuth2开放重定向 (需用户交互)
- URL: https://openauth.ys7.com/oauth/authorize
- **redirect_uri参数未做白名单校验，接受任意域名**
- 攻击链: 钓鱼链接→用户登录→授权码发送到攻击者域名

验证:
```
curl -sk "https://openauth.ys7.com/oauth/authorize?client_id=ezviz&redirect_uri=https://evil.com/steal&response_type=code"
→ 返回200，萤石官方登录页面
```

JS代码确认:
```javascript
params += '&' + location.search.substring(1);  // 包含redirect_uri
// 登录成功后: window.location.href = data.redirectUrl;
```

限制: 需要用户点击链接并输入账号密码

## store-front.ys7.com — 萤石派配置泄露

### config.js 泄露内容
- store-api.ys7.com (后端API)
- ecadmin.ys7.com (管理后台)
- vending-gateway.ys7.com:8586 (WebSocket)
- mall-gateway.ys7.com, mall-webgateway.ys7.com
- fs.ys7.com/upload.php (文件上传)
- iothome.ys7.com
- Geetest CAPTCHA ID: f9350603a2daf430a742bd784316546f
- appId: 6126e42c790f49ef8c7a
- Baidu Maps API key: cwo0RxtBi9KYHdC2bIRSkMa0CiYmrVMp

### Apollo配置端点
- /mall_newstore_front-nodeApolloCachedConfig.json (超时未测通)

## ezm.ys7.com — 觅讯平台

### 信息泄露
- 内部路径: F:\\workspace\\rtcwork\\rtc_portal\\branches\\v3.1.5\\public\\locales
- debug模式: "debug":true
- 客服电话: 13148352979
- ICP: 浙ICP备2024101974号
- 许可证: B2-20242438 (多方通信)
- 百度统计: d216aa98b35a7747739058994ebb603
- CDN: res.mixlink.com

## auth.sq/auth.xy.ys7.com — 区域认证服务器

- X-Powered-By: PS
- /doLogin → 200 (retcode:1007密码错误)
- /captcha → 200 (JPEG验证码)
- /druid → 302 (Druid存在但403)
- 与auth.ys7.com相同的认证逻辑

## store.ys7.com ThinkPHP — WAF绕过测试

### 已尝试的绕过(全部失败)
- /?s=/index/\\think\\app/invokefunction RCE → 空响应/302
- POST _method=__construct → 418 WAF拦截
- Unicode/双重编码 → WAF拦截
- HTTP走私 → Tengine 400
- exec/passthru/popen不同函数 → 418/000

### 结论
openRASP + 阿里云WAF双重防护，所有已知ThinkPHP RCE payload被拦截。

## fs.ys7.com — 文件上传

- /upload.php 存在，返回 {"status":false,"msg":"参数无效"}
- 需要正确参数才能利用
- config.js暴露参数: app=retail, flag=goods
- 尝试多种参数组合均返回"参数无效"

## vending-gateway.ys7.com:8586 — WebSocket

- Server: workerman/4.0.37
- 版本泄露

## 下次测试优先级

1. **APK逆向获取appKey/appSecret** → openapicn.eziot.com设备API
2. **注册开发者账号** → 获取appKey/appSecret → 测试IDOR
3. **OAuth2钓鱼链** → 需要配合社工
4. **fs.ys7.com参数爆破** → 需要更多参数变体
5. **萤石云视频APP抓包** → 获取accessToken → 测试设备越权
