# 巨人网络(Giant Network) SRC 测试模式 (2026-05-27)

## 目标范围
- *.ztgame.com (核心+常规)
- *.mobileztgame.com (常规)
- *.ztgame.com.cn (常规)
- 其他20+关联域名(见scope)

## 核心资产指纹
| 域名 | 技术栈 | 用途 |
|------|--------|------|
| www.ztgame.com | Nuxt.js SSR + Lego Server | 官网 |
| my.ztgame.com | Java (302登录墙) | 账号中心 |
| reg.ztgame.com | Java (302登录墙) | 注册 |
| login.ztgame.com | SPA fallback (202) | 登录(所有路径返回相同HTML) |
| pay.ztgame.com | nginx, gb2312编码 | 充值(/v5/路径, CORS: *) |
| ipay.ztgame.com | Vue.js SPA + mobileztgame SDK | 手游充值 |
| gsm.ztgame.com | Umi(React) + Spring Boot + X-WAF | 供应商管理平台(边缘资产) |
| ucmsv2api.ztgame.com | nginx + Java Spring Boot | CMS内容API |
| 3rd.login.ztgame.com | PHP (oauth.php) | 第三方OAuth登录(QQ) |
| zt.ztgame.com / yszt.ztgame.com | Apache/2.4.38 (Debian) | 游戏官网(版本泄露) |
| gamm3.ztgame.com | 引用 gamm.ztgame.cn | 账号管家 |

## 已确认漏洞

### 1. gsm.ztgame.com 短信轰炸 [中危]
- 端点: `GET /api/common/sms/send?mobile=<任意手机号>`
- 无需认证/验证码/频率限制
- 返回: `{"msg":"验证码发送成功","code":200}`
- 供应商注册API: `POST /api/supplierRegister` (需phone字段)
- 验证码图片: `GET /api/captchaImage` (无需认证)
- RSA公钥: `GET /api/getPublicKey` (无需认证)

### 2. ucmsv2api.ztgame.com CORS反射 [中危]
- OPTIONS预检反射任意Origin + `access-control-allow-credentials: true`
- 文章API: `GET /api/article/list?site=<site>` (需要有效site参数)
- site=zt返回"内部错误"(有效但有服务端错误)
- 其他site值返回"site不存在"

## Umi框架API端点提取模式
gsm.ztgame.com使用Umi(React)框架，2.2MB JS bundle。
```bash
# 下载Umi JS bundle
curl -sk "https://gsm.ztgame.com/umi.b5d1ed60.js" -o /tmp/umi.js
# 提取API路径
grep -oP '"/api/[a-zA-Z0-9_/\-]*"' /tmp/umi.js | sort -u
# 提取request调用模式(发现隐藏API)
grep -oP 'request\("[^"]*"' /tmp/umi.js
```
发现的API端点:
- /api/login, /api/login/encrypted, /api/logout
- /api/getInfo, /api/getRouters, /api/auth/refresh
- /api/supplierRegister (POST)
- /api/captchaImage, /api/getPublicKey
- /api/common/sms/send (GET, 无认证!)
- /api/login/captcha?mobile= (需认证)

## Zend Apigility 指纹
passport-api.sdk.mobileztgame.com使用Zend Apigility:
- 404页包含: `<title>Apigility</title>`, `/zf-apigility/css/`
- 响应头: `x-sdk-server: passport-api/1.x`
- /oauth → 500错误(服务端处理)
- 版权: 2013-2026 Zend Technologies

## 阿里云OSS指纹
oss.zt2zs.ztgame.com:
- Tengine服务器
- `x-oss-request-id` header
- HostId: zt2zs.oss-cn-hangzhou.aliyuncs.com
- 403: "The bucket you access does not belong to you"

## 子域名资产(237个)
关键子域名:
- admin.ztgame.com → 222.73.63.137 (连接超时)
- jenkins.ztgame.com → 47.123.101.172 (HTTP 403)
- common.dev.ztgame.com → 103.192.255.177
- activity-api.ztgame.com
- api-amt.ztgame.com (503 + X-WAF-UUID)
- git.devcloud.ztgame.com
- passport-api.sdk.mobileztgame.com (Apigility)
- stat.sdk.mobileztgame.com (返回 {"status":1})

## 内部IP/域名泄露
ipay.ztgame.com JS文件泄露:
- 内部IP: 218.242.124.22
- 内部域名: pagespy.devcloud.ztgame.com, beacon.ztgame.com, kfim.ztgame.com
- CDN: cdn-imgs.sdk.mobileztgame.com, cdn-gbuff.sdk.mobileztgame.com

## WAF特征
gsm.ztgame.com: `X-WAF-UUID` header (自建WAF)
api-amt.ztgame.com: 503 + X-WAF-UUID

## 测试限制
- login.ztgame.com是SPA fallback，actuator等路径不是真实端点
- my.ztgame.com/reg.ztgame.com所有路径302重定向(登录墙)
- pay.ztgame.com /v5/api/* 全部302(需登录)
- admin.ztgame.com连接超时(HTTP/HTTPS均不可达)
- jenkins.ztgame.com返回403(无法访问)

## 报告定价
- 核心资产: 高危¥2000-4000, 中危¥1200-1800, 低危¥200-400
- 常规资产: 高危¥1200-2000, 中危¥700-1200, 低危¥100-200
- 边缘资产: 高危¥300-800, 中危¥100-200, 低危¥50-100
