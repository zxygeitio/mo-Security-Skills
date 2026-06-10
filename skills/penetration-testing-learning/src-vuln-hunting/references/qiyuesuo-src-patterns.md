# 契约锁(Qiyuesuo) SRC 专有模式

目标: *.qiyuesuo.com, *.qiyuesuo.me, *.qiyuesuo.cn
测试日期: 2026-05-27

## 资产架构

### 公有云 (121.37.160.134 / 10.242.x.x)
| 域名 | 用途 | 技术栈 |
|------|------|--------|
| cloud.qiyuesuo.com | 电子签云平台(前端) | Vue.js SPA, Express |
| cloudapi.qiyuesuo.com | 云平台API网关 | Spring Boot, Java |
| fileapi.qiyuesuo.com | 文件服务 | Spring Boot, Java |
| passport.qiyuesuo.com | 登录认证(CAS SSO) | Nuxt.js(SSR), Express |
| open.qiyuesuo.com | 开放平台 | Nuxt.js(SSR), Express |
| openapi.qiyuesuo.com | OpenAPI网关 | Spring Boot |
| oss.qiyuesuo.com | 管理平台 | Express |
| auth.qiyuesuo.com | 认证服务 | Spring Boot |
| seal.qiyuesuo.com | 印章管理 | Spring Boot |
| gw.qiyuesuo.com | 存证网关 | Spring Boot |
| verify.qiyuesuo.com | 电子证据链 | Vue.js(Vite) |
| dl.qiyuesuo.com | 文件下载/OSS | OpenResty + OBS |
| cdn.qiyuesuo.com | CDN/营销页 | Nuxt.js |
| demo.qiyuesuo.com | 演示环境 | Vue.js + Mock.js |
| app37.qiyuesuo.cn | 企业印章管理 | Nuxt.js |

### 私有化环境1 (119.3.152.109 / 10.246.x.x)
| 域名 | 用途 |
|------|------|
| passport.qiyuesuo.me | 登录认证 |
| auth.qiyuesuo.me | 认证服务 |
| cloudapi.qiyuesuo.me | API网关 |
| openapi.qiyuesuo.me | OpenAPI网关 |
| m.qiyuesuo.me | 移动端 |

### 私有化环境2 (10.244.x.x)
| 域名 | 用途 |
|------|------|
| passport.qiyuesuo.cn | 登录认证 |
| auth.qiyuesuo.cn | 认证服务 |
| openapi.qiyuesuo.cn | OpenAPI网关 |

### K8s集群 (10.243.x.x)
契约锁使用Kubernetes集群部署，内部微服务通过 `*.qiyuesuo-a.svc.cluster.local` 通信。
发现的微服务: gateway, message, corp-auth, fms, notary, cert, timestamp, event-bus, pay, crm, file, oss, auth, seal, tms, cms, ics, evs, fee, egs, hcs, pcs, link, lux, ums

## 认证体系

### CAS SSO
- passport.qiyuesuo.com 是统一登录入口
- 通过 `?service=` 参数指定回调URL
- Cookie: QID(主session), CSRFID
- cloud.qiyuesuo.com 通过 passport 登录后获取 session

### OpenAPI认证
- 需要 `x-qys-open-accesstoken` (accessKey)
- 需要 `x-qys-open-signature` (MD5或HMAC-SHA256签名)
- 需要 `x-qys-open-timestamp` 和 `x-qys-open-nonce`
- SaaS API额外需要 `x-qys-open-agentaccesstoken`
- 错误码: 441=缺少header, 442=无效token

### 前端→后端API映射
cloud.qiyuesuo.com 前端(Vue.js)的API调用实际目标是 cloudapi.qiyuesuo.com:
```javascript
// cloud.qiyuesuo.com 首页暴露:
var API = 'https://cloudapi.qiyuesuo.com';
var FILE_API = 'https://fileapi.qiyuesuo.com';
var OPEN = 'https://open.qiyuesuo.com';
```

cloud.qiyuesuo.com 本身的路径(如 /contract/, /user/)返回404，真实API在 cloudapi.qiyuesuo.com。

## 已验证漏洞

### 1. fileapi Spring Boot环境配置泄露 (严重)
`/file/test` 端点返回完整 application.properties，包含:
- Redis密码、RabbitMQ密码
- 阿里云OSS AccessKey、华为云AccessKey
- 微信/钉钉/金蝶/百度/腾讯 API密钥
- 内部API secret (qiyuesuo.secret, foundation.internal.appsecret)
- K8s集群拓扑、50+内部微服务地址
- ZooKeeper集群地址
- Sentry DSN

### 2. 全系CORS配置不当 (中危)
以下域名将任意Origin反射 + Credentials:true:
- passport.qiyuesuo.com/.me/.cn
- app37.qiyuesuo.cn
- cloudapi.qiyuesuo.com (GET返回403但OPTIONS preflight返回200)
- cloudapi.qiyuesuo.me
- m.qiyuesuo.me

以下域名CORS通配符(*):
- auth.qiyuesuo.com/.me/.cn
- seal.qiyuesuo.com

### 3. /health接口内网IP泄露 (低危-中危)
所有域名的 /health 无需认证返回 `{"ip":"内网IP","time":"...","result":"OK"}`。
泄露了3个独立环境的内部网络拓扑。

### 4. OpenAPI文档和SDK信息泄露 (低危)
- open.qiyuesuo.com /api/doc/info 返回完整API文档树
- SDK下载包泄露120+ API端点
- SDK包含SSL证书验证绕过(TrustAllTrustManager)

### 5. CDN JS泄露pocToken和内部域名 (中危)
cdn.qiyuesuo.com 的JS bundle硬编码:
- app37.qiyuesuo.cn 域名
- pocToken: w4lCceAoW7CqORbVgAgPiA==
- 4个印章ID

## 关键API端点 (cloudapi.qiyuesuo.com)

认证态API(需QID cookie):
- /user - 用户信息
- /userprivilege - 用户权限
- /company/list - 公司列表
- /business/list - 合同列表
- /contract/{id} - 合同详情
- /contract/download/document/{id} - 文档下载
- /contract/attachment/download - 附件下载
- /contact/list - 联系人列表
- /template/list - 模板列表
- /seal/list - 印章列表
- /fee/get?tenantType=PERSONAL&tenant={id} - 费用信息
- /account/merge/check/namemismatch?userId={id} - 账号合并检查(可枚举)

OpenAPI端点(openapi.qiyuesuo.com):
- /api/v2/contract/{list|detail|draft|send|...} - 合同管理
- /api/v2/seal/{list|image|create|...} - 印章管理
- /api/v2/document/{add|download|...} - 文档管理
- /saas/v2/{binding|company|...} - SaaS API

## 测试注意事项

1. 注册需要Geetest滑块验证码，无法程序自动完成
2. 私有化域名(priv*.qiyuesuo.me)全部403，需特定IP访问
3. /actuator/env 被WAF拦截返回418
4. demo.qiyuesuo.com 使用 `isDemo=!0` + Mock.js，前端拦截API调用返回mock数据
5. cloud.qiyuesuo.com 前端所有路径返回200(Vue SPA fallback)，需检查API是否返回JSON
6. cloudapi CORS: GET请求带Origin:evil.com返回403"Invalid CORS request"，但OPTIONS preflight返回200且CORS头完整
7. 用户ID格式: 雪花算法生成(如3497116750724702273)
8. 内部IP段: 10.242.x.x(公有云), 10.244.x.x(私有化2), 10.246.x.x(私有化1), 10.243.x.x(K8s集群)

## 新发现但未在SRC范围的域名

以下域名不在SRC测试范围但属于契约锁基础设施:
- auth2.qiyuesuo.com (认证服务v2)
- person-auth.qiyuesuo.com (个人认证)
- corp-auth.qiyuesuo.com (企业认证)
- lcs.qiyuesuo.com
- site-cms.qiyuesuo.com
- crm.qiyuesuo.com
- pay.qiyuesuo.com
- ossapia.qiyuesuo.com
- help.qiyuesuo.com
- sentry.qiyuesuo.com (错误追踪)
