# 契约锁(Qiyuesuo) SRC 情报

适用场景：契约锁SRC目标侦察、API端点发现、认证绕过、环境配置泄露。

## 目标资产清单

核心资产(在SRC范围)：
- cloud.qiyuesuo.com - 公有云电子签系统
- passport.qiyuesuo.com - 公有云登录平台
- open.qiyuesuo.com - 公有云开放平台
- oss.qiyuesuo.com - 公有云管理平台
- www.qiyuesuo.com - 官网

附属域名(不在SRC范围但属于契约锁)：
- fileapi.qiyuesuo.com - 文件服务API
- cloudapi.qiyuesuo.com - 云平台后端API
- openapi.qiyuesuo.com - 开放平台API网关
- dl.qiyuesuo.com - 文件下载/OSS
- cdn.qiyuesuo.com - CDN/营销页
- auth.qiyuesuo.com / auth2.qiyuesuo.com - 认证服务
- seal.qiyuesuo.com - 印章管理
- gw.qiyuesuo.com - API网关
- t1.qiyuesuo.com - 测试服务
- person-auth.qiyuesuo.com - 个人认证
- crm.qiyuesuo.com - CRM系统(Ant Design Pro)
- pay.qiyuesuo.com - 支付系统
- verify.qiyuesuo.com - 电子证据链平台
- app37.qiyuesuo.cn - 企业印章管理
- demo.qiyuesuo.com/cn - 演示环境

私有化资产(通常403/需内网)：
- privapp/privopen/privoss.qiyuesuo.me
- passport/auth/cloudapi/openapi/m.qiyuesuo.me/.cn

## 技术栈

- 前端：Nuxt.js (passport/open), Vue.js SPA (cloud/crm)
- 后端：Spring Boot (Java), Express.js (前端SSR)
- WAF：华为云WAF (HWWAFSESID cookie)
- 认证：CAS SSO (passport.qiyuesuo.com), Cookie: QID + CSRFID
- 容器：Kubernetes, ZooKeeper集群
- 存储：阿里云OSS, 华为云OBS
- 缓存：Redis (华为云DCS), RabbitMQ

## API架构

cloud.qiyuesuo.com前端 → cloudapi.qiyuesuo.com后端
- 前端JS中API路径不带/api/前缀
- 实际调用 https://cloudapi.qiyuesuo.com/{path}
- 通过浏览器Performance API的XHR条目可发现真实后端域名

关键API端点(从XHR拦截发现)：
- /user, /userprivilege, /company/list, /business/list
- /fee/get?tenantType=PERSONAL&tenant={id}
- /contract/batch/statistics, /account/merge/check/namemismatch?userId={id}
- /company/recover/query?userId={id}, /config, /help/all

openapi.qiyuesuo.com认证：
- x-qys-open-accesstoken (441 if missing)
- x-qys-open-signature (441 if missing)
- 无效token返回442

## 已确认漏洞模式

### fileapi /file/test 环境配置泄露 (严重)
- 端点：https://fileapi.qiyuesuo.com/file/test
- 无需认证，返回88KB JSON，包含完整Spring Boot环境配置
- 泄露：Redis密码、RabbitMQ密码、阿里云OSS密钥、华为云密钥、微信/钉钉密钥、内部API密钥、K8s集群信息、50+微服务地址
- 复现：curl -sk "https://fileapi.qiyuesuo.com/file/test" | grep 'redis'

### CORS配置缺陷 (低危，不建议单独提交)
- passport/cloudapi/fileapi: 反射任意Origin + Credentials:true
- auth/seal/auth2/person-auth/pay: CORS通配符(*)
- 所有域名/health泄露内网IP (10.242.x.x段)
- 仅CORS+IP不够SRC提交门槛，需证明可跨域读取登录态敏感数据

## 注册流程

1. passport.qiyuesuo.com/signup
2. 输入手机号/邮箱 → Geetest滑块(需手动) → 验证码 → 设密码
3. Geetest滑块无法程序化完成

## SDK情报

Java SDK v4.0.0: https://dl.qiyuesuo.com/sdk/java/sdk-java-4.0.0.zip
- 认证头: x-qys-open-accesstoken/signature/timestamp/nonce
- MD5和HMAC-SHA256签名
- 120+ API端点：合同/文档/模板/印章/员工/签署方/企业认证/SaaS
