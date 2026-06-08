# 契约锁(Qiyuesuo) SRC渗透测试记录 (2026-05-27)

## 目标资产
- 公有云: cloud/passport/open/oss/www/dl/cdn.qiyuesuo.com
- 私有化: privapp/privopen/privoss.qiyuesuo.me (均403)
- 私有化登录: passport.qiyuesuo.me/.cn, auth.qiyuesuo.me/.cn
- OpenAPI: openapi.qiyuesuo.com/.me/.cn
- 文件服务: fileapi.qiyuesuo.com
- 企业印章: app37.qiyuesuo.cn
- 存证网关: gw.qiyuesuo.com
- 印章管理: seal.qiyuesuo.com
- 电子证据: verify.qiyuesuo.com
- 认证服务: auth.qiyuesuo.com
- API网关: cloudapi.qiyuesuo.com/.me, m.qiyuesuo.me
- 演示环境: demo.qiyuesuo.com/.cn

## 关键发现

### 严重: fileapi /file/test Spring Boot环境配置泄露
- URL: `https://fileapi.qiyuesuo.com/file/test`
- 无需任何认证，返回88KB完整Spring Boot application.properties
- 泄露50+敏感配置: Redis密码、RabbitMQ密码、阿里云OSS密钥、华为云密钥、微信/钉钉密钥、内部API密钥、Kubernetes集群信息
- 复现: `curl -sk "https://fileapi.qiyuesuo.com/file/test" | grep redis`

### 中危: 全系CORS反射 + /health内网IP泄露
- passport.qiyuesuo.com/.me/.cn, app37.qiyuesuo.cn: 任意Origin反射+Credentials:true
- auth.qiyuesuo.me/.cn: CORS通配符(*)
- cloudapi.qiyuesuo.com/.me: 反射+Credentials+expose-headers:content-disposition
- /health端点返回内网IP: 10.242.x.x(公有云), 10.246.x.x(私有化1), 10.244.x.x(私有化2)

### 中危: cdn JS泄露pocToken和内部域名
- cdn.qiyuesuo.com/_nuxt/0.5eeed4289bc23c16386c.js 硬编码:
  - app37.qiyuesuo.cn (印章管理)
  - pocToken: w4lCceAoW7CqORbVgAgPiA%3D%3D
  - 4个印章ID
  - 权限视角: appPermission/chopPermission

### 低危: cloud前端泄露内部服务配置
- cloud.qiyuesuo.com HTML中硬编码:
  - var API = 'https://cloudapi.qiyuesuo.com'
  - var FILE_API = 'https://fileapi.qiyuesuo.com' (新发现域名!)
  - var OPEN = 'https://open.qiyuesuo.com'

## 技术栈
- 前端: Vue.js SPA (cloud), Nuxt.js SSR (passport/open)
- WAF: 华为云WAF (HWWAFSESID cookie)
- 负载均衡: ELB
- 后端: Spring Boot (Java 17)
- 容器: Kubernetes (10.243.0.1)
- 缓存: Redis (华为云DCS)
- 消息队列: RabbitMQ
- 存储: 阿里云OSS + 华为云OBS
- CAPTCHA: Geetest滑块

## API架构
- cloud.qiyuesuo.com 前端 → cloudapi.qiyuesuo.com 后端
- API路径不带/api/前缀: /user, /contract/, /company/list等
- 认证cookie: QID + CSRFID
- openapi使用自定义header: x-qys-open-accesstoken/signature/timestamp/nonce

## 注册流程
- passport.qiyuesuo.com/signup 需要Geetest滑块验证码
- 无法程序自动完成，需手动注册
- 注册后可用QID+CSRFID cookie访问cloudapi认证态接口

## 内部网络拓扑(通过/health泄露)
- 公有云 10.242.x.x: passport(3节点)/cloudapi/openapi/auth/seal/gw/fileapi
- 私有化1 10.246.x.x: passport/auth/cloudapi/openapi
- 私有化2 10.244.x.x: passport/auth/openapi
