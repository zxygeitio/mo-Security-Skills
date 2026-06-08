# 契约锁(Qiyuesuo) SRC 渗透测试记录 (2026-05-27)

## 目标范围
- 核心资产: cloud/passport/open/oss/www.qiyuesuo.com, privapp/privopen/privoss.qiyuesuo.me
- 常规资产: privoss.qiyuesuo.me

## 技术栈
- 前端: Nuxt.js (Vue 2 SSR) + Element UI + Express
- 后端: Spring Boot + Kubernetes (华为云/阿里云)
- WAF: 华为云WAF (HWWAFSESID cookie)
- 认证: CAS SSO (passport.qiyuesuo.com)
- API网关: cloudapi.qiyuesuo.com
- 文件服务: fileapi.qiyuesuo.com
- OpenAPI: openapi.qiyuesuo.com

## 已验证漏洞

### 1. 严重: fileapi /file/test Spring Boot环境配置泄露
- URL: https://fileapi.qiyuesuo.com/file/test
- **无需任何认证**, 返回88KB完整Spring Boot环境配置
- 泄露: Redis密码、RabbitMQ密码、阿里云OSS密钥、华为云密钥、微信/钉钉secret、内部API密钥、Kubernetes集群信息、50+微服务地址
- 复现: `curl -sk "https://fileapi.qiyuesuo.com/file/test" | grep redis`

### 2. 中危: 全系CORS配置不当 + /health内网IP泄露
- 10+子域名/health返回内网IP (10.242.x.x段)
- CORS反射型(任意Origin+Credentials): passport/cloudapi/fileapi/crm
- CORS通配符型(*): auth/seal/auth2/person-auth/pay
- 复现: `curl -sk -D- "https://passport.qiyuesuo.com/health" -H "Origin: https://evil.com"`

### 3. 中危: CDN JS泄露pocToken和内部域名
- cdn.qiyuesuo.com/_nuxt/0.5eeed4289bc23c16386c.js 硬编码:
  - app37.qiyuesuo.cn (印章管理平台)
  - pocToken: w4lCceAoW7CqORbVgAgPiA%3D%3D
  - 4个印章ID
  - 权限视角: appPermission/chopPermission

## 内部网络拓扑(通过/health泄露)
| 域名 | 内网IP | 服务 |
|------|--------|------|
| passport.qiyuesuo.com | 10.242.9.33 | 登录 |
| cloudapi.qiyuesuo.com | 10.242.18.197 | API网关 |
| fileapi.qiyuesuo.com | 10.242.3.220 | 文件服务 |
| openapi.qiyuesuo.com | 10.242.12.161 | OpenAPI |
| auth.qiyuesuo.com | 10.242.9.158 | 认证 |
| seal.qiyuesuo.com | 10.242.16.148 | 印章 |
| t1.qiyuesuo.com | 10.242.11.153 | 测试 |
| auth2.qiyuesuo.com | 10.242.5.153 | 认证2 |
| person-auth.qiyuesuo.com | 10.242.9.163 | 个人认证 |

## 认证流程
1. cloud.qiyuesuo.com → 302到 passport.qiyuesuo.com/login?service=...
2. 密码登录(含Geetest滑块验证码)
3. 登录后获取QID + CSRFID cookie (域名: .qiyuesuo.com)
4. API调用到 cloudapi.qiyuesuo.com, 带QID+CSRFID cookie

## 关键API端点(cloudapi.qiyuesuo.com, 需认证)
- /user → 用户信息(id/name/mobile/idcard)
- /userprivilege → 用户权限
- /company/list → 公司列表
- /fee/get?tenantType=PERSONAL&tenant={id} → 费用信息
- /contract/{id} → 合同详情
- /business/list → 业务列表
- /account/merge/check/namemismatch?userId={id} → 账户合并检查(任意userId)
- /company/recover/query?userId={id} → 公司恢复(需权限)

## OpenAPI认证机制
- Header: x-qys-open-accesstoken (accessKey)
- Header: x-qys-open-signature (MD5/HMAC-SHA256签名)
- Header: x-qys-open-timestamp
- Header: x-qys-open-nonce
- SaaS: x-qys-open-agentaccesstoken
- 错误码: 441=缺少header, 442=无效token

## CORS验证细节
- cloudapi GET+Origin:evil.com → 403 "Invalid CORS request" + CORS headers仍设置
- cloudapi OPTIONS+Origin:evil.com → 200 + CORS headers允许evil.com
- 含义: preflight成功但实际请求被拒, CORS headers不应在错误响应中设置

## 新发现子域名(不在SRC范围但属于契约锁)
fileapi/cloudapi/m/openapi/auth/seal/gw/app37/verify/sign/demo/t1/auth2/person-auth/crm/pay/site-cms/help/ossa/ossapi/lcs/person-auth/corp-auth

## 测试限制
- 私有化资产(privapp/privopen/privoss.qiyuesuo.me)均返回403
- Geetest滑块验证码无法程序自动完成
- 注册需手机号+短信验证码+Geetest

## 用户偏好
- grep -oP正则在终端复制时*被吞, 优先用python3 -c过滤或先保存文件再grep
- 用户希望直接看到过滤结果, 不是给命令让用户自己跑
- 单行curl, 不用反斜杠续行
