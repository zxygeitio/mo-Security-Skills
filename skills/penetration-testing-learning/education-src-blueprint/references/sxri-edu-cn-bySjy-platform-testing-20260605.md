# sxri.net (陕西铁路工程职业技术学院) bySjy平台测试记录 2026-06-05

## 目标概况
- 学校: 陕西铁路工程职业技术学院
- 域名: sxri.net
- CDN: 加速乐(Jiasule) - X-Via-JSL header, __jsluid_s cookie
- 所有子域名解析到198.18.x.x(保留IP), 历史DNS泄露真实IP: 61.150.72.60/142/145
- 真实IP开放全部端口(蜜罐/opencanary), 不要浪费时间测试

## 子域名清单(128个)
存活的关键子域:
- zsw.sxri.net - 招生网 (SUDY WebPlus CMS, siteId=80)
- www.sxri.net - 主站 (SUDY, siteId=2)
- cas.sxri.net - CAS统一认证 (lyuapServer)
- portal.sxri.net - Liferay Portal CE 4.0.0 (2013)
- ehall.sxri.net - 办事大厅 (域名暂未生效)
- zsxt.sxri.net - 招生考试系统 (bySjy/bysjy.com.cn平台)
- cs-sec.sxri.net - 云就业运营管理平台 (bySjy平台, PHP 7.1.33)
- apply.sxri.net - 实训室预约系统 (DianCMS, ASP.NET 4.0.30319)
- ai.sxri.net - AI知识系统 (CAS SSO)
- jw.sxri.net - 纪检委 (SUDY, siteId=90)
- jwc.sxri.net - 教务处 (SUDY)
- 各二级学院子域 (cxxy/cgxy/chxy/dlxy/glxy/gtxy/qjxy/ysxy/zbxy等) - 均为SUDY CMS

DNS通配符子域(198.18.x.x, "域名暂未生效"): sso/auth/ids/idp/swagger/actuator/druid/admin/manage/api/rest等

## 发现1: cs-sec.sxri.net CORS `*` + Credentials (高危)

### 指纹
- Server: nginx
- X-Powered-By: PHP/7.1.33
- 平台: bySjy (bysjy.com.cn) 云就业运营管理平台
- jQuery 1.11.2
- captcha.js: AES ECB模式, key=XwKsGlMcdPMEhR1B

### CORS响应头
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: *
Access-Control-Allow-Methods: *
```

### 验证命令
```bash
curl -sk "https://cs-sec.sxri.net/" -H "Origin: https://evil.com" -D- | grep -i access-control
```

### 注意
- OPTIONS预检返回405(nginx拦截), 但GET/POST请求正常携带CORS头
- 所有路径均返回相同CORS配置(全局生效)
- API端点均为SPA路由(返回200+空body), 需通过浏览器JS调用

## 发现2: CAS lyuapServer 用户枚举+密码错误计数泄露+无锁定 (中危)

### 认证路径差异(重要!)
- **纯数字密码**: HTTP 200, 返回PASSERROR, data字段递增(错误计数)
- **含字母/特殊字符密码**: HTTP 500, 返回"系统内部错误"
- **不存在用户**: HTTP 200, 返回NOUSER
- **存在用户**: HTTP 500 或 HTTP 200 PASSERROR(取决于密码格式)

### 验证命令
```bash
# 存在用户(纯数字密码) → PASSERROR+计数
curl -sk -X POST "https://cas.sxri.net/lyuapServer/v1/tickets" \
  -d "username=admin&password=123456" \
  -H "Content-Type: application/x-www-form-urlencoded"

# 不存在用户 → NOUSER
curl -sk -X POST "https://cas.sxri.net/lyuapServer/v1/tickets" \
  -d "username=nonexistent12345&password=123456" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

### 无账号锁定验证
连续39+次纯数字密码错误, data字段从1递增到39+, 未触发锁定。

### SMS API
- 端点: POST /lyuapServer/v2/sendSms
- 需要appid参数, 测试的hash值均返回"appid不存在或被禁用"
- JSON格式请求返回"appid参数不能为空"

## 发现3: zsxt.sxri.net bySjy平台API未授权 (低危)

### 未授权API端点
- `/login/get_exam_list` → 返回考试列表
- `/login/get_security_question_list` → 返回密保问题列表
- `/login/get_login_config` → 返回登录配置
- `/gzdz/get_apply_flow` → 返回报名流程

### 登录参数
- user_code: 身份证号
- pwd: MD5哈希
- exam_id: 考试ID
- captcha_token + captcha: 行为验证码(不可绕过)
- verification_code: 图片验证码(传统4位, 101x49 PNG)

### AES硬编码密钥
captcha.js: `aesEncrypt(word, keyWord = 'XwKsGlMcdPMEhR1B')` 使用ECB模式

### error_info泄露
错误响应含`error_info":{"line":N}`泄露服务端源码行号

## 发现4: Liferay Portal CE 4.0.0 (2013)

- 版本头: `Liferay-Portal: Lyasp Portal Community Edition 4.0.0 CE GA1 (Newton / Build 6201 / November 1, 2013)`
- JSONWS `/api/jsonws/invoke` 可访问但返回"Unable to deserialize object"(需认证)
- `/actuator/env` 被创宇盾WAF拦截(403)
- `/tunnel-web/` 302重定向到 `/api/`

## 负证据(不建议提交)
- SUDY CMS后端全面503(搜索/API/.psp不可用, 静态页面正常)
- ehall.sxri.net "域名暂未生效"
- apply.sxri.net upload/editor目录403(WAF拦截)
- yqfk.sxri.net 录取查询"站点还在建设中"
- Liferay actuator被创宇盾拦截
- CAS SMS API需要有效appid
