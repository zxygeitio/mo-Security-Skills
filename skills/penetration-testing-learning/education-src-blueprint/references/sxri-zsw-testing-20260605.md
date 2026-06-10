# sxri.net zsw.sxri.net 招生网测试记录 (2026-06-05)

## 目标概况
- 学校: 陕西铁路工程职业技术学院
- 主域: sxri.net
- 测试子域: zsw.sxri.net (招生网), cas.sxri.net, portal.sxri.net, zsxt.sxri.net, ehall.sxri.net, ai.sxri.net
- CDN: 加速乐 (Jiasule) - `X-Via-JSL` header, `__jsluid_s` cookie
- DNS: 所有子域解析到198.18.x.x (CDN通配符)
- 真实IP: 61.150.72.60 (通过 hackertarget 历史DNS获取) — 但为蜜罐(opencanary, 全端口开放)

## CMS指纹
- zsw/www/jwc等: SUDY WebPlus CMS (siteId=80主站, siteId=2主域)
- portal.sxri.net: Liferay Portal CE 4.0.0 GA1 (2013年版本)
- cas.sxri.net: 联创天空lyuapServer CAS
- zsxt.sxri.net: 第三方招生系统 (bysjy.com.cn 毕业生就业系统) + Vue.js + Element UI

## 确认漏洞

### 1. CAS lyuapServer 用户枚举 (中危)
```
POST https://cas.sxri.net/lyuapServer/v1/tickets
Content-Type: application/x-www-form-urlencoded

存在用户(admin/test): HTTP 500 "系统内部错误"
不存在用户: HTTP 200 {"meta":{"success":true,"statusCode":200,"message":"ok"},"data":{"code":"NOUSER"}}
```
- 无速率限制
- 仅admin和test用户存在

### 2. zsxt.sxri.net 招生系统API未授权访问 (低危)
无需认证即可访问的API:
- `/login/get_exam_list` → 返回考试列表 [{"exam_id":191,"exam_name":"..."}]
- `/login/get_security_question_list` → 返回密保问题列表 (8个问题)
- `/login/get_login_config` → 返回登录配置
- `/gzdz/get_apply_flow` → 返回报名流程
- 错误响应泄露源码行号: `{"error_info":{"line":116}}`

### 3. zsxt.sxri.net AES硬编码密钥 (中危边界)
文件: `/captcha/utils/captcha.js`
密钥: `XwKsGlMcdPMEhR1B` (ECB模式)
用途: 验证码加密
限制: 有行为验证码(滑块)保护, 无法直接利用

## 不建议提交的发现
- Liferay 4.0.0 JSONWS `/api/jsonws/invoke` 可访问但需认证 → 不可利用
- Liferay `/actuator/env` → 创宇盾WAF 403拦截
- SUDY CMS后端全面503 → 无法测试搜索/API/管理后台
- ehall.sxri.net → 域名暂未生效 + SUDY CMS 503
- ai.sxri.net → CAS SSO保护, 无直接漏洞
- 真实IP 61.150.72.60 → opencanary蜜罐(全端口开放)

## 新发现的攻击面
- zsxt.sxri.net 招生考试系统 — 从zsw.sxri.net首页链接发现
- 第三方系统 bysjy.com.cn — 毕业生就业/招生管理平台
- 忘记密码流程: `/login/apply_retrieve_password` + `/login/select_retrieve_password_method` + `/login/save_retrieve_password`
- mobile登录: 使用图片验证码(非行为验证码), 参数verification_code

## 停止条件
- SUDY CMS后端503, 无法继续CMS层面测试
- CAS用户枚举已确认, 无新发现
- zsxt验证码无法绕过
- 建议: 尝试admin弱口令爆破(CAS无速率限制)
