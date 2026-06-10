# sxri.net 深度测试记录 (2026-06-05)

## 目标概况
- 学校: 陕西铁路工程职业技术学院
- 域名: sxri.net (非.edu.cn)
- 子域数: 128个(subfinder枚举)
- CDN: 加速乐(X-Via-JSL header), 所有子域解析到198.18.x.x
- 真实IP: 61.150.72.60(主站), 61.150.72.142(CAS), 61.150.72.145(ai/apply)
- 真实IP全端口开放 = 蜜罐(opencanary), 不要浪费时间

## 已确认漏洞

### 1. cs-sec.sxri.net CORS * + Credentials (高危)
- PHP 7.1.33 EOL + Yii2 + nginx/1.17.9
- Access-Control-Allow-Origin: * + Credentials: true + Headers: * + Methods: *
- Yii2错误页面(/platform, /user, /school, /company)泄露:
  - SERVER_ADDR: 192.168.90.90 (内网IP)
  - SERVER_NAME: zsxtgl.sxri.net (内网主机名)
  - DOCUMENT_ROOT: /www/yjy/platform/web
  - USER: www
  - 完整Yii2源码路径(/www/yjy/vendor/yiisoft/yii2/...)
- 跨域POST /welcome/validate 成功(返回验证码错误)
- 跨域POST /welcome/captcha 成功(返回验证码图片+token)
- OPTIONS预检返回500, 但简单请求正常工作
- 登录API: POST /welcome/validate (user_name, password(hex_md5), captcha_token, captcha)
- 验证码API: POST /welcome/captcha {"captchaType":"blockPuzzle"}
- 平台: bysjy.com.cn 云就业运营管理平台

### 2. cas.sxri.net 用户枚举+无锁定 (中危)
- lyuapServer (联创天空)
- nginx/1.21.5
- POST /lyuapServer/v1/tickets (form-data: username, password)
- 存在用户(admin, test) → HTTP 500 "系统内部错误"
- 不存在用户 → HTTP 200 {"code":"NOUSER"}
- 纯数字密码 → HTTP 200 PASSERROR (data字段递增)
- 含特殊字符密码 → HTTP 500 "系统内部错误" (不同认证路径)
- 无账号锁定: 39+次错误密码仍可继续
- SMS API: POST /lyuapServer/v2/sendSms 需要appid
- 不接受Open Redirect(service参数校验)

### 3. zsxt.sxri.net API未授权 (低危)
- 招生考试系统, bysjy.com.cn平台, Vue.js + Element UI
- 无需认证API:
  - GET /login/get_exam_list → 考试列表
  - GET /login/get_security_question_list → 密保问题(8个)
  - GET /login/get_login_config → 登录配置
  - GET /gzdz/get_apply_flow → 报名流程
- 登录参数: user_code(身份证号), pwd(MD5), exam_id, verification_code
- 初始密码: 身份证号, 初始密码: 高考报名号
- 验证码: 101x49 PNG传统验证码(非行为验证码)
- error_info泄露源码行号
- captcha.js硬编码AES密钥: XwKsGlMcdPMEhR1B (ECB模式)

## 不可提交发现(负证据)
- Liferay Portal CE 4.0.0 GA1 (2013): portal.sxri.net, JSONWS需认证, actuator被创宇盾403
- SUDY CMS全站后端503: zsw/www/jwc/cw等所有子域搜索/API/admin不可用
- apply.sxri.net DianCMS ASP.NET 4.0: CAS认证, upload/editor目录403
- ai.sxri.net一方云Yifangyun: CAS SSO, API 401需认证
- 198.18.x.x DNS通配符: sso/auth/swagger/actuator/druid/admin等子域非真实服务
- 内网IP 192.168.90.90 从外网不可达
- OCR验证码识别不准确(101x49 PNG, tesseract预处理后识别率低)

## 关键技术细节
- 加速乐CDN: X-Via-JSL header, __jsluid_s cookie
- Yii2错误页面: 访问不存在的controller(/platform等)触发详细错误
- bysjy.com.cn: 多个子域使用此平台(cs-sec, zsxt)
- CAS认证路径差异: 纯数字密码走正常路径(PASSERROR), 含特殊字符走异常路径(500)
