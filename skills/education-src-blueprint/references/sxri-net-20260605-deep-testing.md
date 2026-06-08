# sxri.net 深度测试记录 (2026-06-05)

## 目标概况
- 学校: 陕西铁路工程职业技术学院
- 域名: sxri.net
- 子域数量: 128个(subfinder枚举)
- CDN: 加速乐(X-Via-JSL), 所有子域解析到198.18.x.x(保留IP)
- 历史DNS真实IP: 61.150.72.60(主站), 61.150.72.142(CAS), 61.150.72.145(AI)
- 真实IP端口: 全部1000端口开放(蜜罐/opencanary)

## 活跃子域
| 子域 | 系统 | 技术栈 |
|------|------|--------|
| cs-sec.sxri.net | 云就业运营管理平台 | PHP 7.1.33 + Yii2 + nginx/1.17.9 |
| cas.sxri.net | 统一身份认证平台 | nginx/1.21.5 + lyuapServer |
| zsxt.sxri.net | 分类考试招生报名系统 | Vue.js + bysjy.com.cn + Element UI |
| ai.sxri.net | AI知识平台 | Yifangyun + CAS SSO |
| portal.sxri.net | 门户 | Liferay Portal CE 4.0.0 (2013) |
| apply.sxri.net | 实训室预约系统 | ASP.NET 4.0.30319 + DianCMS |
| www/zsw/jwc等 | 主站/招生网/教务处 | SUDY WebPlus CMS(后端503) |

## 已确认漏洞

### 1. cs-sec.sxri.net CORS * + Credentials (高危 7.5)
- 响应头: `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` + `Access-Control-Allow-Headers: *` + `Access-Control-Allow-Methods: *`
- 跨域POST请求成功: `/welcome/validate`返回登录响应
- 跨域获取验证码: `/welcome/captcha`返回图片+token+secretKey
- Yii2错误页面泄露: SERVER_ADDR=192.168.90.90, SERVER_NAME=zsxtgl.sxri.net, nginx/1.17.9, /www/yjy/
- 验证: `curl -sk "https://cs-sec.sxri.net/" -H "Origin: https://evil.com" -D- | grep -i access-control`

### 2. ai.sxri.net SSO Open Redirect (中危 6.1)
- 参数: `?redirect=https://evil.com`
- 流程: 设置`LoginRedirect` cookie → 重定向到CAS → 登录后重定向到恶意URL
- 验证: `curl -sk "https://ai.sxri.net/sso/login?redirect=https://evil.com" -D- | grep -i 'location\|set-cookie'`

### 3. cas.sxri.net 用户枚举+无锁定 (中危 6.5)
- 存在用户→HTTP 500 "系统内部错误"
- 不存在用户→HTTP 200 `{"code":"NOUSER"}`
- 密码错误计数泄露: `PASSERROR` data字段递增(1→3→5→...→39)
- 无账号锁定: 39+次错误仍可继续
- 已确认存在: admin, test
- 认证路径差异: 纯数字密码→200 PASSERROR, 含字母/特殊字符→500
- 验证: `curl -sk -X POST "https://cas.sxri.net/lyuapServer/v1/tickets" -d "username=admin&password=test" -H "Content-Type: application/x-www-form-urlencoded"`

### 4. zsxt.sxri.net API未授权 (低危 5.3)
- `/login/get_exam_list` → 考试列表
- `/login/get_security_question_list` → 密保问题列表
- `/login/get_login_config` → 登录配置
- `/gzdz/get_apply_flow` → 报名流程
- error_info泄露源码行号
- 验证: `curl -sk "https://zsxt.sxri.net/login/get_exam_list"`

## 不可提交发现
- SUDY CMS后端全面503(11个子域)
- portal.sxri.net Liferay 4.0.0 CE JSONWS需认证
- apply.sxri.net DianCMS CAS认证保护
- 所有子域actuator返回302→.psp(SUDY CMS代理)
- nuclei/sqlmap/hydra均未发现新漏洞
- OCR验证码识别不准确

## 关键技术细节

### cs-sec.sxri.net Yii2控制器
- `/platform` → 500 (PlatformController.php)
- `/user` → 500 (UserController.php)
- `/school` → 500 (SchoolController.php)
- `/company` → 500 (CompanyController.php)
- `/resume` → 302 (需认证)
- `/meeting` → 302 (需认证)
- `/interview` → 302 (需认证)

### cs-sec.sxri.net 登录API
- POST `/welcome/validate`: user_name, password(hex_md5), captcha_token, captcha, password_level, school_token
- POST `/welcome/captcha`: captchaType=blockPuzzle → 返回图片+token+secretKey
- POST `/welcome/verify_captcha`: captchaType, captcha, captcha_token
- POST `/welcome/expire_change`: a(旧密码md5), b(新密码md5), b1(确认), c(验证码), d(用户标识)

### zsxt.sxri.net 登录参数
- user_code: 身份证号
- pwd: MD5密码
- exam_id: 考试ID
- captcha_token + captcha: 行为验证码
- verification_code: 图形验证码(mobile登录)
- 初始密码: 身份证号, 初始密码: 高考报名号

### SUDY CMS siteId列表
cw=108, cyzx=112, chgcx=17, cgxy=8, dlxy=12, gtxy=119, qjxy=120, ysxy=15, zbxy=11, db=49, 50xq=109, zsw=80, www=2
