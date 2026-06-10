# cuit.edu.cn 成都信息工程大学 测试记录 (2026-06-02)

## 目标信息
- 学校: 成都信息工程大学
- 域名: cuit.edu.cn
- IP: 210.41.224.132 (CERNET教育网)
- WAF: 主站Server头隐藏(*********)
- 认证: ywtb.cuit.edu.cn (一网通办, CAS + Vite SPA + Vue.js 2.7.16)

## 子域名资产 (192个)
subfinder枚举192个子域名。高价值可访问子域:
- ywtb.cuit.edu.cn - 一网通办 (CAS认证中心, Vite SPA)
- oa.cuit.edu.cn - 致远OA A8N V10.0SP1 (V10_0SP1_251202_152011_0, 302→ywtb CAS认证)
- idp.cuit.edu.cn - Shibboleth IdP (nginx/1.21.5, Jetty容器)
- webvpn.cuit.edu.cn - Sangfor EasyConnect WebVPN
- email.cuit.edu.cn - 网易企业邮箱登录
- cjypt.cuit.edu.cn - 继续教育平台 (schoolId=129582, JSESSIONID .web1)
- zkypt.cuit.edu.cn - 科研一体化平台 (schoolId=129670, JSESSIONID .jvm66)
- notice.cuit.edu.cn - 一网通办入口
- user.cuit.edu.cn - nginx, 同ywtb SPA
- ceshi.cuit.edu.cn - 应用数学学院 (VSB 9, jQuery 1.4.2)
- klas.cuit.edu.cn - 大气探测重点开放实验室 (VSB 9)
- iwm.cuit.edu.cn - 人工影响天气研究院 (VSB 9)
- ztb.cuit.edu.cn - 资产招投标中心 (VSB 9)
- security.cuit.edu.cn - 403, CSP含unsafe-inline/unsafe-eval
- app.cuit.edu.cn - 不可达
- sslvpn/vpn2/jxglxt/jwc/pan - 不可达(超时)

## 已确认漏洞 (2026-06-02)

### 1. CAS登录接口用户枚举 [中危]
- URL: https://ywtb.cuit.edu.cn/api/base/login
- 存在账号(admin): "登录失败(在校园网外的地方不支持账号密码登录，请使用微信扫码登录！)"
- 不存在账号(nonexistent999): "账号不存在"
- 复现: curl -sk 'https://ywtb.cuit.edu.cn/api/base/login' -X POST -H 'Content-Type: application/json' -d '{"username":"admin","password":"***"}'

### 2. CAS多接口未授权信息泄露 [中危]
- URL: https://ywtb.cuit.edu.cn/api/base/apps (14KB, 全部应用+角色+分组)
- URL: https://ywtb.cuit.edu.cn/api/base/stats/dept (1.3KB, 全校部门ID+名称)
- URL: https://ywtb.cuit.edu.cn/api/base/index_apps (66KB, 完整应用配置)
- URL: https://ywtb.cuit.edu.cn/api/base/register/config (注册配置+匿名token)
- URL: https://ywtb.cuit.edu.cn/api/base/wx/qr_code (微信AppID: wx6651bf981310e1a1)
- URL: https://ywtb.cuit.edu.cn/api/base/config (系统配置)

### 3. 致远OA REST API CORS配置不当 [低危]
- URL: https://oa.cuit.edu.cn/seeyon/rest/*
- Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true
- 受影响端点: /seeyon/rest/{token,orgMember,organization,department,user,session,service}

## CAS认证架构
- 所有需认证系统通过 ywtb.cuit.edu.cn/authserver/login 统一认证
- SPA路由: /#/login?loginType=cas → /api/base/login (POST)
- 微信扫码: /api/base/wx/qr_code → wx6651bf981310e1a1
- 密码重置: /api/base/retrieve/{valid,check,resetPwd} - retrieve/check对不存在用户返回"登录账号不存在"(不能用于枚举)
- 外网限制: 密码登录仅限校园网，外网需微信扫码
- /api/ssoLogin/cxd → 302 → /admin + YWTBSESSIONID cookie (domain=.cuit.edu.cn)

## WebVPN (Sangfor EasyConnect)
- URL: https://webvpn.cuit.edu.cn
- 登录: /por/login_psw.csp (POST, XML响应含ErrorCode)
- TWFID cookie + CSRF_RAND_CODE保护
- 暴力破解保护: ErrorCode 20041 "You are trying brute-force login"
- SMS登录(/por/login_sms.csp): "unexpected user service"
- Token登录(/por/login_token.csp): "User timed out!"

## cjypt/zkypt 继续教育/科研平台
- 技术栈: jQuery + SM4加密(des.js)
- SM4密钥硬编码: 5BD730C485F2AF10, 90ACB357C1AC99D4
- 登录: /commonlogin/commoncheck?tmp=xxx (POST)
- 无用户枚举: 所有用户名返回"用户或密码不正确"
- 登录模式: 学生用户 + 管理员用户

## CSP配置
- 主站CSP: frame-src 'self' *.cuit.edu.cn ek.cuit.edu.cn; default-src ... 'unsafe-inline' 'unsafe-eval'
- ywtb CSP: default-src 'self' *.cuit.edu.cn *.qq.com *.qlogo.cn 'unsafe-inline' 'unsafe-eval' blob: data:

## 内部服务泄露 (来自index_apps)
- cuit.edu.cn:56443/labms/ - 实验室管理系统
- cuit.edu.cn:8072/ - 未知服务
- cuit.edu.cn:8081/ - 未知服务
- cuit.edu.cn:8084 - 未知服务
- kygl.cuit.edu.cn - 科研管理系统
- scxy.cuit.edu.cn - 未知系统
- eams.cuit.edu.cn - 教务管理系统

## CERNET网络特性
- IP段: 210.41.224.x (主站/OA/IdP)
- 外网访问速度慢, 串行curl严重低效
- 必须用批量脚本: edu-batch-probe.py (5域名2.4秒)
- delegate_task子代理全部超时(900s)
- /usr/bin/python3 运行脚本(shell python3 shim慢)
