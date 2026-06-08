# gfxy.com (陕西国防工业职业技术学院) 测试记录

日期: 2026-06-01
结论: 未发现可提交漏洞, 安全防护较好

## 目标资产

| 子域 | IP | 技术栈 | 状态 |
|------|-----|--------|------|
| www.gfxy.com | 113.200.57.254 | 博达CMS Visual SiteBuilder 9 | 200 |
| oa.gfxy.com | 113.200.57.210 | nginx + 通达OA 2025 | 200(需认证) |
| pay.gfxy.com | 113.200.57.207 | IIS 10.0 / ASP.NET / V5.TF2209.1 | 200 |
| jyxt.gfxy.com | 113.200.57.212 | IIS 10.0 / ASP.NET | 200 |
| zhaopin.gfxy.com | 113.200.57.225 | Apache Tomcat/9.0.98 / JSP | 302→200 |
| cwbx/cwapi.gfxy.com | 113.200.57.224 | nginx/1.23.4 | 200 |
| zsbm.gfxy.com | 113.200.57.211 | IIS/ASP.NET | 200 |
| dgsx.gfxy.com | 113.200.57.251 | 习讯云实习管理平台 | 200 |
| opac.gfxy.com | 113.200.57.248 | 图书馆 | 302 |
| cas.gfxy.com | 113.200.57.206 | Apache-Coyote/1.1 | 404 |
| demo.gfxy.com | 113.200.57.205 | 不可达 | 000 |

统一返回403的子域(100+): sso/webvpn/webmail/portal/one/home/ids/idp/auth/ehall/ecard/news/mrtg/bysjpt/das/edr/skxy/jdxy/dxxy/flks/fyps/blj/dzx/wzk/yyn/index 等

## 通达OA 2025 特征

- 模板: `/static/templates/2025_year_01/index.css?20241218`
- SDK: `ispirit_sdk.js?v=20240530202303`
- jQuery: `jquery.min.js` + `jquery-with-migrate.min.js`
- RSA: `/static/js/rsa/jsbn.js|prng4.js|rng.js|rsa.js`
- Bootstrap: `/static/js/bootstrap/css/bootstrap.css?20230526`
- 主题: `/static/theme/1/style.css?20190719`
- favicon hash: `1205af91d6b1638c23de1132ae0c7e0b`

### 测试结果

| 端点 | 状态 | 响应 |
|------|------|------|
| `/ispirit/interface/gateway.php` | 200 | `RELOGIN` |
| `/ispirit/login_code.php` | 200 | JSON `{codeuid, authcode}` (公开设计) |
| `/logincheck_code.php` | 200 | `{"status":0,"msg":"参数错误！"}` (所有参数组合) |
| `/ispirit/im/upload.php` | 200 | `-ERR 用户未登陆` |
| `/module/ueditor/php/controller.php` | 200 | "用户未登录" HTML页 |
| `/general/*/delete.php` (多个) | 200 | 登录页HTML (非真实delete功能) |
| `/general/attendance/personal/index.php` | 200 | 登录页HTML |
| `/inc/expired.php` | 200 | 存在 |
| `/auth_mobi.php` | 404 | 不存在(已修复/移除) |
| `/general/document/index.php` | 301 | 重定向 |

### 关键发现
- 所有敏感端点均已认证保护
- logincheck_code.php 需要正确的login_code流程(CODEUID+CODE), 随机参数均返回"参数错误"
- UEditor控制器存在但需登录态
- 未发现未授权RCE (CVE-2023-2244等均需认证)

## 博达CMS Visual SiteBuilder 9 测试

- 搜索接口: `search.jsp?wbtreeid=1001` (POST)
- 搜索参数: `lucenenewssearchkey` (base64编码) + `_lucenesearchtype=1` + `searchScope=1` + `showkeycode` (明文)
- JS: `base64.js` + `formfunc.js` + `vsbscreen.min.js` + `counter.js`
- CustomerNO: `776562626572323069754754525a554a03090003`
- DWR: 404 (不存在)
- admin: 404 (不存在)
- search API: 404 (不存在)
- SQL注入: 测试了base64编码的SQL payload, 无错误响应

## 支付平台 V5.TF2209.1

- jQuery 3.9.0 + jQuery Migrate 3.3.2
- LoginSafe.js: 完整RSA加密(jsbn.js+prng4.js+rng.js+rsa.js+base64.js)
- 登录字段: `txt_yhm`(用户名) `txt_pwd`(密码) `txt_yzm`(验证码) `rbDl`(登录类型)
- ViewState: 未加密(1194字节)但MAC已启用
- ViewState MAC验证: 篡改ViewState→302重定向到`/xysf/syserror.htm` (确认MAC enabled)
- ViewStateGenerator: `809773DA`
- Admin/Login.aspx: 302 (存在但需认证)
- Manage/Login.aspx: 302 (存在但需认证)
- WebService.asmx/DataService.asmx/Handler.ashx: 302→404 (不存在)
- CheckCode.ashx/VerifyCode.ashx: 302 (验证码接口)
- 自定义404: `/xysf/404.htm`

## Tomcat/9.0.98 版本泄露

zhaopin.gfxy.com 的404页面泄露完整版本:
```
<h3>Apache Tomcat/9.0.98</h3>
```
Manager/host-manager: 404 (不存在)
WEB-INF/web.xml: 不可达

## CSP泄露域名

zsbm.gfxy.com CSP头泄露外部服务:
```
connect-src 'self' https://lzkjadmin.sxlzsoft.com
```

## 邮件安全

- MX: `mx.ym.163.com` (网易企业邮)
- SPF: `v=spf1 include:spf.163.com ~all` (弱~all)
- DMARC: 无记录

## 安全防护评估

- Server头: 隐藏 (`*********`)
- HSTS: `max-age=31536000; includeSubdomains; preload`
- CSP: 完整配置
- X-Frame-Options: SAMEORIGIN
- X-XSS-Protection: 1; mode=block
- X-Content-Type-Options: nosniff
- 反向代理/WAF: 100+子域统一403, 集中化防护

## 停止条件

- 通达OA: 所有敏感端点需认证, 无未授权RCE → 停止
- 支付平台: ViewState MAC启用, RSA加密 → 需账号继续
- 博达CMS: 搜索无SQL注入 → 停止
- 其他子域: 403或需认证 → 停止
