# 陕西国防工业职业技术学院 (gfxy.com) 测试记录

## 基本信息
- 域名: gfxy.com
- IP: 113.200.57.254 (主站)
- 学校全称: 陕西国防工业职业技术学院
- 行业: 教育
- 地址: 陕西省西安市鄠邑区(需确认精确区)

## 资产清单 (2026-06-01)

### 独立IP子域名
| IP | 子域 | 技术栈 | 状态 |
|---|---|---|---|
| 113.200.57.205 | demo.gfxy.com | 未知 | 不可达 |
| 113.200.57.206 | cas.gfxy.com | Apache-Coyote/1.1 | 443全404, 8443仅"Hello!" |
| 113.200.57.207 | pay.gfxy.com | IIS 10.0/ASP.NET | 校园统一支付平台 |
| 113.200.57.210 | oa.gfxy.com | nginx/PHP | 通达OA 2025 |
| 113.200.57.211 | zsbm.gfxy.com | IIS/ASP.NET | 分类考试招生管理系统 |
| 113.200.57.212 | jyxt.gfxy.com | IIS 10.0/ASP.NET | 就业系统 |
| 113.200.57.224 | cwbx/cwapi/cw.gfxy.com | nginx/1.23.4 | 移动报销(财务) |
| 113.200.57.225 | zhaopin.gfxy.com | Tomcat/9.0.98 JSP | 招聘系统 |
| 113.200.57.248 | opac.gfxy.com | 未知 | 图书馆(302) |
| 113.200.57.251 | dgsx.gfxy.com | 静态HTML | 习讯云实习管理平台 |

### 主站IP (113.200.57.254) 托管子域 (100+个)
大部分返回403 Forbidden，包括: sso/webvpn/webmail/portal/one/home/ids/idp/auth/ehall/ecard/news/mrtg/bysjpt/das/edr/skxy/jdxy/dxxy/flks/fyps/blj/dzx/wzk/yyn等

### 博达CMS主站 (www.gfxy.com)
- CMS: Visual SiteBuilder 9 (`<!--Announced by Visual SiteBuilder 9-->`)
- CustomerNO: 776562626572323069754754525a554a03090003
- 搜索接口: `search.jsp?wbtreeid=1001` (POST, lucenenewssearchkey base64编码)
- 搜索未发现SQL注入
- counter.js泄露: `/system/resource/code/datainput.jsp` (返回空image/gif)

### 通达OA (oa.gfxy.com)
- 版本: 2025_year_01模板 (CSS路径 `static/templates/2025_year_01/`)
- 旧版模板仍存在: 2015_01, 2016_01
- 所有敏感端点已认证保护(gateway.php/UEditor/upload/delete)
- logincheck_code.php返回"参数错误"
- IP速率限制: 大量请求后封禁源IP(浏览器可绕过)
- RSA加密: 1536-bit key, modulus 384字符hex, exponent 10001
- CAPTCHA: 懒加载(焦点触发), 首次登录可能不需要
- QR码登录: login_code_uid.php → login_code.php → login_code_check.php → logincheck_code.php
- 详见 `references/tongda-oa-2025-fingerprint.md`

### 支付平台 (pay.gfxy.com/xysf/)
- 版本: V5.TF2209.1 (console.log泄露)
- 技术栈: IIS 10.0 + ASP.NET WebForms
- ViewState MAC已启用(篡改ViewState重定向到syserror.htm)
- 登录表单: txt_yhm(用户名/学号) + txt_pwd(密码) + txt_yzm(验证码)
- RSA加密: LoginSafe.js (17KB, 包含jsbn/prng4/rng/rsa/base64)
- 密码找回: t_rybh(人员编号) + t_reset_yzm(验证码) + 密保验证
- 初始密码规则: "身份证号舍去末位后6位"
- 管理入口: Admin/Login.aspx, Manage/Login.aspx (均需认证)

### 招聘系统 (zhaopin.gfxy.com)
- Apache Tomcat/9.0.98 (404页面泄露版本)
- JSP招聘系统, 主页返回500
- 验证码: `/product/recruit/pages/verfication.jsp` (注意拼写错误)
- register.jsp/retrievePassword.jsp返回404

### 就业系统 (jyxt.gfxy.com)
- IIS 10.0 + ASP.NET
- 登录入口: `/frame/login.aspx`
- `/Frame/Default.aspx`返回重定向到登录

### 财务报销 (cwbx/cwapi.gfxy.com)
- nginx/1.23.4
- "移动报销"系统
- config JS (`application.prod.web.js`)返回404
- eruda调试开关注释: `// eruda.init();`

### 实习管理 (dgsx.gfxy.com)
- 习讯云第三方SaaS平台
- CSP泄露: `connect-src 'self'` + `oss-resume.xixunyun.com`

## ⚠️ 防火墙假阳性模式

113.200.57.206 (cas.gfxy.com) 端口扫描显示所有1-9000端口均为open，但实际连接时:
- 大部分端口返回空响应(仅换行符)
- 3306(MySQL)/6379(Redis)不返回服务banner
- 8080返回代理banner: `(UNKNOWN) [113.200.57.206] 8080 (http-alt) : Connection...`

**结论**: 这是防火墙/NAT设备接受TCP连接但不转发到实际服务的行为，不是真实开放端口。
其他IP (205/207/210/211/212/224/225/248/251) 也显示相同模式。

## 安全防护评估
- WAF/反向代理: Server头隐藏(`*********`), 批量子域403
- HSTS: max-age=31536000; includeSubdomains; preload
- CSP: 完整配置(self + 数据URI + 特定白名单域名)
- X-Frame-Options: SAMEORIGIN (双重设置)
- X-XSS-Protection: 1; mode=block
- X-Content-Type-Options: nosniff
- Referrer-Policy: no-referrer-when-downgrade
- X-Download-Options: noopen
- X-Permitted-Cross-Domain-Policies: master-only
- 邮件: MX=mx.ym.163.com, SPF=v=spf1 include:spf.163.com ~all, 无DMARC

## 结论
安全防护较好，未发现可提交的实质漏洞。建议获取测试账号后重新测试通达OA和支付平台。
