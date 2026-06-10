# 南京林业大学 (njfu.edu.cn) SRC测试模式

## 目标概况
- IP: 121.248.150.233
- 反代: rump/e (所有子域统一)
- 主站: IIS 6.0 (反代后) + Viriy CMS (`/DFS/` 模板, `/bcms/` 后端)
- WAF: 主站 IIS 层"访问禁止"模式 (200 + body含"访问禁止" + 事件编号)
- 子域: 150+ (subfinder枚举)
- VPN: Sangine aTrust 2.0 (vpn.njfu.edu.cn)
- 邮件: QQ Exmail (mail.njfu.edu.cn, Wwebsvr)
- 5G网络: Dr.COM Server (5g.njfu.edu.cn)
- 云盘: pan.njfu.edu.cn (fc_session cookie, SSO登录)

## 高价值子域
| 子域 | 用途 | 状态 |
|------|------|------|
| uia.njfu.edu.cn | CAS统一认证 (wisedu) | 可达 |
| ehall.njfu.edu.cn | 网上办事大厅 (金智教育) | 可达，JSONP API可用 |
| eseal.njfu.edu.cn | 电子签章 (契约锁qiyuesuo.com) | 可达，CORS漏洞 |
| jwxt.njfu.edu.cn | 教务系统 | 302到CAS |
| webvpn.njfu.edu.cn | WebVPN (rump/e) | 301 |
| vpn.njfu.edu.cn | VPN (Sangine aTrust 2.0) | 302 |
| 5g.njfu.edu.cn | 5G校园网 (Dr.COM) | 200 |
| bsmanager.njfu.edu.cn | CMS后台 | 301到/bcms |
| pan.njfu.edu.cn | 云盘 | 302到SSO |
| gsnfu.njfu.edu.cn | 研究生院 | 200 (静态) |
| renshi.njfu.edu.cn | 人事处 | 200 (bcms) |
| xgc.njfu.edu.cn | 学工处 | 200 (WCM CMS) |

## 不可达/无价值子域
- oa.njfu.edu.cn → 000
- sso/auth/admin/ids/idp/passport → 198.18.x.x (保留IP，非真实服务)
- opac.njfu.edu.cn → 000
- dagl.njfu.edu.cn → 000
- kjs.njfu.edu.cn → 000

## 已确认漏洞

### 1. eseal.njfu.edu.cn CORS任意Origin反射+Credentials (高危)
- 契约锁(qiyuesuo.com)平台默认配置
- 所有API端点(/api/user, /api/seal, /api/auth)均反射任意Origin
- `access-control-allow-credentials: true`
- CSP: `script-src *` (极宽松)
- 验证: `curl -sk -D- "https://eseal.njfu.edu.cn/" -H "Origin: https://evil.com" | grep -i access-control`

### 2. CAS嵌套URL Open Redirect (中危)
- CAS接受嵌套URL: `service=https://ehall.njfu.edu.cn/login?service=https://evil.com`
- ehall login页面接受任意service参数无验证
- ehall `/redirect?url=` 端点同样传递到CAS
- 攻击链: 用户点击恶意链接 → CAS登录 → ehall重定向到evil.com
- 验证: `curl -sk "https://uia.njfu.edu.cn/authserver/login?service=https://ehall.njfu.edu.cn/login?service=https://evil.com" | grep -oP 'action="[^"]*"'`

### 3. CAS JSESSIONID URL泄露 (低危)
- CSS href: `/authserver/custom/css/login1.css;jsessionid=XXX`
- JS src: `/authserver/custom/js/jquery.min.js;jsessionid=XXX`
- 图片src: `/authserver/custom/images/image_1.png;jsessionid=XXX`
- 约21处泄露
- 验证: `curl -sk "https://uia.njfu.edu.cn/authserver/login" | grep -oP 'href="[^"]*jsessionid[^"]*"' | wc -l`

### 4. CAS pwdDefaultEncryptSalt泄露 (低危)
- 每个会话轮转盐值
- JS中硬编码: `var pwdDefaultEncryptSalt = "XXX"`
- 验证: `curl -sk "https://uia.njfu.edu.cn/authserver/login" | grep -oP 'pwdDefaultEncryptSalt\s*=\s*"[^"]*"'`

## ehall JSONP API
- `serviceCenterData.json` — 应用列表(公开)，但响应极慢(常60s超时)
- `school.json` — 学校配置
- `userInfo.json` — 站点结构
- `appIntroduction.json?appId=XXX` — 应用详情(无PII)
- 其他端点(userSearchHistory/myAppService/serviceRoleApp)需登录
- appIds: 6487147974980611(博物馆预约), 5276511943829139(固话托收), 5530522108024834(人事流程引擎), 4997522740549769(学生问卷调查)

## 测试注意事项
- CAS/ehall有请求频率限制，需用XFF绕过: `-H "X-Forwarded-For: 10.0.0.1"`
- ehall serviceCenterData.json响应极慢，建议设15s超时
- 主站WAF"访问禁止"返回200而非403，需检查body内容
- swagger-ui.html/.git/HEAD等路径返回200但body为空(反代拦截模式)
- sso/auth/admin等子域解析到198.18.x.x(保留IP)，非真实服务

## 地址信息
- 补天地址: 江苏省南京市玄武区龙蟠路159号
- 行业: 教育
- 域名归属: 南京林业大学
