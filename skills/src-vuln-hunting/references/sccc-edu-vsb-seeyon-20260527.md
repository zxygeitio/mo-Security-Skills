# sccc.edu.cn (四川化工职业技术学院) 测试记录 2026-05-27

## 目标概况
- IP: 61.188.205.41
- CMS: 博达VSB (Visual SiteBuilder)
- OA: 致远A8+ V8.2SP1 (build V8_2SP1_231013_1903070)
- 邮件: 网易企业邮 (mxmail.netease.com)
- WAF: wengine防火墙

## 子域名资产 (78个)
| 子域名 | 状态 | 系统 |
|--------|------|------|
| oa.sccc.edu.cn | 302→seeyon | 致远OA A8+ V8.2SP1 |
| seafile.sccc.edu.cn | 302→login | Seafile文件共享 |
| pay.sccc.edu.cn | 200 SPA | 缴费大厅(Vue.js+Element UI) |
| xy-file.sccc.edu.cn | 200 | 文件服务器(CORS *) |
| jwc.sccc.edu.cn | 200 | 教务处(VSB CMS) |
| lib.sccc.edu.cn | 200 | 图书馆(VSB CMS) |
| xy-h5.sccc.edu.cn | 200 | 四川化工校友会 |
| rsc.sccc.edu.cn | 200 | 人事处(VSB CMS) |
| wvpn.sccc.edu.cn | 000 | VPN(不可达) |
| xwgj.sccc.edu.cn | 302 | 外教管理 |

## 已确认漏洞

### 1. getSession.jsp未授权会话获取 (中危)
- URL: https://sccc.edu.cn/system/resource/getSession.jsp
- 响应: 返回32位JSESSIONID (如 7B36D73EFA0AEA27FAAA00544F1C5FAC)
- 来源: token.js中暴露接口路径
- 利用: session可用于getToken.jsp返回"preview"模式

### 2. 致远OA版本信息泄露 (低危)
- URL: https://oa.sccc.edu.cn/seeyon/main.do
- CSS引用: /seeyon/common/all-min.css?V=V8_2SP1_231013_1903070
- 标题: 致远A8+协同管理软件 V8.2SP1

### 3. xy-file CORS通配符 (低危)
- URL: https://xy-file.sccc.edu.cn/
- 响应头: Access-Control-Allow-Origin: *
- 暴露方法: GET, POST, OPTIONS, PUT, DELETE
- 注意: Access-Control-Allow-Credentials: false (不可窃取cookie)

### 4. pay系统前端泄露后端配置 (信息泄露)
- URL: https://pay.sccc.edu.cn/static/js/app.7c5014eb.js
- 泄露: http://localhost:8090/druid (Druid监控控制台)
- API基础: baseURL:"/api/"
- 认证: user-token机制

## 邮件安全 (已正确配置)
- DMARC: v=DMARC1; p=quarantine; fo=1
- SPF: v=spf1 include:spf.qiye.163.com -all (hardfail)
- DKIM: 已配置 (RSA 1024bit)
- MX: hzmx01/02.mxmail.netease.com

## 安全评估
- WAF有效拦截敏感路径(.env→wengine-firewall.html)
- 致远OA默认密码已修改(全部401)
- Seafile需认证，无未授权访问
- 主站VSB CMS getSession.jsp是最主要风险点
- 未发现RCE/SQLi/认证绕过等高危漏洞

## 不建议提交的发现
- pay.sccc.edu.cn /actuator等为SPA fallback(返回相同HTML)
- Seafile系统需认证，无未授权访问
- 致远OA默认密码已修改
- robots.txt/sitemap.xml返回自定义404(null字节填充)
- CORS credentials=false，不可用于凭证窃取
