# DataCanvas 九章云极 SRC 测试记录 (2026-05-27)

## 目标范围
- 核心: *.alayanew.com (¥800-2000高危)
- 常规: oa.datacanvas.com, www2.datacanvas.com, ones.datacanvas.com (¥500-1000高危)
- 排除: *.proxy.*.alayanew.com, *.sproxy.*.alayanew.com, enterprise.alayanew.com

## 资产发现
- alayanew.com: 59子域(subfinder), 排除21个proxy/sproxy后37个
- datacanvas.com: 41子域(subfinder)
- 存活资产: 12个(多数datacanvas.com子域不通/内网)

### 存活资产指纹
| 域名 | IP | 技术栈 | 标题 |
|------|-----|--------|------|
| bi.alayanew.com | 8.141.27.142 (US/Alibaba) | Java, JSESSIONID, jQuery | 经营管理平台 登录页面 |
| sso.alayanew.com | 8.141.17.204 (US/Alibaba) | Tengine, Casdoor SSO | Alaya NeW |
| bsm.alayanew.com | 8.152.153.156 (US/Alibaba) | Tengine, Apache APISIX | Alaya NeW |
| www.alayanew.com | - | Apache APISIX, React SPA | - |
| docs.alayanew.com | - | HSTS, 静态文档站 | 九章智算云文档中心 |
| apps.datacanvas.com | 47.93.35.1 (CA/Alibaba) | React SPA, HSTS | DataCanvas apps |
| codingplan.alayanew.com | - | One API Gateway, React | Alaya Code |
| ylearn.datacanvas.com | - | Python文档 | YLearn |
| bugfix/feature/test.apps.datacanvas.com | - | 403 Forbidden | - |
| tableagent.datacanvas.com | - | 503 | - |

### 不通资产(可能内网)
oa.datacanvas.com, www2.datacanvas.com, ones.datacanvas.com, gitlab.datacanvas.com, chat.datacanvas.com, finance.datacanvas.com, playground.datacanvas.com, mmalaya.datacanvas.com, doc.datacanvas.com, files.datacanvas.com

## 发现漏洞

### 1. codingplan.alayanew.com /api/status 未授权配置信息泄露 [中危]
- URL: https://codingplan.alayanew.com/api/status
- 返回: OIDC client_id(16aa7e14f26c731ba894)、管理员UUID(cb704eeb-78c9-4c91-af5b-2df031933b17)、注册配置、后端地址、OSS地址
- 系统: One API (开源AI API网关)
- curl: `curl -sk "https://codingplan.alayanew.com/api/status"`

### 2. codingplan.alayanew.com 任意用户注册 [中危]
- URL: https://codingplan.alayanew.com/api/user/register
- 配置: password_register_enabled=true, email_verification=false, turnstile_check=false
- 验证: 注册testuser12345成功(ID:3754), 登录返回完整用户对象
- curl: `curl -sk -X POST "https://codingplan.alayanew.com/api/user/register" -H "Content-Type: application/json" -d '{"username":"test","password":"Test123!","email":"test@test.com"}'`

### 3. apps.datacanvas.com CORS反射型 [低危]
- URL: https://apps.datacanvas.com/api/* (所有API路径)
- 响应: access-control-allow-origin: https://evil.com (反射) + access-control-allow-origin: * (通配符)
- 无Access-Control-Allow-Credentials头
- 前端使用withCredentials:true

### 4. sso.alayanew.com OIDC/JWKS暴露 [低危]
- URL: https://sso.alayanew.com/.well-known/openid-configuration
- URL: https://sso.alayanew.com/.well-known/jwks
- 泄露: 完整OIDC端点链、password grant支持、RSA签名证书x5c链
- SSO系统: Casdoor (基于Casbin)

### 未提交发现(不够门槛)
- bi.alayanew.com 被云防护WAF拦截(403 "安全拦截提示")
- docs.alayanew.com sitemap泄露OAuth client_id(cb4dcdeb3113cfd834b4) - 公开client_id非漏洞
- docs.alayanew.com sitemap泄露codingplan.alayanew.com AI API端点(从docs页面HTML提取)
- 所有目标缺少X-Frame-Options - 低危一般不收
- www.alayanew.com/.svn/entries 返回405(Tengine WAF) - 非真实SVN泄露

### 验证方法(2026-05-27 最终验证)
漏洞1: 用全新请求重测/api/status → 成功返回完整配置
漏洞2: 用新用户名butiancheck0527注册 → 成功(ID:3757)，登录成功
漏洞3: 用不同Origin(butian-test.cn)测试CORS → 被反射
漏洞4: 重测OIDC配置 → issuer/grant_types/jwks均返回

### 去重确认
session_search查询"datacanvas alayanew codingplan" → 0结果
search_files查询"*datacanvas*" → 0文件
结论: 全新目标，无重复提交风险

## 报告位置
/tmp/vuln_reports/datacanvas/report-{1,2,3,4}-*.txt

## 测试耗时
约45分钟完成全部侦察+验证+报告

## 验证脚本
一键验证脚本: `references/scripts/datacanvas-verify.sh`
注意: 必须用 `-4` 强制IPv4 + `--connect-timeout` 防止curl卡住。用户机器到codingplan.alayanew.com可能不通(Alibaba Cloud US IP)，脚本内已处理超时。
