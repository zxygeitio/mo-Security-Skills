# hnca.edu.cn (河南农业职业学院) 测试记录 (2026-06-07)

## 目标概况
- 域名: hnca.edu.cn
- IP: 61.163.83.34(www), 61.163.83.35(ehall/authserver/xljk), 61.163.83.36(vpn)
- 学校: 河南农业职业学院 (schoolId: 13790)
- 地址: 河南省郑州市中牟县

## 子域资产
| 子域 | IP | 服务 |
|------|-----|------|
| www.hnca.edu.cn | 61.163.83.34 | 博达CMS (Server: rump/c) |
| ehall.hnca.edu.cn | 61.163.83.35 | 金智教育ehall (openresty) |
| authserver.hnca.edu.cn | 61.163.83.35 | 金智教育CAS (openresty) |
| xljk.hnca.edu.cn | 61.163.83.35 | 空页面(226B) |
| vpn.hnca.edu.cn | 61.163.83.36 | 深信服SSL VPN M7.6.9R1 |
| mail.hnca.edu.cn | 14.17.5.207 | 腾讯企业邮箱(Exmail) |
| dns.hnca.edu.cn | 125.219.172.8 | DNS服务器 |
| smtp.hnca.edu.cn | smtp.exmail.qq.com | SMTP(CNAME到腾讯) |
| osp.hnca.edu.cn | 172.16.111.10 | 云景教育APM(内网) |

## 已确认漏洞

### 1. CAS CORS反射型漏洞 [高危]
authserver.hnca.edu.cn 所有端点将Origin直接反射到ACAO + ACAC:true

受影响端点(8个):
- /authserver/login
- /authserver/status
- /authserver/serviceValidate
- /authserver/getBackPasswordMainPage.do
- /authserver/validatePasswordAjax.do
- /authserver/index.do
- /authserver/services
- /authserver/getEncryptKey.do

OPTIONS预检也通过，POST请求也被CORS允许。

验证命令:
```bash
curl -sk -D- 'https://authserver.hnca.edu.cn/authserver/login' -H 'Origin: https://evil.com' | grep -i access-control
# ACAO: https://evil.com + ACAC: true
```

### 2. VPN M7.6.9R1 在CVE影响范围内 [高危边界]
版本M7.6.9R1在SF-PSIRT-20220032影响范围(M7.5-M7.6.9R2)内。
rpc_gateway.fcgi / cmd_process.fcgi 已404(新版本修补)。
仅版本确认不足以通过SRC审核。

### 3. CAS status信息泄露 [中危]
/authserver/status 无需认证返回服务器健康信息:
- 内存: 179.27MB free, 512.03MB total
- 会话: com.wisedu.authserver.ticket.registry.CacheTicketRegistry

### 4. CAS JSESSIONID URL泄露 [低危]
CSS/JS资源URL中暴露JSESSIONID:
```
/authserver/custom/js/login-wisedu_v1.0.js;jsessionid=XXX
/authserver/custom/js/encrypt.js;jsessionid=XXX
```

## 技术栈指纹
- 主站: 博达CMS (Server: rump/c, counter.js, /system/resource/)
- CAS: 金智教育wisedu (openresty, pwdDefaultEncryptSalt, login-wisedu_v1.0.js, encrypt.js)
- ehall: 金智教育 (openresty, /jsonp/*, YUNJING APM)
- VPN: 深信服SSL VPN M7.6.9R1 (/por/login_auth.csp, /por/login_psw.csp)
- 邮件: 腾讯企业邮箱 (Server: Wwebsvr, smtp.exmail.qq.com)
- APM: 云景教育 (s.yunjingedu.com, osp.hnca.edu.cn内网)

## 负证据
- ehall所有路径302到CAS认证(actuator/druid/swagger/env)
- ehall JSONP端点(readyAndOpenService/serviceRoleApp/myAppService)需登录
- ehall serviceCenterData.json在CERNET下超时(20-30秒)
- 主站/api/返回"hello api"但所有子路径返回404
- 博达CMS搜索API(/_web/_search/)返回404
- VPN rpc_gateway.fcgi/cmd_process.fcgi 404
- VPN changepwd.csp 需session("unexpected user service")
- needCaptcha对所有用户名返回true(无枚举价值)
- validatePasswordAjax.do对所有用户名返回相同错误(无枚举价值)
- authserver actuator/druid/swagger 404

## 测试教训
1. CERNET教育网(61.163.x.x)响应慢，serviceCenterData.json容易超时，需加searchKey缩小结果
2. wisedu CAS CORS是框架级默认配置缺陷，不是个别学校问题
3. needCaptcha用户枚举需用20+随机用户名验证，不可靠
4. 深信服VPN M7.6.9R1虽在CVE范围内，但常见RCE路径已404，需进一步利用证明
