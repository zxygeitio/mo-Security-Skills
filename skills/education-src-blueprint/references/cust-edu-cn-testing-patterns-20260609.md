# cust.edu.cn (长春理工大学) Testing Patterns — 2026-06-09 深度测试

**Date**: 2026-06-09 (第二轮，基于06-02的补充)
**Result**: 1 new submitable vuln (数据库端口暴露, 中危), 1 previously submitted (CAS Open Redirect)

## 新发现 (06-09)

### 致远OA服务器公网暴露数据库端口 (中危)
- **IP**: 121.37.5.226 (华为云ECS, ecs-121-37-5-226.compute.hwclouds-dns.com)
- **暴露端口**: MySQL(3306), Redis(6379), MongoDB(27017), IIS(80), Seeyon(8090), 8080, 8443, 9090
- **验证**: `nmap -sS -Pn -p 3306,6379,27017 121.37.5.226` → 全部open
- **限制**: 实际TCP连接被过滤(tcpwrapped)，nc/redis-cli/mysql连接均超时
- **判断**: SYN扫描确认端口开放，但完整TCP握手被防火墙拦截
- **风险**: 防火墙规则变更时数据库将直接暴露；Redis/MongoDB默认无密码

### CAS Actuator端点存在 (低危)
- **端点**: /cas/actuator/health, /cas/actuator/env, /cas/actuator/info, /cas/actuator/mappings, /cas/actuator/beans, /cas/actuator/configprops, /cas/actuator/dump
- **响应**: 全部返回403 (存在但被WAF/ACL拦截)
- **CAS版本**: 基于webjars推断为CAS 5.3.x (jQuery 3.3.1 + Bootstrap 4.1.0 + PAC4J)
- **修复建议**: nginx层面完全屏蔽/actuator路径

### CAS密码重置流程分析
- **触发**: POST /cas/login, `_eventId=resetPassword`
- **重置页面**: 包含`passwordManagementForm`和三个验证方式按钮
- **验证方式**:
  - `sendMsg('weschool')` — 发微校验证码
  - `sendMsg('qywechat')` — 发企业微信验证码
  - `sendMsg('aliyunsms')` — 发短信验证码(阿里云)
- **sendMsg函数**: 设置`msgType`隐藏字段后提交表单(`$('#fm1').submit()`)
- **findAccount流程**: POST with `_eventId=findAccount` + `msgType=aliyunsms`
- **用户枚举**: 无效(所有用户名返回相同200 49609字节响应)
- **验证码**: 通过"信息化中心公众号"推送，需激活微信校园卡

### Shiro rememberMe测试 (不一致结果)
- **Portal**: portal.cust.edu.cn/custp/ 使用Apache Shiro
- **默认密钥测试**: `kPH+bIxk5D2deZiIxcaaaA==`
- **结果不一致**: 有时10/10接受，有时5/10接受，有时0/10接受
- **可能原因**: 负载均衡(多个后端实例不同配置)、Shiro filter不活跃、网络超时
- **nuclei扫描**: 使用`shiro-deserialization-detection.yaml`未确认漏洞
- **结论**: 无法构造有效PoC，不建议提交

### 其他测试结果
- **ehall直接IP访问**: 221.8.23.23和210.47.2.25均被WebVPN拦截(302→wwwn.cust.edu.cn)
- **114.116.241.75:8020**: zs.cust.edu.cn泄露的外部IP，端口open但HTTP无响应
- **CAS @绕过**: `service=https://mysso.cust.edu.cn@evil.com/` 被接受(Open Redirect变体)
- **CAS nested URL**: `service=https://mysso.cust.edu.cn/cas/login?service=https://evil.com/` 被编码接受
- **Seeyon OA CORS**: REST token等端点`Access-Control-Allow-Origin: *` + `Credentials: true`，但API需认证
- **Seeyon OA REST**: /rest/orgMember返回"HTTP 404"纯文本，/rest/token/identity返回异常页面

## 06-02已有发现 (不再重复)
- CAS Open Redirect (中危, 已提交)
- WeChat AppID泄露 (低危)
- 内网IP泄露 (低危)
- 博达CMS jQuery旧版本 (不报)

## 防护总结
- **WebVPN(网瑞达)**: ehall/jwc/教务系统全部在WebVPN后面，直接IP访问无效
- **CAS**: Apereo CAS + PAC4J，无CORS，Actuator返回403
- **Seeyon OA**: V8.0SP2已修补所有已知CVE，REST API需认证
- **WAF**: wengine WAF保护大部分子域

## 关键命令
```bash
# 子域枚举
subfinder -d cust.edu.cn

# 端口扫描
nmap -sS -Pn -p 3306,6379,27017 121.37.5.226

# CAS Open Redirect
curl -sk 'https://mysso.cust.edu.cn/cas/login?service=https://evil.com/'

# CAS密码重置
curl -sk 'https://mysso.cust.edu.cn/cas/login' -d 'execution=TOKEN&_eventId=resetPassword'

# Seeyon OA CORS
curl -sk -D- 'http://121.37.5.226:8090/seeyon/rest/token' -H 'Origin: https://evil.com'

# Shiro默认密钥测试
for i in $(seq 1 10); do
  curl -sk 'https://portal.cust.edu.cn/custp/index' \
    -H 'Cookie: rememberMe=kPH+bIxk5D2deZiIxcaaaA==' \
    -D- 2>/dev/null | grep 'rememberMe'
done
```

## 教训
- **负载均衡导致测试不一致**: Shiro rememberMe测试结果在不同请求间变化，需要多次测试取统计结果
- **WebVPN绕过无效**: 直接IP访问、Host头注入、HTTP/HTTPS切换均被拦截
- **密码重置需captcha**: CAS密码重置表单包含captcha字段，无法自动化测试
