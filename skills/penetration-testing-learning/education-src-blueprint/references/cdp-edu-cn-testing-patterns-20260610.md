# cdp.edu.cn 成都职业技术学院 测试模式 (2026-06-10)

## 概要
- 域名: cdp.edu.cn (成都职业技术学院)
- 子域枚举: subfinder获取29个子域
- 网络: 所有子域解析到 198.18.0.x (Cloudflare WARP保护), curl可正常访问
- CAS系统: 联奕科技 lyuapServer (非金智wisedu)
- ehall: UmiJS SPA (非金智ehall)

## 指纹识别

### CAS统一身份认证 (cas.cdp.edu.cn)
- Server: nginx
- CAS实现: 联奕科技 lyuapServer
- 登录路径: `/lyuapServer/login`
- 验证路径: `/lyuapServer/serviceValidate` (返回JSON或CAS XML)
- 登录页大小: 4499B
- SPA fallback: 所有未匹配路径返回相同4499B登录页 (包括 /actuator, /status 等)
- 安全中心: 端口4102(PC端)和4107(移动端)公网暴露

### 联奕CAS安全中心端口暴露 (重要发现)
CAS登录页JS中硬编码了安全中心URL:
```javascript
window.safeQuestion = 'https://cas.cdp.edu.cn:4102/#/problem';
window.safePassWord = 'https://cas.cdp.edu.cn:4102/#/password/passwordFound';
window.mobileSafePassWord = 'https://cas.cdp.edu.cn:4107/#/password';
window.mobileSafeAppeal = 'https://cas.cdp.edu.cn:4107/#/complain/baseInfo';
window.mobileSafeProblem = 'https://cas.cdp.edu.cn:4107/#/question';
```

4102端口标题: "安全中心", 包含:
- 安全问题功能 (`/#/problem`)
- 密码找回功能 (`/#/password/passwordFound`)

4107端口标题: "安全中心" (移动端UmiJS SPA), 包含:
- 密码找回 (`/#/password`)
- 账号申诉 (`/#/complain/baseInfo`)
- 常见问题 (`/#/question`)

检测命令:
```bash
curl -sk 'https://cas.cdp.edu.cn/' 2>/dev/null | grep -oP 'https?://[^"'"'"']*'
```

风险: 如果安全问题验证逻辑存在缺陷(可暴力枚举/答案可预测), 可导致任意账号密码重置。

### CAS Spring Boot错误信息泄露
路径: `/lyuapServer/proxy`, `/lyuapServer/status`, `/lyuapServer/info`, `/lyuapServer/env`
返回: `{"timestamp":"...","status":404,"error":"Not Found","path":"/lyuapServer/proxy"`
价值: 低 (仅泄露框架特征和时间戳)

### aic.cdp.edu.cn (ASP.NET应用)
- Server: Microsoft-IIS/10.0
- X-Powered-By: ASP.NET
- X-AspNet-Version: 4.0.30319
- 通过CAS SSO认证: 302 → `cas.cdp.edu.cn/lyuapServer/login?service=https://aic.cdp.edu.cn/login_CDSSO.aspx`
- **CORS配置不当**: 所有响应设置 `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`
- API端点: `/api/` (301重定向), 其他API路径返回空响应(可能需要认证)

CORS验证:
```bash
curl -sk -D- 'https://aic.cdp.edu.cn/' -H 'Origin: https://evil.com' 2>/dev/null | grep -i access-control
```

### Tomcat 8.0.9 版本泄露
受影响子域: jedu.cdp.edu.cn, jy.cdp.edu.cn, jy-hr.cdp.edu.cn, jy-o.cdp.edu.cn, sdmg.sad.cdp.edu.cn
错误页标题: `Apache Tomcat/8.0.9 - Error report`

### 其他子域
- ehall.cdp.edu.cn: UmiJS SPA, 2097B
- webvpn.cdp.edu.cn: 自研WebVPN (非网瑞达), Rails框架
- sicsve.cdp.edu.cn: "四川职业教育技能创新中心", layui框架, /admin 302→首页
- scskills.cdp.edu.cn: "四川省大学生竞赛信息系统", Vue.js SPA
- www.cdp.edu.cn: 主站, 安全头较完整, /.env返回403
- welcome.cdp.edu.cn: 81409B, 响应超时

## CERNET网络注意事项
- src-fast-assess.py 超时(120s限制), 需手动执行
- 正确流程: subfinder → DNS过滤 → 分批串行探活
- 不要用timeout wrapper调用dig, 用subprocess.run的timeout参数

## 已验证无实质漏洞的发现
- CAS SPA fallback: 所有路径返回4499B登录页, 非真正Actuator暴露
- CAS service参数: 页面不反射service参数到JS变量中
- ehall JSONP端点: 全部404
- yikatong: 参见cdp-deep-recon-20260523.md (SM4加密, 需要合法账号)

## 后续投入条件
1. 安全问题/密码找回功能逻辑缺陷验证 (需测试暴力枚举/答案可预测性)
2. aic.cdp.edu.cn CORS + 认证后敏感API组合利用 (需CAS凭证)
3. Tomcat 8.0.9 已知CVE验证 (CVE-2017-12617 PUT上传等)
