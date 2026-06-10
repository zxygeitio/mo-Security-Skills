# EZVIZ/萤石 SRC 2026-05-14 实战记录

## 测试概况
- 测试时间: 2026-05-14
- 子域名枚举: 400+个子域名，25+个存活
- WAF类型: Tengine + 阿里云WAF + openRASP
- 后端技术: Java/Tomcat, PHP/ThinkPHP, Vue.js SPA, Next.js SPA

## 发现的漏洞

### 1. openauth.ys7.com OAuth开放重定向（中危）
- OAuth authorize端点接受任意redirect_uri
- 攻击链: 钓鱼→授权码→AccessToken→设备/视频
- SRC反馈: 需要用户交互，不直接判定高危

### 2. store.ys7.com ThinkPHP RCE风险（中危）
- ThinkPHP框架确认（captcha端点存在）
- WAF拦截差异: GET返回000:0，POST返回418:6357
- SRC反馈: WAF拦截=不可利用

### 3. mfs.ys7.com CORS配置缺陷（中危）
- 反射任意Origin + Credentials开启
- OSS bucket: mall-files (oss-cn-hangzhou-internal)
- SRC反馈: bucket只含公开图片，无实质危害

### 4. 多子域.git目录泄露（中危）
- 16个子域存在.git目录
- WAF返回418:6357（文件存在但被拦截）
- SRC反馈: WAF拦截=不可利用

## SRC拒绝模式总结

### 被否定的漏洞类型
1. CORS配置缺陷 - 无实质危害
2. .git目录泄露 - 被WAF拦截
3. OAuth开放重定向 - 需要用户交互
4. 敏感文件存在但被拦截 - openRASP拦截

### SRC看重的漏洞类型
1. 获取任意用户摄像头视频（严重）
2. RCE - 命令注入、远程命令执行（严重）
3. 严重信息泄露 - SQL注入≥10万条（严重）
4. 核心系统越权 - 任意账号登录（严重）
5. 内网SSRF - 能直接访问内网（高危）

## 关键教训

### 1. IoT API是最高价值目标
- open.ys7.com的IoT API需要appKey/appSecret
- 如果找到有效凭证，可访问用户摄像头视频
- 这是萤石SRC最看重的漏洞类型

### 2. WAF响应差异分析
- 418:6357 = WAF标准拦截页
- 000:0 = 连接被WAF主动杀死
- 403:40 = openRASP拦截
- 302:0 = 需要认证

### 3. GET vs POST WAF差异
- 某些函数（shell_exec, assert, eval）GET返回000，POST返回418
- 这表明WAF对GET和POST的处理方式不同

### 4. 编码绕过技术
- %0a (换行) 绕过: 返回302:0
- %0d%0a (回车换行) 绕过: 返回302:0
- %09 (制表符) 绕过: 返回302:0

## 未完成测试
1. 移动端APP逆向 - 提取硬编码appKey/appSecret
2. open.ys7.com appKey枚举 - 需要有效凭证
3. ThinkPHP RCE WAF绕过 - 需要更 sophisticated 技术
4. 内网SSRF - 需要找到可访问内网的漏洞

## 新发现的攻击面 (2026-05-14 深度测试)

### 开发者控制台 (open.ys7.com/console)
- /console → 302 → /console/home.html (需要登录)
- /console/api/apps → 302 → /auth?r=...&returnUrl=... (需要认证)
- /console/api/developer/info → 302 (需要认证)
- /console/api/app/list → 302 (需要认证)
- 认证入口: /auth → 登录页面
- 注册接口: /api/developer/register, /api/app/register
- 登录接口: /api/developer/login, /console/api/login

### 移动端API (mobile.ys7.com)
- /api/device/list → 401:46 (需要认证)
- /api/device/add → 401:46 (需要认证)
- /api/user/login → 405:86 (方法不允许)
- /api/token/verify → 000:0 (连接被杀)
- 认证方式: Bearer token
- 错误响应: {"resultCode":"-3","resultDes":"Unauthorized"}
- 测试了多种认证头，全部返回401

### Tomcat版本泄露 (auth.ys7.com)
- Server: Apache Tomcat/8.0.36
- 该版本存在已知漏洞: CVE-2017-12617, CVE-2019-0232, CVE-2020-1938
- AJP端口8009: filtered (不可访问)
- PUT方法上传: 被openRASP拦截

### store.ys7.com ThinkPHP深度分析
- 完整函数GET vs POST差异矩阵（见references/thinkphp-rce-waf-bypass.md）
- X-Forwarded-Host: store.ys7.com → 000:0 (特殊响应)
- 时间延迟异常: sleep 1 → 21.4秒
- HTTP请求走私成功但openRASP仍拦截
- 所有WAF绕过技术全部失败
