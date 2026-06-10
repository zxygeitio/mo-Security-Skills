# ThinkPHP RCE WAF绕过 - 萤石SRC实战记录 (2026-05-14)

## 目标: store.ys7.com

## 框架确认
- /index.php?s=captcha → 302:0 (ThinkPHP验证码端点)
- /admin.php/admin_user/index/login → 200:8683 (管理后台)
- Server: Tengine
- X-Protected-By: openRASP

## WAF响应差异（关键发现）

### 响应码含义
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

### 其他WAF绕过尝试（全部失败）
- HTTP/2协议: 418:6357
- 分块编码: 418:6357
- URL编码: 418:6357
- 双重URL编码: 418:6357
- 不同User-Agent: 418:6357
- X-Forwarded-For: 418:6357
- Referer: 418:6357
- Cookie: 418:6357

## 时间延迟验证
- exec(sleep 5) → 0.3秒（命令未执行，WAF拦截）
- passthru(sleep 1) → 21.4秒（异常延迟，可能执行）
- create_function(phpinfo()) → 5.002秒（异常延迟）
- 结论: 部分请求有异常延迟，但无法验证命令是否真正执行

## SRC反馈
- SRC认为WAF拦截=不可利用
- 需要找到绕过WAF的方法才能报告
- 或者找到不被WAF拦截的攻击面

## 教训
1. WAF响应差异（000 vs 418）只是信息，不是漏洞证据
2. 时间延迟验证可以确认命令是否真正执行
3. ThinkPHP RCE需要WAF绕过才能利用
4. openRASP对PHP文件的拦截很有效
5. HTTP请求走私成功但openRASP仍拦截
6. X-Forwarded-Host: store.ys7.com触发特殊响应
