# 深信服SSL VPN测试模式 + 网易邮箱枚举 + 企业微信API泄露

## 深信服SSL VPN指纹与漏洞

### 版本指纹
```bash
curl -sk 'https://vpn.TARGET/por/login_auth.csp'   # → <VPNVERSION>M7.x.xRx</VPNVERSION>, <GMVERSION>, <RSA_ENCRYPT_KEY>, <RSA_ENCRYPT_EXP>
curl -sk 'https://vpn.TARGET/por/ec_pkg.csp'        # → 客户端版本
curl -sk 'https://vpn.TARGET/portal/' | grep sangfor # → class="sangfor-body"/sangfor-main"
```

### 已知CVE
| CVE/通告 | 描述 | 影响版本 | CVSS | 修复 |
|----------|------|---------|------|------|
| SF-PSIRT-20220032 | 远程命令执行 | M7.5-M7.6.9R2 | 9.8 | SP_SSL_IMPROVE_COM(20211022) |
| CVE-2016-2183 | SWEET32 TLS信息泄露 | 多版本 | 5.3 | 禁用3DES |
| Pre-Auth密码重置 | RC4加密弱密钥 | M7.6.6R1以下(M7.6.8R2已删除) | 8.1 | 升级 |

### TLS版本检测
```bash
echo | openssl s_client -connect vpn.TARGET:443 -tls1   # TLS 1.0
echo | openssl s_client -connect vpn.TARGET:443 -tls1_1 # TLS 1.1
# 如果返回 Protocol: TLSv1/TLSv1.1 = 已废弃协议仍启用
```

### 暴力防护
- ErrorCode 20041: "maybe attacked" — IP被标记为暴力攻击
- 触发后需要验证码(rand_code.csp返回图片)
- /por/rand_code.csp — 验证码图片
- /por/randtick.csp — 随机tick

### 其他端点
- /por/login_psw.csp — 登录POST (XML响应含ErrorCode/Message)
- /por/login_auth.csp — 认证初始化(版本/RSA密钥/CSRF)
- /por/ec_pkg.csp — 客户端安装包信息

### Pre-Auth密码重置(仅低版本)
- 端点: /por/changepwd.csp
- RC4密钥: M7.6.1=20100720, M7.6.6R1=20181118
- 数据格式: `,username=test,ip=127.0.0.1,grpid=1,pripsw=old,newpsw=new,`
- M7.6.8R2已删除相关函数

---

## 网易企业163邮箱用户枚举

### 识别
- mail.xxx.edu.cn → 登录页包含 `mailh.qiye.163.com`
- 非本地Exchange/OWA — 所有Exchange路径(/owa/, /ews/, /ecp/)返回404

### 枚举命令
```bash
curl -sk -D- 'https://mailh.qiye.163.com/login/domainEntLogin' \
  -d 'account_name=USERNAME&domain=TARGET.edu.cn&password=test123456&language=0&passtype=1&secure=' \
  2>&1 | grep 'location.*msg='
```

### 响应差异
| 用户状态 | msg参数 | 含义 |
|---------|---------|------|
| 有效用户(如admin) | VERIFYCODE.REQ | 要求验证码(账号存在) |
| 无效用户 | ERR.LOGIN.PASSERR | 账号或密码错误 |
| 有效用户(多次错误后) | 同VERIFYCODE.REQ | 已触发验证码保护 |

### 注意
- 不是所有有效用户名都触发VERIFYCODE.REQ — 可能仅admin等特殊账户
- 需要测试更多用户名确认差异模式
- 无速率限制观察(小批量测试)

---

## 企业微信(WeCom)API错误泄露

### 触发
目标集成企业微信但corpsecret未配置或配置错误时:
```bash
curl -sk 'https://TARGET/api/wecom/login' -X GET
```

### 泄露内容
```json
{
  "ret": 500,
  "error": "获取TOKEN失败: corpsecret missing, hint: [HINT_ID], from ip: INTERNAL_IP, more info at https://open.work.weixin.qq.com/devtool/query?e=41004",
  "msg": null
}
```

### 可提取信息
- 内网IP (`from ip: x.x.x.x`)
- 企业微信应用hint ID
- 错误码(e=41004 = corpsecret缺失)

### 利用价值
- 内网IP暴露 → 辅助内网渗透/缩小探测范围
- hint ID → 可能用于社工或API攻击

---

## 17gz.org国际学生服务平台

### 识别
- 静态资源: `arc.17gz.org`, `a2.17gz.org`, `itf.17gz.org`
- 机构ID: 图片路径中 `/images/custom/leftLogo_NNNNNNNN.png`
- 登录资源: `/login/login.js`, `/login/login.css`
- 图片服务: `itf.17gz.org/is/service/image/rotate.do?url=...`

### 暴露内容
- 机构标识符(如11027701)
- Aliyun OSS签名URL含临时access key ID/scope
- QR码路径: `/2dcode/NNNNNNNN_m2.png`

### 已确认使用学校
- admission.sus.edu.cn (上海体育大学国际学生服务平台)
