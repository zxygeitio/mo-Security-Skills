# Apereo CAS pwdDefaultEncryptSalt 密钥泄露模式

## 指纹特征
- URL路径: `/authserver/login` 或 `/cas/login`
- 页面JS中包含: `pwdDefaultEncryptSalt = "xxx"`
- 隐藏字段: `<input type="hidden" id="pwdDefaultEncryptSalt" value="xxx"/>`
- 表单字段: lt, execution, dllt, _eventId, rmShown
- JSESSIONID暴露在URL中: `;jsessionid=xxx`

## 漏洞描述
CAS登录页面的JavaScript直接暴露了客户端密码加密使用的AES密钥(pwdDefaultEncryptSalt)。该密钥用于前端加密密码后再传输到服务端。

## 检测命令
```bash
# 获取加密密钥
curl -sk 'https://authserver.<domain>/authserver/login' | grep -i 'pwdDefaultEncryptSalt'

# 获取完整表单字段
curl -sk 'https://authserver.<domain>/authserver/login' | grep -iE 'lt.*value|execution.*value|dllt.*value|pwdDefaultEncryptSalt'
```

## 响应示例
```javascript
var pwdDefaultEncryptSalt = "Ra3ecgs32OgS34gb";
// 或
var pwdDefaultEncryptSalt = "Facdbu9MibYNr7ab";
```
```html
<input type="hidden" name="lt" value="LT-803503-xxx-5Z97-cas"/>
<input type="hidden" name="dllt" value="userNamePasswordLogin"/>
<input type="hidden" name="execution" value="e1s1"/>
<input type="hidden" name="_eventId" value="submit"/>
<input type="hidden" id="pwdDefaultEncryptSalt" value="Facdbu9MibYNr7ab"/>
```

## 危害
1. 攻击者获取密钥后可解密截获的加密密码传输包
2. 可构造加密后的密码payload进行暴力破解
3. 结合JSESSIONID URL泄露可进行会话固定攻击

## JSESSIONID URL泄露
CAS系统将JSESSIONID嵌入URL路径:
```
/authserver/custom/css/login.css;jsessionid=RMiGHSKvQ5Fe9xx3dPhb_1ba0RDLFbrCMOUg51MpUNDJblMXa1go!-2022159154
```
可通过浏览器历史、Referer头、服务器日志泄露。

## 报告模板
```
标题: <学校>统一身份认证系统密码加密密钥泄露
域名: authserver.<domain>
类型: 信息泄露
等级: 中危
行业: 教育
地址: <精确地址>
URL: https://authserver.<domain>/authserver/login

详情: CAS登录页面JavaScript中直接暴露密码加密密钥pwdDefaultEncryptSalt，
攻击者可获取该密钥构造加密密码进行暴力破解或解密截获的密码传输包。

复现:
curl -sk 'https://authserver.<domain>/authserver/login' | grep pwdDefaultEncryptSalt

响应: var pwdDefaultEncryptSalt = "xxx";

影响: 降低认证安全性，辅助暴力破解攻击

修复建议:
1. 将密码加密逻辑移至服务端
2. 如必须前端加密，使用一次性会话密钥
```

## 已确认目标
| 学校 | 域名 | 密钥示例 |
|------|------|----------|
| 河南农业职业学院 | authserver.hnca.edu.cn | Facdbu9MibYNr7ab / Ra3ecgs32OgS34gb |
