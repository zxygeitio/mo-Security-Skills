# 联奕科技(Lianyi) CAS 指纹与攻击模式

## 指纹特征
- 路径: /lyuapServer/login, /ly_web_casconsole/
- JS: RSA.js, BigInt.js, Barrett.js (RSA密码加密)
- 占位符: "职工号/学号/别名"
- 厂商: "LIANYI TECHNOLOGY CO.,LTD." (2004-2017)
- 内部域名: cas.leaf.com
- LT token格式: LT-xxxxx-random-cas01.example.org

## 高发漏洞
1. 管理后台公网暴露(/ly_web_casconsole/) — 无服务端验证码
2. Open Redirect(service参数无白名单)
3. 源码泄露(内网IP/内部域名/RSA公钥)
4. SMS登录用户枚举(/lyuapServer/MsmInfo)
5. 学生密码找回页面暴露(/safe/findPassByOther.jsp)

## 关联组件
- Liferay Portal (JSONWS API, /api/jsonws/)
- OA/HR/CRM系统 (/lyoa/, /lyhr/, /lycrm/)
- CoCall即时通讯 (端口65083, V6.2.x)

## 与wisedu CAS对比
| 项 | 联奕 | 金智 |
|---|---|---|
| 路径 | /lyuapServer/ | /authserver/ |
| 后台 | /ly_web_casconsole/ | /ly_console/ |
| 加密 | RSA(KeyPair) | AES/SM2 |
| 验证码 | captcha.jsp(图片) | 滑块/算术 |
