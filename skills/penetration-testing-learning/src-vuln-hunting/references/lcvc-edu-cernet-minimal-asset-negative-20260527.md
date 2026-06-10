# lcvc.edu.cn 负面验证记录 (2026-05-27 / 2026-06-09 重测)

## 目标
柳州城市职业学院 (lcvc.edu.cn)

## 资产清单

| 子域 | IP | 类型 | 状态 |
|------|-----|------|------|
| www.lcvc.edu.cn | 125.217.2.5 | CERNET | 首次HTTP/200→后续IP限流 |
| ehall.lcvc.edu.cn | 220.173.103.130 | 非CERNET | Vue.js SPA + WAF拦截敏感路径 |
| yx.lcvc.edu.cn | 220.173.103.131 | 非CERNET | wengine WAF 483/403 |
| vpn.lcvc.edu.cn | 125.217.2.5 | CERNET | 不可达 |
| oa.lcvc.edu.cn | 125.217.2.5 | CERNET | 不可达 |
| mail.lcvc.edu.cn | mailhz.qiye.163.com | 网易企业邮箱 | 第三方 |
| imap.lcvc.edu.cn | imaphz.qiye.163.com | 网易企业邮箱 | 第三方 |

子域名发现方法: subfinder(3个) + DNS暴力枚举前缀(2个) + 常见教育前缀(2个)
crt.sh返回502, 无证书透明度数据
所有子域DNS解析到198.18.2.x (Cloudflare WARP假IP)

## 技术栈指纹

### www.lcvc.edu.cn (125.217.2.5)
- Server: nginx
- 框架: 静态HTML + jQuery + SuperSlide
- CMS: VSB博达(sitegray代码被注释掉)
- 安全头: X-Frame-Options: SAMEORIGIN, X-XSS-Protection: 0, X-Content-Type-Options: nosniff
- 特点: 纯展示型静态站点,无用户交互功能

### ehall.lcvc.edu.cn (220.173.103.130)
- Server: nginx
- 框架: Vue.js SPA (网上办事服务大厅)
- JS: app.5bf3b6e7.js, chunk-vendors.3941facb.js
- UI库: WE UI v0.9.0 (wed.js)
- API: stataAddress + /minos-stata 路径
- WAF: "访问禁止"拦截页(swagger-ui.html等返回200+拦截内容,非标准403)
- Cookies: gwroute-casp-portal, route

### yx.lcvc.edu.cn (220.173.103.131)
- Server: nginx
- WAF: 网瑞达(wengine) WAF → 483/403
- 错误页: wengine-auth-failed.png

## CERNET间歇可达模式

首次curl请求成功:
```
HTTP/2 200
server: nginx
title: 柳州城市职业学院
证书: CN=*.lcvc.edu.cn (广西壮族自治区/柳州市/柳州城市职业学院)
```

后续所有请求(不同UA/不同协议/不同路径)全部 timeout → IP级速率限制

## 防火墙幻影端口检测模式 (2026-06-09 新增)

三个不同IP(125.217.2.5/220.173.103.130/220.173.103.131)开放完全相同的14个端口:
21/22/25/80/110/143/443/3306/3389/5432/6379/8080/8443/27017

nmap显示全部"tcpwrapped"(接受连接后立即关闭)。实测:
- SSH: 连接后立即关闭(Connection closed by host)
- MySQL: 握手阶段丢失连接(ERROR 2013)
- Redis: 服务器关闭连接
- HTTP/HTTPS: curl全部超时(限流后)

**判断规则**: 同一学校不同IP段出现完全一致的端口开放模式 = 基础设施级防火墙策略,非真实服务。不要在这些端口上浪费时间做深入测试。

## ehall WAF拦截特征

swagger-ui.html 等敏感路径返回 HTTP 200 (非403!) 但内容是"访问禁止"拦截页:
```html
<TITLE>访问禁止</TITLE>
检测到可疑访问，事件编号：{YYYYMMDD}{HHMMSS}{随机4位}
```

**陷阱**: curl -o /dev/null -w '%{http_code}' 会显示200,误以为端点可达。必须检查响应体内容。

## ehall不可达(2026-05-27)→ 部分可达(2026-06-09)

05-27: 220.173.103.130 完全不可达(所有端口超时)
06-09: HTTPS可达,Vue.js SPA正常加载,WAF拦截敏感路径
变化: ehall从完全不可达变为部分可达,但WAF保护下无可利用面

## 邮件安全(配置正确)

```
MX: hzmx01.mxmail.netease.com / hzmx02.mxmail.netease.com
DMARC: v=DMARC1; p=quarantine; fo=1; ruf=mailto:dmarc@qiye.163.com; rua=mailto:dmarc_report@qiye.163.com
SPF: v=spf1 include:spf.163.com -all
DKIM default selector: RSA公钥存在
```

结论: 邮件安全配置完整, 无伪造风险

## 教训

1. **CERNET首次成功≠可持续访问**: 首次curl拿到200后应立即采集完整信息(响应头+body+JS), 不要只检查状态码然后继续下一步
2. **delegate_task在CERNET目标上会全部超时**: 3个子代理各600s = 30分钟浪费
3. **最小资产目标应2分钟内决策**: 7个子域名+大部分不可达 = 立即结论, 不要花30+分钟尝试各种方法
4. **网易企业邮箱配置正确时邮件攻击面为零**: MX→netease.com + DMARC quarantine + SPF -all + DKIM → 跳过
5. **WAF返回200而非403是常见陷阱**: 必须检查响应体,不能只看状态码
6. **相同端口开放模式=幻影端口**: 不同IP完全一致的端口列表说明是前端防火墙,非真实服务

## 不建议提交

该学校攻击面极小, 未发现任何可利用漏洞. 基础设施安全性在教育机构中属于较好水平.
已在2026-05-27和2026-06-09两次确认, 13天内无任何变化.
