# lcvc.edu.cn 负面验证记录 (2026-05-27)

## 目标
柳州城市职业学院 (lcvc.edu.cn)

## 资产清单

| 子域 | IP | 类型 | 状态 |
|------|-----|------|------|
| www.lcvc.edu.cn | 125.217.2.5 | CERNET | 首次HTTP/200→后续IP限流 |
| ehall.lcvc.edu.cn | 220.173.103.130 | 非CERNET | 完全不可达(所有端口超时) |
| yx.lcvc.edu.cn | 220.173.103.131 | 非CERNET | wengine WAF 483/403 |
| vpn.lcvc.edu.cn | 125.217.2.5 | CERNET | 不可达 |
| oa.lcvc.edu.cn | 125.217.2.5 | CERNET | 不可达 |
| mail.lcvc.edu.cn | mailhz.qiye.163.com | 网易企业邮箱 | 第三方 |
| imap.lcvc.edu.cn | imaphz.qiye.163.com | 网易企业邮箱 | 第三方 |

子域名发现方法: subfinder(3个) + DNS暴力枚举前缀(2个) + 常见教育前缀(2个)
crt.sh返回502, 无证书透明度数据

## CERNET间歇可达模式

首次curl请求成功:
```
HTTP/2 200
server: nginx
title: 柳州城市职业学院
证书: CN=*.lcvc.edu.cn (广西壮族自治区/柳州市/柳州城市职业学院)
```

HTML特征:
- sitegray/sitegray.js (被注释, VSB CMS迹象但不确定)
- jquery.min.js + jquery.SuperSlide.js
- 静态HTML/CSS站点

后续所有请求(不同UA/不同协议/不同路径)全部 timeout → IP级速率限制

## ehall不可达

220.173.103.130 非CERNET公网IP, 但:
- curl HTTP/HTTPS: 000 timeout
- whatweb: Net::ReadTimeout
- nmap: 超时
- 端口80/443/8080/8443: 全部000

可能原因: 严格的入站防火墙策略, 仅允许校内/CERNET访问

## yx.wengine WAF

220.173.103.131 返回:
```
HTTP/2 483 (非标准)
Server: none
Content-Type: text/html
HTML: <title>访问出错 - 403</title> + wengine-auth-failed.png + 错误代码403
```

nmap扫描: 所有端口filtered(21/22/80/443/3306/6379/8080/8443)

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

## 不建议提交

该学校攻击面极小, 未发现任何可利用漏洞. 基础设施安全性在教育机构中属于较好水平.
