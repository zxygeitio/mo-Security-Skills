# CPIC太保SRC深度侦察 (2026-05-16)

## 测试概述

目标: CPIC太保SRC (太平洋保险)
测试时间: 2026-05-16 下午
测试范围: 集团/产险/寿险/资产 + 统一登录/服务大厅/团体险等20+子系统

## 发现的所有CPIC资产

| 域名 | IP | 说明 |
|------|-----|------|
| www.cpic.com.cn | 198.18.0.120 | WAF保护 |
| property.cpic.com.cn | 198.18.0.121 | 产险, WAF |
| life.cpic.com.cn | 198.18.0.122 | 寿险, WAF |
| asset.cpic.com.cn | 198.18.0.123 | 资产, WAF |
| one.cpic.com.cn | 103.230.111.221 | 统一登录系统, ROT代理 |
| service.cpic.com.cn | 58.246.171.102 | 服务大厅, ROT代理 |
| open.cpic.com.cn | 103.230.111.133 | 开放平台, 502后端离线 |
| api.cpic.com.cn | 103.230.111.128 | API网关, Nginx默认页 |
| m2web.cpic.com.cn | 103.230.110.191 | 团体险系统 |
| onesit.cpic.com.cn | 101.204.252.93 | SIT环境, 无响应 |
| gwkf.cpic.com.cn | ROT路由 | 后端nginx 500错误 |
| sxthd.cpic.com.cn | ROT路由 | 后端Apache, 403 |
| oneft.cpic.com.cn | ROT路由 | 502后端离线 |
| bfylj.cpic.com.cn | ROT路由 | 502后端离线 |
| health.cpic.com.cn | 116.236.67.182 | 健康险, 301重定向 |
| ssp.cpic.com.cn | 112.64.1.226 | 不明, 403 |
| ecpic.com.cn | 112.64.185.50 | 不明, 无响应 |

## ROT Proxy架构 (58.246.171.102)

service.cpic.com.cn作为ROT代理，支持Host头路由:

```
Host: api.cpic.com.cn → 真实后端 (200 OK)
Host: one.cpic.com.cn → 真实后端 (200 OK)
Host: gwkf.cpic.com.cn → 后端nginx 500错误
Host: sxthd.cpic.com.cn → 后端Apache 403
Host: bfylj.cpic.com.cn → 后端离线 502
```

**关键发现**: ROT代理接受任意Host头，可通过枚举Host头探测内部路由表。

## one.cpic.com.cn 统一登录系统

### 技术栈
- 前端: Vue.js SPA + webpack bundle
- 加密: SM4 CBC + SM2公钥加密密钥交换
- 认证: 短信验证码 + 图形验证码
- API前缀: /Proxy/

### API端点
```
/Proxy/member/userInfo          # 用户信息
/Proxy/member/smsLogin          # 短信登录
/Proxy/member/checkMobileExist  # 手机号检查
/Proxy/oauth2/authorize         # OAuth2授权
/Proxy/oauth2/userinfo          # OAuth2用户信息
/Proxy/oauth2/tokeninfo        # Token信息
/Proxy/oauth2/checkToken        # Token验证
/Proxy/captcha/generate         # 图形验证码
/Proxy/captcha/check            # 验证码校验
/Proxy/member/sendLoginSms     # 发送登录短信
```

### OAuth安全测试结果
- redirect_uri bypass: SQL注入过滤器检测，绕过失败
- state参数: 无反射
- JWT伪造: 正确拒绝
- 用户枚举: 正确拒绝
- SQL注入检测: 有防护机制

### URL配置 (从actionTokens-prod.js提取)
```javascript
urlRoot: "https://one.cpic.com.cn/Proxy/"
```

## service.cpic.com.cn 服务大厅

### 技术栈
- 后端: Java (Spring Boot)
- 加密: SM4密钥交换API
- API前缀: /secure/ (认证绕过前缀)

### 高价值API端点
```
/secure/ePolicy/ePolicyInit     # 保单初始化
/secure/common/delSession       # 删除会话 (可登出其他用户!)
/secure/personal/lookOutsideMedical/isDisabled
/secure/policy/utilsAnnuity/isDisabled
```

### APK文件
- URL: service.cpic.com.cn/android/service.apk
- 大小: ~14MB
- 内网IP泄露: 172.18.18.11, 101.68.192.3, 101.68.192.4
- JWT密钥: "cpic20191206" (已无效，每次不同)

## 安全配置总结

| 系统 | WAF | 认证 | 加密 | 评估 |
|------|-----|------|------|------|
| 所有CPIC主站 | 阿里云/玄武云 | - | Nginx | 完善 |
| one.cpic.com.cn | 是 | SM4+短信 | 是 | 完善 |
| service.cpic.com.cn | 是 | SM4 | 是 | 完善 |
| property/life/asset | 是 | 登录后 | 是 | 完善 |

## 测试失败的漏洞类型

1. **.git泄露** → property WAF拦截(405)
2. **OAuth redirect bypass** → SQL注入过滤器检测
3. **SQL注入** → 防护完善
4. **Spring Boot Actuator** → 无暴露
5. **ThinkPHP RCE** → 不适用
6. **Nginx CVE** → 版本隐藏，无法测试
7. **ROT SSRF** → gwkf返回500但无法直接利用
8. **IDOR** → 需要有效认证

## ROT Proxy Host头枚举技术

详见: `rot-proxy-behind-discovery/references/rot-proxy-host-header-enumeration-20260516.md`

## 结论

CPIC太保SRC安全评级非常高，所有系统均有完善防护:
- WAF有效拦截敏感路径
- 认证机制健全(SM4+短信)
- ROT代理安全配置正确
- 未发现可直接利用的高危漏洞

**建议**: 关注0day漏洞、第三方组件漏洞、钓鱼攻击路线。
