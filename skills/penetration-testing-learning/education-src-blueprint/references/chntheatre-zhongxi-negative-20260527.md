# 中央戏剧学院 (chntheatre.edu.cn / zhongxi.cn) 深挖负证据包
## 2026-05-27

## 目标概况

- **学校**: 中央戏剧学院 (Central Academy of Drama)
- **主域名**: chntheatre.edu.cn
- **关联域名**: zhongxi.cn (学校内部域名)
- **地址**: 北京市东城区
- **行业**: 教育/艺术类高校

## 域名架构

### 主站
| 域名 | IP | 用途 |
|------|-----|------|
| chntheatre.edu.cn | CNAME: saaswaf.com | 主站(WAF防护) |
| www.chntheatre.edu.cn | 113.142.69.133 | 301→主站 |
| en.chntheatre.edu.cn | (同主站) | 英文版 |
| mail.chntheatre.edu.cn | 111.124.200.42 | 网易企业邮 |

### zhongxi.cn 子域名
| 子域名 | IP | 用途 | 状态 |
|--------|-----|------|------|
| www.zhongxi.cn | 36.110.24.9 | 主站 | 301→chntheatre.edu.cn |
| webexp.zhongxi.cn | (APISIX) | 校外访问登录门户 | Vue.js SPA |
| ehall.zhongxi.cn | 36.110.24.9 | 办事大厅 | 302→webexp登录 |
| jwc.zhongxi.cn | 36.110.24.9 | 教务处 | 302→webexp登录 |
| cwc.zhongxi.cn | 36.110.24.9 | 财务系统 | 302→webexp登录 |
| zzb.zhongxi.cn | 36.110.24.9 | 组织部 | 302→webexp登录 |
| idp.zhongxi.cn | 36.110.24.9 | 身份提供商 | 403 ADG WAF |
| lib.zhongxi.cn | 113.142.69.133 | 图书馆 | 静态HTML |
| changping.zhongxi.cn | 36.110.24.9 | 图书馆系统 | 302→webexp登录 |
| maxkb.zhongxi.cn | 36.110.24.9 | AI聊天机器人 | 302→webexp登录 |
| zhaosheng.zhongxi.cn | 116.211.138.205 | 招生网 | 静态HTML |
| vpn.zhongxi.cn | 36.110.24.11 | Astraeus VPN | CAS认证 |
| wrdvpn.zhongxi.cn | 36.110.24.9 | WebVPN | 302→webexp登录 |
| mail.zhongxi.cn | 111.124.200.44 | 网易企业邮 | 标准配置 |
| auth.zhongxi.cn | 172.16.138.7 | CAS认证 | 内网IP(DNS泄露) |
| ids-443.vpn.zhongxi.cn | (VPN内) | CAS认证服务器 | Apereo CAS |
| drms.zhongxi.cn | (无DNS) | 数字资源系统 | 不可达 |

## 技术栈

### 主站 (chntheatre.edu.cn)
- **CMS**: Fractal Technology 自研CMS (PHP)
- **WAF**: saaswaf.com (CNAME指向)
- **前端**: jQuery 1.11.3, 静态HTML生成
- **特征**: 
  - `<!--auther>孙</auther-->` / `<!--auther>王</auther-->` HTML注释
  - `meta author: http://www.fractal-technology.com`
  - PHPSESSID cookie
  - `/Public/static/themes/cad/` 静态资源路径
  - 搜索功能重定向到百度站内搜索

### 校外访问门户 (webexp.zhongxi.cn)
- **框架**: Vue.js SPA
- **网关**: APISIX (openresty)
- **认证**: CAS + WeCom(企业微信)
- **API端点**:
  - `/api/access/user/info` → 需认证(返回"未授权")
  - `/api/access/authentication/list` → 认证方法列表
  - `/api/access/password-auth` → 密码认证配置
  - `/api/authentication/conf` → 安全配置
  - `/api/access/authentication/all` → 所有认证方式
  - `/api/access/authentication/page-custom-detail` → 页面定制

### CAS认证系统 (ids-443.vpn.zhongxi.cn)
- **类型**: Apereo CAS
- **特征**: 
  - `/authserver/login` 登录页
  - pwdEncryptSalt 密码加密盐值泄露
  - JSESSIONID 在URL中泄露
  - 密码找回/验证接口需要登录态

### VPN (vpn.zhongxi.cn)
- **类型**: Astraeus VPN
- **认证**: CAS (跳转到 ids-443.vpn.zhongxi.cn)
- **特征**: `_astraeus_session` cookie

## 测试结果

### 已测试项目
1. **SQL注入** - 未发现
   - `?id=` 参数测试: 无差异响应
   - 搜索功能: 重定向到百度站内搜索
   - ThinkPHP RCE测试: 返回502(非ThinkPHP)

2. **文件上传** - 未发现
   - 主站无上传功能
   - `/Public/` 返回403
   - `/Uploads/` 返回403

3. **认证绕过** - 未发现
   - webexp.zhongxi.cn 有正常认证检查
   - `/api/access/user/info` 返回"未授权"

4. **IDOR越权** - 未发现
   - 招生详情页为公开信息(无敏感数据)
   - `/detail/{id}.html` 为公开文章页

5. **CORS配置** - 正常
   - 主站无CORS头
   - webexp.zhongxi.cn 仅允许自身域名

6. **信息泄露** - 低价值
   - CAS密码加密盐值泄露(低危)
   - auth.zhongxi.cn 内网IP泄露(极低危)

### 低价值发现(不建议提交)

1. **CAS密码加密盐值泄露**
   - 端点: `https://ids-443.vpn.zhongxi.cn/authserver/login`
   - 泄露值: `MaAHMQ5UrPYIysOd` / `tL97Tiez9cP3MNtS`
   - 等级: 低危
   - 不建议提交原因: 纯信息泄露,无法直接利用

2. **auth.zhongxi.cn DNS解析到内网IP**
   - 泄露IP: 172.16.138.7
   - 等级: 极低危
   - 不建议提交原因: 仅DNS信息泄露,无法利用

3. **jQuery 1.11.3 版本泄露**
   - 等级: 极低危
   - 不建议提交原因: 无直接可利用的XSS入口

## 防护总结

- **主站**: 静态CMS + WAF(saaswaf.com), 攻击面极小
- **子域名**: 统一使用APISIX网关 + CAS认证, 防护良好
- **VPN**: Astraeus VPN + CAS认证, 无已知漏洞
- **邮件**: 网易企业邮, 标准配置

## 结论

中央戏剧学院网站防护良好,主站是静态CMS攻击面极小,子域名统一使用APISIX网关和CAS认证。经过深度挖掘未发现可提交的实质漏洞(RCE/SQLi/越权/认证绕过/文件上传)。不建议继续投入时间。

## 后续投入条件

仅在以下情况才重新投入:
- 发现新的未授权敏感数据接口
- 发现认证绕过或SQL注入
- 发现文件上传漏洞
- 发现IDOR越权访问真实用户数据
