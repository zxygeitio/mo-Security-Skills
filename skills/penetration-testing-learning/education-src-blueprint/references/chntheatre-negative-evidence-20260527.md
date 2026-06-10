# 中央戏剧学院 chntheatre.edu.cn 负证据包 (2026-05-27)

## 目标概况

- 主站: chntheatre.edu.cn (PHP, Fractal Technology CMS)
- CNAME: chntheatre-edu-cn.cname.saaswaf.com (SaaS WAF)
- 关联域名: zhongxi.cn
- 子域名: www, en, zhaosheng, lib, webexp, ehall, cwc, maxkb, changping, auth, drms, mail

## 测试结果

### 主站 (chntheatre.edu.cn)

| 测试项 | 结果 | 说明 |
|--------|------|------|
| SQL注入 | 未发现 | `?id=`参数无差异响应, 搜索重定向到百度 |
| 文件上传 | 未发现 | 无上传功能, /Public/ 403 |
| XSS | 未发现 | 搜索重定向到百度site:搜索 |
| 目录遍历 | 未发现 | /Public/, /Application/ 均403 |
| CORS | 无 | 主站无CORS头 |
| .env/.git | 未发现 | /.env返回首页(非真实.env), /.git/HEAD 404 |
| ThinkPHP RCE | 未发现 | 502错误(非ThinkPHP) |
| Actuator | 未发现 | 404 |

### 子域名测试

| 子域名 | 状态 | 说明 |
|--------|------|------|
| en.chntheatre.edu.cn | 可达 | 英文版, 同一CMS |
| zhaosheng.zhongxi.cn | 可达 | 静态招生网, 详情页公开信息 |
| lib.zhongxi.cn | 可达 | 静态图书馆页, 含搜索功能 |
| webexp.zhongxi.cn | 可达 | Vue.js SPA登录门户, API有正常鉴权 |
| ehall.zhongxi.cn | 302 | 重定向到webexp登录 |
| cwc.zhongxi.cn | 302 | 重定向到webexp登录 |
| maxkb.zhongxi.cn | 302 | 重定向到webexp登录 |
| changping.zhongxi.cn | 302 | 重定向到webexp登录 |
| auth.zhongxi.cn | DNS泄露 | 解析到内网IP 172.16.138.7, 不可访问 |
| drms.zhongxi.cn | 不可达 | 无响应 |
| mail.zhongxi.cn | 可达 | 网易企业邮 |

### webexp.zhongxi.cn API测试

| 端点 | 状态 | 返回 |
|------|------|------|
| /api/access/user/info | 200 | `{"code":100009,"message":"未授权"}` — 正常鉴权 |
| /api/access/authentication/list | 200 | CAS + WeCom认证方式 |
| /api/access/authentication/all | 200 | 含支付宝/微信/密码登录 |
| /api/access/password-auth | 200 | 密码认证配置 |
| /api/authentication/conf | 200 | IP/账号锁定策略, 会话超时 |
| /api/access/authentication/page-custom-detail?id=0 | 200 | 页面自定义配置(公开) |
| /api/access/authentication/login | 404 | 登录接口不存在(可能不同路径) |

## 低价值发现(不建议提交)

1. **auth.zhongxi.cn DNS泄露内网IP 172.16.138.7**
   - 极低危, 仅DNS信息泄露, 无法利用
   - 教育SRC不收此类配置缺陷

2. **jQuery 1.11.3 版本泄露**
   - 极低危, 无直接可利用的XSS入口
   - 主站搜索功能重定向到百度, 无反射型XSS

3. **webexp.zhongxi.cn 安全配置泄露**
   - IP锁定/账号锁定/会话超时策略通过公开API可查
   - 属于公开设计, 不建议单独提交

## 结论

目标防护较好, 主站为静态CMS攻击面极小, 子域名统一使用APISIX网关+CAS认证, 无实质漏洞(RCE/SQLi/越权/认证绕过/文件上传)。不建议继续投入。

## 停止条件触发

- [x] 主站无登录功能, 无API接口
- [x] 子域名统一认证, 无绕过可能
- [x] 静态CMS, 无文件上传
- [x] WAF防护(POST请求可能返回403)
- [x] 无SQL注入入口
