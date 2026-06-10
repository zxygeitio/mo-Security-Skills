# 环球时报/环球网 SRC 测试记录 (2026-05-17)

## 测试范围
- 核心: www.huanqiu.com, 3w.huanqiu.com, i1.huanqiu-ltd.com
- 常规: *.huanqiu.com (346子域)
- 边缘: *.huanqiu-ltd.com (34子域), *.globaltimes.cn (23子域)
- 其他: visitbeijing.com.cn, iprcc.org.cn, hicn.cn, gdpc.org.cn, kxtwz.com, zysy.org.cn, zhwhxy.org.cn, lifetimes.cn

## 资产规模
- 441个域名, 420个存活目标
- 技术栈: OpenResty+(主力), ASP.NET MVC 4.0/5.2, Express/Node.js, Vue.js(iview-admin), Nuxt.js

## 发现的漏洞/风险

### CORS配置不当 (中危)
- www.huanqiu.com: `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Methods: GET,POST,OPTIONS`
- i1.huanqiu-ltd.com: `access-control-allow-origin: *`
- visitbeijing.com.cn: meta标签中也有 `Access-Control-Allow-Origin: *`

### API路由信息泄露 (中危)
- www.huanqiu.com/api/comment → 返回483KB JSON, 包含全部40+子域名的完整路由配置
- 包含: 子域名列表、API路径、内部节点ID(node)、频道名称映射
- capital.huanqiu.com/api/site_nav → 99KB站点导航配置
- capital.huanqiu.com/api/black_json → 12KB黑名单配置

### 内部服务地址泄露 (低危)
- appcms-test.globaltimes.cn/api/user/info → `{"code":1001,"msg":"Unknown Exception","url":"http://api:8080/api/user/info"}`
- 泄露Docker/K8s内部服务名和端口

### 管理API端点泄露 (低危)
- admin.live.huanqiu.com JS文件泄露30+管理API
- 包括: /api/admin/live-streams/set-view, /api/admin/like/direct-increment
- 所有API需要onelogin认证(302重定向)

### 服务器版本泄露 (低危)
- api.globaltimes.cn: X-AspNetMvc-Version: 5.2, X-AspNet-Version: 4.0.30319
- hqsb/newspaper.globaltimes.cn: X-AspNetMvc-Version: 4.0
- i1.huanqiu-ltd.com: X-Powered-By: Express, Server: Apache

### 备份管理系统 (信息)
- hicn.cn/backupmgt/ → 302重定向(WAF拦截)
- 路径: login.php, backup.php, restore.php, config.php
- WAF: 403 Forbidden "HTTP Proxy"

## 关键技术发现

### 1. huanqiu.com API架构
- /api/comment → 站点配置(非评论数据)
- /api/list?node=/xxx&page=1&pagesize=10 → 文章列表
- /api/site_nav → 导航配置
- /api/black_json → 黑名单
- 文章ID格式: hash字符串(如4RZoyFULL6v), 非数字

### 2. globaltimes.cn 测试环境
- subscribetest.globaltimes.cn → UmiJs SPA + 微信JS SDK
- appcms-test.globaltimes.cn → iview-admin CMS后台(Vue.js)
- appcms-test API: /api/user/info, /api/user/login, /api/user/logout (返回内部服务地址)

### 3. ASP.NET MVC登录系统模式
- hqsb.globaltimes.cn 和 newspaper.globaltimes.cn 使用相同登录框架
- 登录接口: /Login/CheckLogin (POST, x-www-form-urlencoded)
- 验证码: /Login/GetAuthCode (图片)
- 密码使用MD5: jquery.md5.js
- 验证码绕过: 获取cookie后用错误验证码提交 → "Object reference not set to an instance of an object."(.NET NullReferenceException)
- 无验证码直接提交 → "验证码错误，请重新输入"

### 4. 视频直播管理系统
- admin.live.huanqiu.com → Vue.js + Element UI
- CDN: rs-live.huanqiucdn.cn/huanqiu-frontend-video-live-manage/25571/
- 认证: onelogin (http://admin.live.huanqiu.com/onelogin/login)
- API返回405(Method Not Allowed)表示端点存在但需POST方法

## 未发现高危漏洞的目标
- hqsb.globaltimes.cn - 验证码保护, SQL注入测试未成功
- newspaper.globaltimes.cn - 同上
- i1.huanqiu-ltd.com - 需认证, 自定义404页面返回200状态码(需内容长度验证)
- subscribe.globaltimes.cn - 无明显漏洞
- visitbeijing.com.cn - CORS但无实质危害

## 2026-05-19 重新验证结果

### 漏洞状态更新

| 漏洞 | 域名 | 状态 | 说明 |
|------|------|------|------|
| Blazor SignalR未授权 | ai.globaltimes.cn | ✅ 可复现 | negotiate端点返回connectionId，需Content-Length:0 |
| DES密钥泄露 | appcms-test.globaltimes.cn | ✅ 可复现 | 密钥移至app.a1ee46f1.js(原chunk-90c5.js已失效) |
| 生命时报API未授权 | api.lifetimes.cn | ❌ 已修复 | 所有API返回404页面 |

### Blazor SignalR复现命令
```bash
curl -s "https://ai.globaltimes.cn/_blazor/negotiate" -X POST -H "Content-Type: application/json" -H "Content-Length: 0"
```
返回: {"negotiateVersion":0,"connectionId":"gtScQ38NMK9615grsM4enQ","availableTransports":[...]}

### DES密钥复现命令
```bash
curl -s "https://appcms-test.globaltimes.cn/js/app.a1ee46f1.js" | grep -oP 'ENAPP[^"]*'
```
返回: ENAPP>GLOBALTIMES>CN

注意: chunk-*.js文件名每次构建都会变，需要从首页HTML提取最新路径。app.*.js路径相对稳定。

### 报告路径
- /tmp/vuln_reports/huanqiu/report-2-des-key-v2.txt (带截图位置标注)
- /tmp/vuln_reports/huanqiu/report-3-blazor-v2.txt (带截图位置标注)
