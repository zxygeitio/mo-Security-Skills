# 批量教育目标扫描结果 (2026-05-20 扩展扫描)

## 扫描范围
- 目标数量: 30+所学校
- 测试方法: DNS枚举 + 端口扫描 + CMS指纹 + 漏洞利用
- 扫描时长: ~2小时

## 可达目标汇总

| 学校 | 域名 | IP | CMS | HTTP | 漏洞 |
|------|------|-----|-----|------|------|
| 湖北大学 | hubu.edu.cn | 202.114.144.124 | 博达CMS | 200 | 无 |
| 六盘水幼儿师范 | lpsyz.cn | 61.189.243.28 | 博达CMS | 200 | 无 |
| 南宁商贸学校 | nnsmxx.com | 211.149.226.66 | BoCaiCMS | 200 | 管理后台暴露(低危) |
| 南京师范大学泰州学院 | nnutc.edu.cn | 58.192.111.139 | NNUTC CLOUD | 405 | WAF拦截 |
| 无锡学院 | wxic.edu.cn | 61.177.124.50 | SUDY CMS | 200 | SVN/Git被WAF拦截 |
| 湖南交通职业技术学院 | hnjt.edu.cn | 59.51.42.155 | 自研PHP | 200→000 | 后台无验证码(中危) |
| 湖北水利水电职业技术学院 | hbsy.cn | 61.183.174.52 | 博达CMS | 200 | 无 |
| 广东岭南现代技师学院 | gdhxxy.cn | 219.234.31.204 | SaaS建站 | 302 | 无价值 |

## 不可达目标 (DNS无记录或CERNET-only)

| 学校 | 尝试域名 | 结果 |
|------|---------|------|
| 六盘水师范学院 | lpssy.edu.cn/lpssy.cn | DNS无记录/不可达 |
| 广西电力职业技术学院 | gxdyxy.edu.cn/gxdy.cn | DNS无记录/域名出售 |
| 合肥一六八中学 | hf168.cn/hf168.net | 不可达 |
| 福清一中 | fqyz.cn/fqyz.net | 不可达/域名过期 |
| 黄河科技学院 | hhstu.edu.cn/hhkj.cn | DNS无记录 |
| 四川乐山一中 | lsyz.cn/lsyz.net | 不可达 |
| 河南工业大学 | haut.edu.cn | DNS无记录 |
| 广州卫生职业技术学院 | gzwsxy.edu.cn/gzws.edu.cn | DNS无记录/不可达 |
| 武汉体育学院 | wipe.edu.cn/wipe.cn | DNS无记录/400 |
| 洛阳师范学院 | lynu.edu.cn/lynu.cn | DNS无记录/不可达 |
| 山东铝业职业学院 | sdlyzyxy.edu.cn | DNS无记录 |

## 域名已出售/过期

| 域名 | 状态 | 识别方式 |
|------|------|---------|
| hnsw.cn | 出售中 | 标题"此域名正在出售中" |
| jxsf.cn | 出售中 | 标题"此域名出售或转让" |
| hbty.cn | 出售中 | 标题"此域名正在出售中" |
| gxdy.cn | 已出售 | 非学校网站 |
| fqyz.net | 已过期 | 标题"域名已过期" |

## 新发现CMS指纹

### BoCaiCMS (博采CMS)
- 识别: X-Powered-By: BoCaiCMS, ThinkPHP
- 管理后台: /admin.php?m=Public&a=login
- 表单字段: username, password, code(验证码)
- 目录: /d/file/ (403)
- 搜索: /index.php?g=Search (POST)
- 留言板: /index.php?g=Addons&m=GuestBook&a=add
- 实战: nnsmxx.com

### 博达CMS (Visual SiteBuilder 9)
- 识别: `<!--Announced by Visual SiteBuilder 9-->`, /_sitegray/
- 资源: /system/resource/js/counter.js, /_sitegray/_sitegray.js
- 搜索: /_web/_search/api/search/new.rst (POST)
- DWR: /_dwr/test/ (部分部署)
- 实战: hubu.edu.cn, lpsyz.cn, hbsy.cn, jwc.hubu.edu.cn

### SUDY CMS
- 识别: /_js/sudy-jquery-autoload.js, sudyNavi
- 上传: /_upload/ (403)
- 样式: /_css/_system/ (403)
- 实战: wxic.edu.cn

### 自研PHP CMS
- 识别: /admin/index/login.html, /public/admin/css/layout.css
- 登录表单: t0=用户名, t1=密码(自定义参数名)
- 无验证码
- 实战: hnjt.edu.cn

## 新发现WAF类型

### NNUTC CLOUD
- 学校: 南京师范大学泰州学院
- 特征: Server: NNUTC CLOUD
- 行为: 所有子域名返回Error页面
- 绕过: 无法绕过

### 宝塔网站防火墙免费版
- 学校: 南宁商贸学校
- 特征: `<title>宝塔网站防火墙免费版</title>`
- 行为: XSS/SQLi拦截, 事件处理器可通过
- 绕过: HTTP头注入, 非WAF保护路径

### rump/c
- 学校: 六盘水幼儿师范, 湖北水利水电职业技术学院
- 特征: Server: rump/c
- 行为: 博达CMS部署, 搜索API返回404
- 绕过: 无需绕过, API不可达

## hubu.edu.cn 子域名枚举

| 子域名 | IP | HTTP | 用途 |
|--------|-----|------|------|
| www.hubu.edu.cn | 202.114.144.124 | 200 | 主站(博达CMS) |
| ehall.hubu.edu.cn | 122.204.223.183 | 302 | 办事大厅 |
| sso.hubu.edu.cn | 202.114.144.88 | 200 | SSO(SPA架构) |
| webvpn.hubu.edu.cn | 122.204.223.31 | 301 | WebVPN |
| news.hubu.edu.cn | 202.114.144.124 | 200 | 新闻 |
| mail.hubu.edu.cn | 14.17.27.155 | 200 | 邮件(QQ Exmail) |
| jwc.hubu.edu.cn | 202.114.144.123 | 200 | 教务处(博达CMS) |
| yjs.hubu.edu.cn | 202.114.144.155 | 200 | 研究生院(IIS7) |
| zzb.hubu.edu.cn | 202.114.144.123 | 200 | 组织部(博达CMS) |
| sme.hubu.edu.cn | 202.114.144.123 | 200 | 商学院 |

### yjs.hubu.edu.cn IIS7发现
- /iisstart.htm → 200 (IIS默认页面)
- /aspnet_client/ → 403 (ASP.NET客户端脚本)
- /trace.axd → 跟踪错误(远程查看已禁用)

### hubu.edu.cn DMARC
- DMARC: p=reject (已配置, 无漏洞)
- SPF: -all (hardfail)

## 结论

1. 30+所学校中仅8个有效可达(1个域名已出售, 1个SaaS建站)
2. 大部分.edu.cn域名DNS无记录或CERNET-only
3. 未发现高价值P0/P1漏洞
4. nnsmxx.com管理后台暴露是最有希望的攻击面, 但被宝塔WAF保护
5. hnjt.edu.cn后台无验证码, 可暴力破解(需更长时间)
6. wxic.edu.cn SVN/Git泄露, 但被WAF拦截
7. 约30%的.edu.cn域名外网可达
