# lycvc.linyi.cn 新发现API端点与CORS漏洞 (2026-05-28)

## 背景
lycvc.linyi.cn (临沂城市职业学院) 之前已提交 `/api/cms/upload` 未授权文件上传漏洞。
本次测试发现新的API端点和系统性CORS漏洞，属于不同根因，可独立提交。

## 技术栈确认
- Server: LyWebServer (AWS托管)
- siteId: 1930900465347256321
- channelId (学院新闻): 1939938219638980610
- jQuery: 1.12.4 (CVE-2020-11022, CVE-2019-11358)
- IP: 120.220.31.123
- SSL: *.linyi.cn (临沂市政府通配符证书)

## 新发现API端点

### 1. /api/channel/tree/{siteId}
- 无需认证
- 返回完整站点栏目结构(所有栏目ID/名称/父子关系)
- 包含: 新闻动态、信息公开、教学机构、图书馆、招生就业等所有栏目
- 响应格式: `{"code":200,"msg":"操作成功","data":[{"id":"...","name":"...","parentId":0,"children":[...]}]}`

### 2. /api/article/search
- 无需认证
- 参数: siteId, channelId, keyword, page, size
- 返回文章列表，total/rows结构
- 测试时搜索结果为空(可能需要有效channelId+keyword组合)

### 3. CORS系统性漏洞
- 所有 `/api/*` 端点统一配置: 反射任意Origin + Credentials:true
- 测试确认的端点: captchaImage, channel/tree, article/search, cms/upload
- 这是LyWebServer CMS的默认/全局配置，非单端点问题

## 已提交漏洞 (历史)
- `/api/cms/upload` 未授权文件上传 (根因A)

## 新发现漏洞 (可提交)
1. CORS任意Origin反射+凭证窃取 [高危] - 根因B
2. jQuery 1.12.4 XSS + 文件上传组合 [中危] - 根因C
3. 钓鱼攻击(文件上传利用) [高危] - 与根因A同根因，不单独提交

## 报告位置
/tmp/vuln_reports/lycvc/

## 停止条件
- 文章搜索API返回空结果，无敏感数据
- 栏目树API返回的是公开网站结构，信息价值有限
- 主站攻击面较小(静态CMS + 有限API)
- 后续只有发现SQLi/RCE/认证绕过/真实IDOR时才继续
