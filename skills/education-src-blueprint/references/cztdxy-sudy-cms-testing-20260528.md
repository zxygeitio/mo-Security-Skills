# 常州铁道职业技术学院 cztdxy.cn 测试记录

## 目标概况
- 域名: www.cztdxy.cn (153.101.55.148)
- CMS: SUDY WebPlus (苏迪科技)
- WAF: 自定义493状态码
- 子域名: 仅www和主域名(crt.sh/subfinder/DNS暴力均无更多)

## 关键发现

### 1. SUDY CMS识别
- `/_js/_portletPlugs/sudyNavi/jquery.sudyNav.js` → 200
- `/_js/jquery.sudy.wp.visitcount.js` → 200
- `/_js/sudy-jquery-autoload.js` → 200
- CSS注释: `/*Technical Support SudyTech*/`
- `sudy-wp-siteId="3"`

### 2. 搜索API
- `/_web/_search/restful/api/search.rst?keyword=*&pageSize=1&pageNo=1&siteId=3&_p=YXM9MyZ0PTE0JmQ9NjQmcD0xJm09U04m`
- 返回1758篇文章总数
- _p参数base64解码: `as=3&t=14&d=64&p=1&m=SN`

### 3. 403页面IP泄露
所有.jsp路径返回403, 泄露:
- `Client IP: 118.113.85.160` (代理IP)
- `connectionId: host-100-126-132-61-*` (内部架构)

### 4. WAF规则泄露
XSS触发493页面泄露:
- `ruleId: 020010029`
- `您的IP: 118.113.85.160`

### 5. 管理后台
- `/admin/login.psp` → 410 Gone, 含ipAddress隐藏字段
- `/admin/main.psp` → 410 Gone

## 不可提交发现
- 搜索API返回公开文章内容 — 非敏感数据
- 403泄露的是代理IP非真实用户IP — 低价值
- CORS未发现
- SQL注入未发现(全文搜索引擎)
