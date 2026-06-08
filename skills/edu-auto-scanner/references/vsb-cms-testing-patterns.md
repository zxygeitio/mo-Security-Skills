# VSB博达网站群 CMS 渗透测试模式

## 指纹识别

### HTTP层
- Cookie: `COLLCK=<数字>` (反爬机制)
- 路径: `/_sitegray/_sitegray.js`、`/_sitegray/_sitegray_d.css`
- CSS: `/index.vsb.css`、`/css/body.css`、`/css/index.css`
- JS: `/system/resource/js/vsbscreen.min.js`、`/system/resource/js/counter.js`
- JS: `/system/resource/js/dynclicks.js`、`/system/resource/js/base64.js`

### 页面结构
- 搜索: `/search.jsp?searchword=`
- 登录: `/system/login.jsp` (返回"系统提示"页面)
- 新闻: `/news/`、`/info/`、`/tzgg/`、`/xwzx/`
- 静态页: `.htm`后缀

## COLLCK反爬机制

### 原理
VSB CMS设置COLLCK cookie进行反爬，首次请求返回302并设置COLLCK cookie，后续请求必须携带该cookie才能正常访问。

### 绕过方法
```bash
# 方法1: 浏览器访问(cookie自动设置)
# 使用browser_navigate工具

# 方法2: curl带cookie重试
curl -sL -b "COLLCK=1234567890" "http://target/page.htm"

# 方法3: 部分静态资源不需要cookie
curl -sL "http://target/system/resource/js/counter.js"
curl -sL "http://target/js/zonghe.js"
```

### 注意
- 302循环是正常的反爬行为，不是服务器错误
- 搜索功能可能返回"系统提示"页面(5秒后重定向)
- 部分路径(如/system/login.jsp)即使带cookie也返回重定向

## 常见漏洞

### 1. 搜索功能XSS
- 路径: `/search.jsp?searchword=<script>alert(1)</script>`
- 部分版本存在反射型XSS

### 2. 信息泄露
- `/system/resource/js/counter.js` - 站点统计信息
- `/_sitegray/_sitegray.js` - 站点配置
- 源码中的`<meta name="keywords">`泄露站点名称

### 3. 管理后台
- 路径: `/system/login.jsp`
- 通常需要内网访问或特定条件

## 实战案例
- 新疆交通职业技术大学 (xjjtedu.com): VSB + COLLCK反爬
