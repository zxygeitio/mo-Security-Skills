# 博达 Visual SiteBuilder (VSB) CMS 漏洞测试模式

## 目的
博达软件 Visual SiteBuilder 是国内高校使用最广泛的站群CMS之一。本文档记录VSB CMS的攻击面、漏洞模式和测试方法。

## 指纹识别

### 服务器头
```bash
# VAppServer (博达应用服务器)
curl -sI "http://<target>/system/resource/code/news/click/dynclicks.jsp" | grep Server
# 返回: Server: VAppServer/6.0.0

# 主页Server头可能被掩码
curl -sI "http://<target>/" | grep Server
# 返回: Server: *********
```

### 前端特征
```bash
# _sitegray 目录 (博达CMS特征)
curl -sI "http://<target>/_sitegray/_sitegray.js"  # 200 = 博达确认

# 系统JS文件
curl -sI "http://<target>/system/resource/js/ajax.js"  # 200 = 博达确认
curl -sI "http://<target>/system/resource/js/vsbscreen.min.js"  # 响应式框架

# CSS特征
curl -s "http://<target>/" | grep -oP 'href="[^"]*index\.vsb\.css"'
```

### 路径特征
| 路径 | 说明 | 状态码 |
|------|------|--------|
| `/_sitegray/_sitegray.js` | 灰度框架JS | 200 |
| `/system/resource/js/ajax.js` | AJAX库 | 200 |
| `/system/resource/js/counter.js` | 访问统计 | 200 |
| `/system/resource/js/formfunc.js` | 表单功能 | 200 |
| `/system/resource/js/vsbscreen.min.js` | 响应式框架 | 200 |
| `/system/resource/code/news/click/dynclicks.jsp` | 动态点击统计 | 200 |
| `/__local/` | 本地资源目录 | 403 |
| `/ss.jsp?wbtreeid=1001` | 站内搜索 | 200 |
| `/info/{id}/{id}.htm` | 内容页 | 200/404 |

### 版本识别
```bash
# VSB 9 (当前主流)
# 特征: /__local/ 资源路径, wbtreeid 参数, .htm 内容页

# VSB 8 (旧版)
# 特征: /system/resource/ 路径, .jsp 内容页

# VAppServer 版本
# 从 dynclicks.jsp 响应头获取
```

## 攻击面枚举

### 1. 搜索功能 (ss.jsp)
```bash
# 搜索入口
curl -s "http://<target>/ss.jsp?wbtreeid=1001&key=test"

# 搜索参数枚举
# wbtreeid: 树节点ID (1001=默认)
# searchScope: 搜索范围 (0=全站)
# currentnum: 页码
# key: 搜索关键词
```

**WAF防护**: VSB 9 内置WAF，检测SQL注入和XSS攻击，返回"输入参数含有不允许的串，可能引起注入或跨站脚本风险，禁止本页面执行！"

**绕过测试**:
- 双写: `kekeyy` → `key`
- 编码: URL编码、Unicode编码
- 注释符: `/**/` 替代空格
- 大小写混合

### 2. 动态点击统计 (dynclicks.jsp)
```bash
# 正常请求 (返回0字节或数字)
curl -s "http://<target>/system/resource/code/news/click/dynclicks.jsp?wbdocid=1,2,3"

# 批量查询文章点击量
curl -s "http://<target>/system/resource/code/news/click/dynclicks.jsp?wbdocid=1,2,3,4,5,6,7,8,9,10"

# SQL注入测试
curl -s "http://<target>/system/resource/code/news/click/dynclicks.jsp?wbdocid=1'+OR+'1'='1"

# XSS测试 (VSB WAF会拦截并返回错误页面)
curl -s "http://<target>/system/resource/code/news/click/dynclicks.jsp?wbdocid=<script>alert(1)</script>"
```

### 3. 内容页面枚举
```bash
# VSB内容页URL格式: /info/{分类ID}/{文章ID}.htm
# 分类ID通常在1001-1030范围
# 文章ID从1开始递增

# 批量枚举
for cat in 1001 1002 1003 1004 1005 1006 1007 1008; do
  for id in 1 2 3 4 5; do
    code=$(curl -sI "http://<target>/info/${cat}/${id}.htm" --connect-timeout 3 -o /dev/null -w '%{http_code}' 2>/dev/null)
    [ "$code" == "200" ] && echo "FOUND: /info/${cat}/${id}.htm"
  done
done
```

### 4. 站点配置泄露
```bash
# 站点灰色配置
curl -s "http://<target>/_sitegray/_sitegray.js"

# 站点配置文件
curl -s "http://<target>/_sitegray/_sitegray_d.css"

# 站点根配置
curl -s "http://<target>/index.vsb.css"
```

### 5. 资源目录遍历
```bash
# __local 目录 (返回403但可枚举子目录)
curl -sI "http://<target>/__local/0/6E/C9/"  # 403 = 目录存在

# 资源文件直接访问
curl -s "http://<target>/__local/0/6E/C9/BDA0BF4AC5B1469C2B354784869_58769A5D_6A654.jpg" -o /dev/null -w '%{http_code}'
```

### 6. 编辑器/上传接口
```bash
# VSB内置编辑器
curl -sI "http://<target>/editor/editor.jsp"
curl -sI "http://<target>/editor/FCKeditor/"

# 上传接口
curl -sI "http://<target>/upload/"
curl -sI "http://<target>/uploadFile/"
```

### 7. DWR接口 (部分VSB版本)
```bash
# DWR引擎
curl -sI "http://<target>/dwr/"
curl -sI "http://<target>/dwr/index.html"

# DWR测试页面
curl -sI "http://<target>/dwr/test/"
```

## 内网地址泄露

VSB CMS首页常硬编码内网系统地址，泄露内网拓扑：
```bash
# 提取内网IP
curl -s "http://<target>/" | grep -oP 'http://172\.16\.[^"]*'
curl -s "http://<target>/" | grep -oP 'http://10\.[^"]*'
curl -s "http://<target>/" | grep -oP 'http://192\.168\.[^"]*'

# 提取外部暴露的内部系统
curl -s "http://<target>/" | grep -oP 'href="http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[^"]*"'
```

## 关联域名发现

VSB站点通常有 .com 和 .cn 两个域名，指向同一服务器：
```bash
# 同IP不同域名
dig +short www.<domain>.com
dig +short www.<domain>.cn

# 子域名枚举
curl -s "https://api.hackertarget.com/hostsearch/?q=<domain>"
```

## 安全配置检查

### 安全头
```bash
curl -sI "http://<target>/" | grep -iE 'strict-transport|x-frame|x-xss|x-content-type|content-security|referrer'
```

### CORS
```bash
curl -sI "http://<target>/" -H "Origin: https://evil.com" | grep -i access-control
```

### HTTP方法
```bash
for method in OPTIONS TRACE DELETE PUT; do
  code=$(curl -s -X "$method" "http://<target>/" -o /dev/null -w '%{http_code}')
  echo "$method: $code"
done
```

## 真实IP发现 (DNS代理绕过)

当DNS解析到198.18.x.x保留段时，说明走了代理/WAF：
```bash
# 1. 用hackertarget查历史解析
curl -s "https://api.hackertarget.com/hostsearch/?q=<domain>"

# 2. 用不同DNS服务器
dig @114.114.114.114 +short <domain>
dig @223.5.5.5 +short <domain>
dig @8.8.8.8 +short <domain>

# 3. 查MX/TXT记录获取真实IP
dig +short <domain> MX
dig +short <domain> TXT

# 4. 查子域名真实IP
# 子域名可能未被代理保护

# 5. 查证书透明度日志
curl -s "https://crt.sh/?q=<domain>&output=json" | grep -oP '"ip":"[^"]*"' | sort -u
```

## 已测试目标

| 目标 | VSB版本 | 发现 | 备注 |
|------|---------|------|------|
| xjjtedu.com/cn | VSB 9 + VAppServer/6.0.0 | 内网地址泄露(172.16.x.x + 124.88.x.x)、Server版本泄露 | WAF防护SQLi/XSS，主站Server头掩码 |
| xjjtxy.cn | lyuapServer + IIS/6.6666666666 | CAS Open Redirect、Session ID URL泄露、RSA公钥泄露 | 统一认证平台 |

## 注意事项

1. VSB 9 内置WAF，SQL注入和XSS攻击会被拦截，返回特定错误页面
2. 主页Server头被掩码(`*********`)，需从子路径(如dynclicks.jsp)获取真实版本
3. VSB站点通常有.com和.cn两个域名，需同时测试
4. 内网地址泄露是VSB CMS的常见问题，首页常硬编码内网系统链接
5. /__local/ 目录返回403但子目录和文件可能可直接访问
6. VSB搜索功能(ss.jsp)接受wbtreeid和key参数，WAF对特殊字符有检测
7. 真实IP发现是关键：198.18.x.x说明DNS被代理拦截，需用hackertarget等查历史IP
