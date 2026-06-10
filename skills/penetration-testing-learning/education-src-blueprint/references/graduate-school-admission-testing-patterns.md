# 研究生招生网信息管理系统测试模式

## 识别特征
- URL模式: `yzcx.{domain}` 或 `yz.{domain}`
- 标题: "研究生招生网信息管理系统" 或 "研究生院"
- 技术栈: ASP.NET Core + Layui前端
- 特征路径: `/Login`, `/Register/Index`, `/Search/ScoreInfo`
- Session Cookie: `.AspNetCore.Antiforgery.*`, `.AspNetCore.Session`
- 验证码: `/code/captcha/captcha?w=105&h=35&t={timestamp}&refresh=1`

## 系统架构
```
/Login                      - 登录页面 (用户名+密码+验证码)
/Register/Index             - 非推免生注册 (准考证号+姓名+身份证号+验证码)
/Register/enrolReg          - 推免生注册
/Register/forgetPwd         - 密码找回 (准考证号+姓名+身份证号+验证码)
/ChangeInfo                 - 信息修改 (需登录)
/Search/ScoreInfo           - 成绩查询 (需登录)
/Search/checkInfo           - 成绩复核 (需登录)
/noteInfo?id={N}            - 通知公告 (可能泄露错误信息)
/code/captcha/captcha       - 验证码图片生成
```

## 漏洞模式

### 1. 错误信息泄露 (.NET)
```bash
# noteInfo端点参数异常时返回.NET错误
curl -sk 'https://yzcx.{domain}/noteInfo?id=1'
# 返回: "Object reference not set to an instance of an object."
# 泄露: Request ID、.NET框架信息
```

### 2. 验证码识别绕过
验证码为4位数字PNG图片，可用vision_analyze工具识别:
```bash
# 获取验证码
curl -sk -b cookies.txt 'https://yzcx.{domain}/code/captcha/captcha?w=105&h=35&t=test&refresh=1' -o captcha.png
# 使用vision_analyze识别数字
```

**注意事项**:
- 验证码与session绑定，需在同一session中使用
- 验证码有时效性，获取后需立即使用
- 验证码过期返回: `alert('验证码过期，请刷新页面后重试！')`

### 3. 注册接口用户信息收集
注册需要准考证号+姓名+身份证号，可尝试:
- 准考证号规律枚举 (年份+院系+序号)
- 弱口令测试 (默认密码模式)

### 4. CSRF Token
```bash
# 从页面提取CSRF token
CSRF=$(grep -oP 'value="CfDJ8[^"]*"' page.html | head -1 | sed 's/value="//;s/"$//')
# 提交时需携带: __RequestVerificationToken=${CSRF}
```

## 实战案例

### gxnu.edu.cn (2026-06-09)
- 系统: yzcx.gxnu.edu.cn
- 技术栈: ASP.NET Core + Layui
- 发现: /noteInfo?id=1 返回.NET错误信息
- 验证码: 4位数字PNG图片
- 注册: 需要准考证号+姓名+身份证号+验证码
- 安全防护: 验证码绑定session、CSRF token

## 与正方教务系统的区别
正方教务系统(ZFSOFT)使用Java技术栈:
- 指纹: `X-Powered-By: Servlet/3.0 JSP/2.2 (ZFSOFT-SERVER)`
- 路径: `/jwglxt/` (教务管理)
- Cookie: `route=xxx`

研究生招生网通常为自研系统，技术栈多样。
