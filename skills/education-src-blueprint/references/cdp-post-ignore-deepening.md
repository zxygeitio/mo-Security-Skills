# 成都职业技术学院 cdp.edu.cn 被忽略/无实质证据后的深挖收敛记录

## 适用场景
教育 SRC 目标已经挖过一轮，存在若干低危线索（ehall 伪 Header 低敏配置、CAS 错误页、就业门户验证码、yikatong 前端加密/验证码、主站 VSB/DWR 路径、邮箱系统），用户要求继续深挖但只接受可提交实质漏洞。

## 本类目标的收敛原则
- 不要把连接不可达、WAF/403/501、SPA fallback、失败响应、公开登录页、公开配置、低敏 systemSetting、验证码图片、硬编码前端加密 key 包装成漏洞报告。
- 能提交的最低门槛：真实未授权敏感数据、IDOR、认证绕过、任意账号接管、可执行上传、SQLi/RCE、可造成业务影响的写操作。
- 若多轮验证仍无实质证据，应明确输出“不建议提交”，并保存证据路径，而不是生成低质量报告。

## 低影响验证清单
1. 资产可达性：解析与 HTTP/HTTPS 探活，短超时，保存 alive/resolved。
2. VSB/DWR：`/_dwr/interface/*.js`、`/_dwr/engine.js`、`/_web/_search/api/search/new.rst`、`/system/resource/getToken.jsp`、`/.git/HEAD`、`/WEB-INF/web.xml`。必须和随机不存在路径对照，防 SPA/门户 fallback。
3. ehall/JinZhi：对比无 Header 与伪 `Loginuserorgid/Loginuserid`，重点看 `/api/authc/user/info`、`service`、`message`、`task/todo`、`docrepo/download`、`jsonp/appIntroduction.json`。只有读到人员、流程、待办、申请单、非公开附件正文或写操作才升级。
4. CAS/authserver：`/authserver/login`、找回密码、`validatePasswordAjax`、`serviceValidate`、`/cas/status`、`/api-docs`。只有用户枚举、验证码绕过、密码重置绕过、ticket/code/token 泄露才提交。
5. jy/jy-hr：邮箱验证码、邮箱校验、`student_key`、密码找回、`get_encode_token`、招聘系统 API。不要轰炸真实邮箱；历史“验证码已发送”只算线索，需证明真实收信/频率缺陷/账号接管才提交。
6. yikatong/uni-app：`getEncrypt`、`getToken`、`captcha/get`、`captcha/check`、`sendSms`、`user/info`、`tradeList`、`cardList`。解密失败消息、验证码图片、硬编码 SM4 key、静态页面 200 均不够；必须拿到真实用户/交易/余额或业务操作成功。
7. go-fastdfs/upload：`/fileServer/status`、`/fileServer/upload`、`/fileServer/static/uppy.html`、`/api/cms/upload`。确认不是同长度 SPA fallback；go-fastdfs 若文件不解析，优先看 status/auth_token/内网信息泄露，不夸大上传危害。
8. mail：腾讯企业邮箱/Coremail 等第三方标准系统通常不是学校自研 API；robots、标准登录页、WAF 501/404 不提交。

## 证据沉淀格式
保存到 `/tmp/vuln_reports/<target>/deep-recon-YYYYMMDD-final-followup.txt`，至少包含：
- 复测时间
- 覆盖资产/路径
- 每类线索的验证结果
- 不建议提交原因
- 证据文件路径
- 后续重新投入条件

## 重新投入条件
- 拿到合法测试账号后可证明 IDOR/越权/业务附件正文下载/流程待办读取/写操作；
- jy 邮箱/重置链证明实际收信、可批量触发或账号接管；
- yikatong 证明验证码绕过、短信真实触发并造成业务影响，或解密出真实业务数据；
- CAS/aic/webvpn 找到未登录真实业务 API；
- VSB/DWR 返回真实后端方法、非公开数据或可写操作。
