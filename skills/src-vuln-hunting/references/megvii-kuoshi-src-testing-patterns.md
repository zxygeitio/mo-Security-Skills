# 旷视科技(Megvii/Kuoshi) SRC 测试模式 (2026-05-31)

## 目标范围
- 核心: www.faceid.com, api.faceid.com, www.megvii.com, cloud9.megvii.com
- 普通: *.brainpp.cn, *.megviirobotics.com, *.megvii-inc.com
- 一般: *.koalacam.net (不含v3), *.xlsdn.com
- 排除: vpn.megvii-inc.com, p6sai.com, xiaoshouyiservice.megvii-inc.com
- 仅收旷视域名/IP下的系统或旷视产品相关漏洞

## 资产规模
- 总子域名: 353个 (subfinder)
- 存活资产: 158个
- 核心业务技术栈: Vue SPA + Nginx + 阿里云 + K8s

## 已验证漏洞 (9份报告)

### 中危 (3个)
1. account.megvii-inc.com FaceEE认证凭据泄露
   - /api/v2/faceee/getFaceSign 无需认证返回OAuth签名凭据
   - 泄露Authorization, X-FaceEE-ClientId, state含"web_login_without_username"
2. retail-test.xlsdn.com 测试环境开发模式未授权访问
   - /api/retail/product/v1/users/development/mode 返回 {"code":0,"data":true}
3. faceid.com OSS存储桶信息泄露
   - POST /faceopen/login 返回OSS错误含存储桶名和区域

### 低危 (6个)
4. srp.megvii.com Prometheus Metrics泄露 (/metrics 19KB)
5. srp.megvii.com CORS * + Credentials
6. cityiotorder.megvii.com Actuator暴露 (/actuator)
7. account-retail-test.xlsdn.com Debug API泄露 (config.js)
8. faceplusplus console硬编码Token (JS中Token="9fd116cb...")
9. faceid.com API错误码泄露 (/docs返回errcode)

## 关键API端点

### facestyle-console.megvii.com
JS: https://facestyle-cdn.megvii.com/fsconsole/app.64651d01cb0a5103ef17.js
- /api/admin/account/export, /api/admin/commercial/trade/export
- /api/admin/upload?prefix=banner, /api/commercial/receipt/receipt_photo_upload
- /api/makeup/products/import, /api/v1/h5/ad/icon/upload
- /api/official/captcha/get?endpoint=login (无需认证返回PNG)
- 所有端点需认证返回 {"err_msg":"需要登录后操作","err_code":101000012}

### onboard-epif.megvii-inc.com
JS: https://onboard-epif.megvii-inc.com/js/app.e1ad1244.js
- /api/login, /api/user/info, /api/user/photo/*, /api/attachment/upload
- /api/send/verify?userId= (潜在IDOR)
- 所有端点返回 {"code":1,"msg":"用户未登录"}

### cloud9.megvii.com (旷视九霄IoT平台)
JS: https://cloud9.megvii.com/aiot/js/app.5c06f4.js
- /account/create, /account/delete, /account/modify-admin
- /appkey/apply, /appkey/resetSecret
- /device/export, /person/export, /passing/export
- SSO: sso.megvii-inc.com/cas/login

### api-escort.megvii.com
- 需要 cappkey + ctimestamp 头 (15分钟有效期)
- /health 无需认证返回 {"status":"UP"}
- IP: 39.105.65.145

## SPA Fallback 误报过滤
所有路径返回相同大小200 = SPA fallback:
- facestyle-console: 2859B, account.megvii-inc: 2361B
- hetu-developer: 2640B, faceidenterprise: 39348B
- onboard-epif: 1661B, faceid.com/faceopen/*: 710B

## 技术栈
- Web: Nginx, Tengine, Vue.js SPA
- 后端: Spring Boot (Actuator), Go (api-escort)
- 云: 阿里云OSS/K8s, Kubernetes
- OA: 致远OA (megoa.megvii-inc.com)
- JIRA: v8.13.18 (jira.megviirobotics.com)
- 邮件: 阿里邮箱

## 子域名枚举
```bash
for d in faceid.com megvii.com brainpp.cn megvii-inc.com koalacam.net xlsdn.com megviirobotics.com; do
    subfinder -d "$d" -all -silent 2>/dev/null | tee "${d//\./_}_subs.txt"
done
```

## HTTP探活 (Python并行)
```python
import subprocess, concurrent.futures
def probe(sub):
    for proto in ['https', 'http']:
        r = subprocess.run(['curl', '-sk', '--max-time', '6', '-o', '/dev/null',
            '-w', '%{http_code}|%{redirect_url}', f'{proto}://{sub}/'],
            capture_output=True, text=True, timeout=10)
        code = r.stdout.strip().split('|')[0]
        if code not in ('', '000'):
            return f'{code}|{proto}://{sub}'
    return None
# 20线程并发, 353域名约60秒完成
```

## 不建议提交
- JIRA版本信息泄露, OpenID Connect配置暴露
- 默认Tengine/Nginx页面, 阿里邮箱登录页面
- GraphQL端点SPA fallback, faceid.com/faceopen/* SPA路由
- 用户枚举(sendPhoneCode) - 所有号码返回相同错误

## SRC定级
- 低危: 信息泄露、路径泄露、配置信息 (80-200元)
- 中危: 需交互漏洞、普通越权、源码泄露 (200-1000元)
- 高危: 敏感信息泄露、未授权访问 (1000-2000元)
- 严重: RCE、SQL注入、核心DB泄露 (2000-3500元)
