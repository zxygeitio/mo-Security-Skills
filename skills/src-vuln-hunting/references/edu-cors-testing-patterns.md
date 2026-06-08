# 教育SRC CORS测试模式

## CORS批量探测模板

```python
import httpx, concurrent.futures

def test_cors_batch(subs, origin="https://evil.com"):
    findings = []
    def check(sub):
        try:
            r = httpx.get(f'https://{sub}/', headers={'Origin': origin}, timeout=10, verify=False)
            acao = r.headers.get('access-control-allow-origin', '')
            acac = r.headers.get('access-control-allow-credentials', '')
            if acao:
                return {'sub': sub, 'acao': acao, 'acac': acac}
        except: pass
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        for r in filter(None, ex.map(check, subs)):
            findings.append(r)
    return findings
```

## CORS漏洞等级判断

| ACAO | ACAC | 等级 | 说明 |
|------|------|------|------|
| evil.com | true | 高危 | 可跨域读取认证数据 |
| null | true | 高危 | iframe sandbox可触发null origin |
| *.evil.com | true | 高危 | 子域劫持利用 |
| * | false | 低危 | 通配符不允许凭证 |
| 同域 | true | 中危 | 同域子站可利用 |

## 实战案例

### certificate.ccnu.edu.cn (华中师范大学, 2026-06-03)
- Spring Boot API, 所有端点返回 {"errcode":"1001","errmsg":"用户未登录"}
- ACAO反射任意Origin + ACAC=true
- 安全头全缺失 (HSTS/XFO/XCTO/XXSS/CSP)
- 验证:
  curl -sk https://certificate.ccnu.edu.cn/api -H "Origin: https://evil.com" -D-
  curl -sk https://certificate.ccnu.edu.cn/api -H "Origin: null" -D-
  curl -sk https://certificate.ccnu.edu.cn/api -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: POST" -D-

### mail.ccnu.edu.cn (华中师范大学, 2026-06-03/06-07)
- ACAO=* (通配符) on POST /mail/loginfun, 无ACAC
- 登录参数: txtuserid, usertype (1=教职工@mails.ccnu.edu.cn, 2=学生@mails.ccnu.edu.cn), pwd
- 验证码完全客户端生成(sessionStorage.setItem('captcha', code))，4位大写字母+数字，60秒过期
- 验证码校验JS: captchaVal.toLowerCase() === yzcodecaha.toLowerCase()
- 等级: 中危 (CORS* + 客户端验证码 = 跨域暴力破解/撞库)
- 验证:
  curl -sS -D- -X POST "https://mail.ccnu.edu.cn/mail/loginfun" \
    -H "Origin: https://attacker.com" \
    -d "txtuserid=test@ccnu.edu.cn&usertype=1&pwd=test"
- 额外路径: /admin 302→/login?ReturnUrl=%2Fadmin, /reg, /pwd 均302→login
- 后端: 自定义代理→腾讯企业邮(exmail.qq.com)

## 教育系统常见CORS问题

1. Spring Boot默认配置: 部分系统未配置CORS, 反射所有Origin
2. 通配符滥用: 部分系统设置ACAO=*但不理解安全影响
3. Nginx配置错误: proxy_pass时未正确处理Origin头
4. 开发环境残留: 测试环境CORS配置被带到生产
