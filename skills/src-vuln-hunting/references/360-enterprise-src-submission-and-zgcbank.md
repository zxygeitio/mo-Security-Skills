# 360众测 / 企业SRC 提交流程与中关村银行实战补充

## 适用场景
- 360众测、企业SRC、漏洞盒子等有严格表单字段长度限制的平台
- 需要把命令行复现步骤和截图提交流程压缩到平台字段中
- 注册/找回密码/供应商入驻等“匿名业务校验接口”型漏洞

## 关键结论

### 1. 360众测 `Recall Step` 字段有硬性长度限制
- `Recall Step`（复现步骤）最大 **8000 字符**
- 超出会直接报错：
  `Recall Step只能包含至多8,000个字符。`

### 2. 压缩复现步骤的正确方法
复现步骤只保留：
- 关键前置条件
- 单行 curl 命令
- 关键返回字段
- 最终漏洞成立结论

不要保留：
- 大段背景分析
- 重复响应体
- 过多修复建议
- 过多截图解释

推荐结构：
1. 访问公开页面，提取 token / 接口路径
2. 调用核心接口A，贴关键返回字段
3. 调用核心接口B，贴关键返回字段
4. 调用核心接口C，贴关键返回字段
5. 结论（未登录/未授权即可调用）

### 3. 截图提交流程
命令行类漏洞截图建议固定为四张：
- 【截图位置1】前置页面/源码中提取 token、接口路径、参数来源
- 【截图位置2】漏洞接口A：完整命令 + 关键 JSON/HTTP 返回
- 【截图位置3】漏洞接口B：完整命令 + 关键 JSON/HTTP 返回
- 【截图位置4】漏洞接口C 或最终对照结果

关键要求：
- 每张图里必须同时出现命令和结果
- 所有 curl 命令必须是单行
- 若平台字段紧张，详细解释交给附件截图，正文只写【截图位置N】

## 中关村银行实战：匿名注册链校验接口

### 公开注册页
- `https://pms.zgcbank.com/pms/ananymous/jyzt/zc/gyszc`

### 可直接从页面源码提取的接口
- `/pms/ananymous/jyzt/zc/checkDlh`
- `/pms/ananymous/jyzt/zc/checkZtmc`
- `/pms/ananymous/jyzt/zc/checkZtdmByZc`
- `/pms/ananymous/jyzt/zc/checkYzm`
- `/pms/ananymous/jyzt/zc/checkSjYzm`
- `/pms/ananymous/jyzt/zc/getEmailSession`
- `/pms/ananymous/jyzt/zc/sendEmailYzm`
- `/pms/ananymous/jyzt/zc/getJc_ztbzt`
- `/pms/ananymous/jyzt/zc/saveJc_ztbzt`

### 关键判定：可作为“权限控制缺失 / 未授权校验接口”提交
如果满足：
1. 页面公开可访问
2. 页面源码中可直接提取 `_csrf`、接口路径等前置参数
3. 仅凭公开页拿到的 SESSION + `_csrf` 就能调用真实业务校验接口
4. 接口直接返回 JSON 状态结果（如 `flag:true`、`state:1`、`操作成功！`）

则可按：
- 权限控制缺失
- 未授权校验接口
方向提交，不必硬归类为信息泄露。

### 中关村银行实战返回样例
- `{"text":"操作成功！","state":1,"data":{"flag":true},"_ResubmitToken":null}`
- `{"text":"操作成功！","state":1,"data":null,"_ResubmitToken":null}`

### 标题建议
- `xxx系统供应商注册链存在未授权校验接口漏洞`
- `xxx系统注册链存在权限控制缺失漏洞`

## CSRF 校验对照验证方法
不要因为页面里出现 `_csrf` 或 `X-CSRF-TOKEN` 就默认系统防护有效。应做三组对照：

1. 无 Cookie、无 CSRF
- 预期：403 / `Invalid CSRF Token.`

2. 有 Cookie + 表单 `_csrf`，但无 `X-CSRF-TOKEN` 头
- 若仍返回 200 且业务成功，说明 CSRF 防护实现存在缺陷

3. 有 Cookie + 有 `_csrf` + 有头
- 作为正常成功对照

### 关键教训
- 如果“缺少 `X-CSRF-TOKEN` 请求头仍成功”，可以独立作为
  - CSRF校验绕过
  - 防护实现缺陷
 方向考虑提交
- 这种对照式证据比单纯说“接口未授权”更容易解释系统安全边界失效
