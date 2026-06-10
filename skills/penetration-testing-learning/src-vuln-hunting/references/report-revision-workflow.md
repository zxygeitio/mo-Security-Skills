# SRC报告被退回的修复工作流 (2026-05-18/19 实战)

## 场景
审核员退回报告，反馈"缺少完整测试细节和验证证明"。
参考：https://www.butian.net/Article/content/id/687

## 批量报告被驳回的修复流程 (2026-05-19 华住+环球时报6报告实战)

当多份报告同时被驳回时，按以下流程处理：

### Step 0: 检查漏洞是否仍然存在
```bash
# 用之前的POC命令直接验证
curl -sk -X POST "https://target/api/endpoint" -H "Auth: xxx" -d '{}'
# 如果返回数据 → 漏洞仍在，继续修复报告
# 如果返回401/403 → 漏洞已修复，放弃该报告
```

### Step 1: 按模板重写报告(带截图位置标注)
在报告中明确标注【截图位置N】，告诉用户哪里需要截图：
```
步骤1: 获取泄露的密钥
curl -s "https://target/app.js" | grep -oP 'secret[^,}]+'
【截图位置1】截图终端执行curl命令和输出结果，圈出泄露的密钥

步骤3: 调用API获取数据
curl -X POST "https://target/api/data" -H "Auth: xxx"
【截图位置2】截图curl命令和返回的JSON数据，圈出total数量
```

### Step 2: 给用户提供可直接复制的单行命令
**关键**: 所有curl命令必须是单行，不能有换行符！
- 用户终端(zsh/bash)复制多行命令会报错
- 每个命令独立一行，可直接复制粘贴执行

### Step 3: 确认可复现后再提交
- 用户执行命令截图 → 确认漏洞存在 → 才提交报告
- 不要让用户"试试看"，要确认能复现

## 审核员要求的完整清单
1. 漏洞URL（完整，含参数）
2. 漏洞所在功能点（无功能点提供漏洞接口来源等）
3. 漏洞验证过程，完整数据包以及POC
4. 漏洞验证证明，危害证明
5. 对应的细节截图（CLI环境用HTTP数据包文本替代）

## 修复流程（3步）

### Step 1: 重新验证漏洞，获取完整数据包
```bash
# 关键：-D- 输出完整HTTP响应头
curl -sk -D- 'https://target/api/endpoint' -H 'Header: value'
# 记录：请求方法/路径/头 + 响应状态码/头/body
```

### Step 2: 按模板重写报告
每个报告必须包含：
- 标题：xxx站xxx处存在xxx漏洞
- 域名/漏洞类型/等级/行业/地址(精确到区)
- 漏洞URL
- 漏洞详情（2-3句话）
- 复现步骤（每步= curl命令 + 完整响应）
- 影响（具体数据，非理论）
- 修复建议（可操作）
- CVSS向量字符串

### Step 3: 对照排除项自查
企业SRC不予奖励的漏洞类型（提交前必查）：
- 非敏感信息CORS → 如果暴露认证token则可报
- 无意义内存泄漏/日志/内网IP → 除非可利用
- 示例文件/前端源码泄露 → 除非有密钥
- 仅缺安全header的配置缺陷 → 不收
- 无意义未授权接口 → 除非返回敏感数据
- 仅文字描述无复现 → 必退

**自动化门禁**: 教育SRC报告可用 `education-src-blueprint/scripts/report-quality-gate.sh report.txt` 自动检查。

## 实战案例

### 环球时报 - api.lifetimes.cn 未授权API
**修复前**：描述"API无认证可访问文章数据"
**修复后**：完整curl命令 + 响应头(200/ACAO:*) + 响应body(total:7602) + 分页遍历POC

### 华住 - cjia.com AppSecret泄露
**修复前**：描述"JS泄露AppSecret"
**修复后**：
1. JS文件URL + grep命令提取AppSecret
2. base64编码构造Authorization头
3. POST请求完整数据包 + 返回10条用户数据(脱敏)
4. 验证其他AppSecret同样可用的POC

### 华住 - CORS反射型
**修复前**：signin.hworld.com CORS
**修复后**：signin被WAF拦截 → 替换为portalapi.huazhu.com(实测验证) → 完整响应头 + POC恶意页面代码

## 截图位置标注模板 (2026-05-19 实战)

报告被驳回后重新提交时，在每个关键步骤后添加【截图位置N】标注：

```
步骤1: 获取泄露的密钥
curl -s "https://target/app.js" | grep -oP 'secret[^,}]+'
响应结果: secret_key_abc123

【截图位置1】截图终端执行curl命令和输出结果，圈出泄露的密钥

步骤2: 构造Authorization头
echo -n 'tenant-H5:secret_key_abc123' | base64
结果: dGVuYW50LUg1OnNlY3JldF9rZXlfYWJjMTIz

【截图位置2】截图base64编码命令和输出

步骤3: 调用数据接口
curl -s -X POST "https://target/api/data" -H "Authorization: Basic dGVuYW50LUg1OnNlY3JldF9rZXlfYWJjMTIz" -H "Content-Type: application/json" -d '{"page":1,"pageSize":10}'

响应数据:
{"total": 76543, "list": [...]}

【截图位置3】截图curl命令和返回的JSON数据，圈出关键字段
```

报告末尾必须附上"复现命令汇总"：
```
===
复现命令汇总:

命令1: 获取密钥
curl -s "https://target/app.js" | grep -oP 'secret[^,}]+'

命令2: 调用API
curl -s -X POST "https://target/api/data" -H "Authorization: Basic xxx" -H "Content-Type: application/json" -d '{"page":1}'
```

**关键原则:**
1. 每个curl命令必须是单行(不能有反斜杠换行)
2. 截图位置标注要说明"圈出"什么内容
3. 先帮用户验证漏洞是否仍存在，再让他截图
4. 如果漏洞已修复(返回401/403/404)，告知用户不要提交
