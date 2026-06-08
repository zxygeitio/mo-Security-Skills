# 教育SRC测试工作流 (Education SRC Testing Workflow)

## 完整流程 (从目标到提交)

```
┌─────────────────────────────────────────────────────────────┐
│                    教育SRC测试工作流                          │
└─────────────────────────────────────────────────────────────┘

Phase 0: 目标预检 (5分钟/目标)
    │
    ├─ 运行 edu-target-preflight.sh
    ├─ 检查可达性、CERNET、WAF、SPA
    └─ 决定: 继续/转向其他攻击面/跳过
    │
    ▼
Phase 1: 侦察 (10-20分钟)
    │
    ├─ 子域名枚举 (subfinder + crt.sh)
    ├─ HTTP探活 (过滤不可达目标)
    ├─ 技术栈识别 (Server/Powered/Title)
    └─ 漏洞类型匹配 (根据技术栈选择攻击向量)
    │
    ▼
Phase 2: 漏洞发现 (20-40分钟)
    │
    ├─ 按优先级矩阵测试:
    │   ├─ P0: SQL注入/RCE/认证绕过
    │   ├─ P1: IDOR/未授权API/文件上传
    │   ├─ P2: 密钥泄露/CORS/邮件安全
    │   └─ P3: 信息泄露(仅在可利用时)
    │
    ├─ 前端JS分析 (API路由+密钥)
    ├─ 敏感路径探测 (actuator/swagger/.git)
    └─ 登录功能测试 (弱口令/验证码绕过)
    │
    ▼
Phase 3: 利用验证 (10-20分钟/漏洞)
    │
    ├─ 触发漏洞并获取实际数据
    ├─ 记录完整HTTP数据包 (curl -sk -D-)
    ├─ 批量验证影响范围
    └─ 编写POC脚本
    │
    ▼
Phase 4: 报告生成 (10-15分钟/漏洞)
    │
    ├─ 使用教育SRC标准模板
    ├─ 包含: curl命令 + 响应 + 数据证据
    ├─ 运行 report-quality-gate.sh 检查
    └─ 修复检查出的问题
    │
    ▼
Phase 5: 提交决策
    │
    ├─ 通过质量门禁 → 提交
    └─ 未通过 → 修复后重新检查
```

## 关键决策点

### 决策1: 目标是否值得测试?
```
目标预检结果
    ├─ HTTP不可达 + CERNET → 转向邮件/DNS
    ├─ HTTP不可达 + 非CERNET → 跳过
    ├─ HTTP可达 + 强WAF → 避免actuator/.git，专注API
    ├─ HTTP可达 + SPA → 避免页面路径，专注API路由
    └─ HTTP可达 + 无WAF + 非SPA → 全面测试
```

### 决策2: 漏洞是否值得提交?
```
发现漏洞
    ├─ P0类型 + 实际利用 → 直接提交
    ├─ P1类型 + 实际数据 → 直接提交
    ├─ P2类型 + 完整利用链 → 提交
    ├─ P2类型 + 无利用证明 → 尝试深入利用或跳过
    ├─ P3类型 + 可利用 → 考虑提交
    ├─ P3类型 + 不可利用 → 跳过
    └─ ❌类型 → 绝对不提交
```

### 决策3: 报告是否可以提交?
```
质量门禁检查
    ├─ 无错误 + ≤2警告 → 提交
    ├─ 有错误 → 修复后重新检查
    ├─ >2警告 → 优化后重新检查
    └─ 包含HTML → 改为纯文本
```

## 实战示例

### 示例1: 亳州学院 go-fastdfs (正确流程)

```
Phase 0: 预检
    目标: oshall.bzuu.edu.cn
    结果: HTTP可达, 无WAF, 非SPA
    决策: 继续测试

Phase 1: 侦察
    技术栈: go-fastdfs
    匹配攻击向量: /fileServer/status (信息泄露)

Phase 2: 漏洞发现
    测试: /fileServer/status → 返回服务器信息
    测试: /fileServer/upload → 无认证上传
    测试: /fileServer/static/uppy.html → 泄露auth_token
    
    漏洞类型判定:
    - 文件上传: ❌ 不收(Content-Type: octet-stream)
    - 信息泄露: P3 → 需要组合利用
    - 组合利用: status泄露内网IP + upload无认证 + auth_token泄露
    
    决策: 以"未授权访问致服务器信息泄露"角度提交

Phase 3: 利用验证
    curl -sk "https://oshall.bzuu.edu.cn/fileServer/status"
    → 返回内网IP、磁盘信息、内存信息、文件统计
    
    curl -sk -X POST "https://oshall.bzuu.edu.cn/fileServer/upload" \
        -F "file=@test.txt" -F "output=json2"
    → 返回上传成功，文件可访问
    
    curl -sk "https://oshall.bzuu.edu.cn/fileServer/static/uppy.html" | \
        grep -oP "auth_token: '[^']*'"
    → 返回auth_token

Phase 4: 报告生成
    标题: go-fastdfs文件存储系统未授权访问致服务器信息泄露
    等级: 中危 (CVSS 6.5)
    复现: 3个curl命令 + 完整响应
    证据: 内网IP、服务器配置、文件统计

Phase 5: 提交
    质量门禁: PASS
    提交: ✓
```

### 示例2: 武汉音乐学院 DMARC (正确流程)

```
Phase 0: 预检
    目标: whcm.edu.cn
    结果: HTTP不可达, CERNET-only
    决策: 转向邮件/DNS攻击面

Phase 1: 邮件安全审计
    dig +short _dmarc.whcm.edu.cn TXT → 空 (DMARC缺失)
    dig +short whcm.edu.cn TXT → SPF ~all (softfail)
    dig +short default._domainkey.whcm.edu.cn TXT → 空 (DKIM缺失)

Phase 2: 漏洞判定
    DMARC缺失: P2类型 → 需要组合利用
    不能单独提交! 必须实际发送伪造邮件

Phase 3: 利用验证
    # 使用自己的SMTP服务器发送伪造邮件
    # 收件人: 自己的邮箱
    # 发件人: jwc@whcm.edu.cn (教务处)
    # 主题: 关于2026年春季学期成绩查询的通知
    
    # 证据:
    # 1. 伪造邮件在收件箱中显示为"来自 jwc@whcm.edu.cn"
    # 2. 没有"可疑邮件"警告
    # 3. SPF检查显示 "softfail" 而非 "fail"

Phase 4: 报告生成
    标题: 邮件系统存在DMARC缺失漏洞可伪造校方邮件进行钓鱼攻击
    等级: 高危 (CVSS 7.5)
    复现: DNS检查命令 + 伪造邮件截图
    证据: 实际发送的伪造邮件证明

Phase 5: 提交
    质量门禁: PASS (有实际利用证明)
    提交: ✓
```

## 常见错误及修正

### 错误1: go-fastdfs以文件上传角度提交
```
错误: 标题"未授权任意文件上传可钓鱼攻击"
原因: Content-Type: octet-stream，文件不解析
修正: 标题"未授权访问致服务器信息泄露"
      主漏洞: /fileServer/status信息泄露
      副漏洞: upload无认证 + auth_token泄露
```

### 错误2: DMARC缺失单独提交
```
错误: 只提交DNS检查结果
原因: 纯配置缺陷，无实际利用证明
修正: 实际发送伪造邮件 + 截图证明
      组合: DMARC缺失 + SPF softfail + DKIM缺失
```

### 错误3: SPA Fallback误报
```
错误: 报告/actuator返回200
原因: SPA应用所有路径返回200
修正: 先验证是否SPA fallback
      body1=$(curl -sk "target/actuator" | head -c 100)
      body2=$(curl -sk "target/nonexistent" | head -c 100)
      [ "$body1" = "$body2" ] && echo "SPA Fallback"
```

### 错误4: 提交纯配置缺陷
```
错误: 报告"缺少安全Header"
原因: 教育SRC不收纯配置缺陷
修正: 不提交，或尝试利用
      如: 缺少CSP → 尝试XSS
```

## 工具清单

| 工具 | 用途 | 用法 |
|------|------|------|
| edu-target-preflight.sh | 目标预检 | `./edu-target-preflight.sh domain.edu.cn` |
| report-quality-gate.sh | 报告质量门禁 | `./report-quality-gate.sh report.txt` |
| subfinder | 子域名枚举 | `subfinder -d domain.edu.cn` |
| curl | HTTP请求 | `curl -sk -D- "URL"` |
| dig | DNS查询 | `dig +short _dmarc.domain.edu.cn TXT` |
| whois | IP归属 | `whois IP` |

## 相关Skill
- `education-src-blueprint` — 教育SRC漏洞挖掘蓝图
- `src-vuln-hunting` — SRC漏洞挖掘全流程
- `web-pentest-fast` — Web渗透快速流程
- `auto-recon-lowhanging` — 自动化初始侦察
- `nginx-spa-fallback-false-positive` — SPA Fallback误报检测
