---
name: agent-task-planner
description: >-
  智能任务规划器 — 复杂渗透任务执行前自动分解为3-7步结构化计划，提升成功率。借鉴PentAGI的Intelligent Task Planning。
domain: cybersecurity
subdomain: soc-operations
tags:
- security
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1595
nist_csf:
- ID.RA-01
---
# Agent Task Planner / 智能任务规划

## 触发条件
- SRC/渗透任务开始前（目标确认后、工具调用前）
- 用户要求"深挖""全面""系统化"的复杂任务
- 目标有 ≥3 个子域或 ≥2 个开放服务

## 规划模板

### Web SRC 标准流程（5步）

```
Step 1: RECON — 被动侦察
  - 子域名枚举 (subfinder/amass)
  - 端口扫描 (nmap/masscan)
  - 技术栈指纹 (whatweb/wappalyzer)
  - 搜索引擎情报 (google dorking/shodan)
  → 产出: 目标清单 + 技术栈 + 入口点

Step 2: FINGERPRINT — 精准指纹
  - CMS/框架识别 + 版本
  - WAF 检测 + 类型
  - API 端点发现 (swagger/openapi/robots/sitemap)
  - JS 文件分析 (密钥/端点/逻辑)
  → 产出: 指纹→漏洞映射候选表

Step 3: ATTACK-SURFACE — 攻击面测绘
  - 按指纹结果选择攻击路径
  - 优先级: RCE > SQLi > Auth Bypass > IDOR > XSS
  - 每个路径分配工具和预期结果
  → 产出: 攻击计划 + 工具分配

Step 4: EXPLOIT — 漏洞验证
  - 按优先级逐一验证
  - 每个漏洞: PoC → 复现步骤 → 证据截图
  - Loop Guard 监控: 同工具 ≤5 次
  → 产出: 已确认漏洞列表

Step 5: REPORT — 报告生成
  - 按平台格式整理
  - 单行 curl 复现
  - 截图位置标注
  - 严重级别评定
  → 产出: 可提交报告
```

### 教育 SRC 快速流程（3步）

```
Step 1: QUICK-RECON (60s)
  - src-fast-assess.py 一键快筛
  - 重点: CAS/VPN/OA/邮件/WAF
  → 产出: 优先攻击面

Step 2: LOW-HANGING-FRUIT (10min)
  - CORS 反射型
  - CAS 用户枚举
  - API 未授权访问
  - 安全头缺失
  - 信息泄露 (版本/路径/配置)
  → 产出: 可提交低危漏洞

Step 3: DEEP-HUNT (30min)
  - 认证绕过
  - 越权访问
  - SQL 注入
  - 命令注入
  → 产出: 高价值漏洞
```

### 内网渗透流程（5步）

```
Step 1: NETWORK-MAP — 内网拓扑
  - ARP 扫描 + 网段发现
  - 服务枚举 + 指纹
  → 产出: 内网资产清单

Step 2: CREDENTIAL-HUNT — 凭据收集
  - 共享目录/配置文件
  - 弱口令爆破
  - Hash 抓取 + 破解
  → 产出: 可用凭据

Step 3: LATERAL-MOVE — 横向移动
  - Pass-the-Hash/Key
  - 服务利用 (SMB/WinRM/SSH)
  → 产出: 新立足点

Step 4: PRIVILEGE-ESC — 提权
  - 本地提权检查
  - 服务提权
  - 配置错误利用
  → 产出: 高权限访问

Step 5: PERSIST + EXFIL — 持久化 + 数据
  - 后门植入（授权范围内）
  - 关键数据定位 + 提取
  → 产出: 完整攻击链证据
```

## 规划执行规则

1. **执行前输出计划**：开始工具调用前，先输出 3-7 步计划
2. **每步有明确产出**：每步结束时检查产出是否达标
3. **动态调整**：发现新信息时可调整后续步骤
4. **跳过条件**：某步无价值时可跳过，但需说明原因
5. **超时控制**：单步超过预期时间 2x 时评估是否继续
6. **Loop Guard 集成**：每步自动启用 agent-execution-monitor

## 与 the AI agent 集成

在 `global-control` 的 SRC 任务流程中，Step 3（指纹→漏洞映射）前插入规划步骤：

```
# 开始 SRC 任务
1. 确认目标和授权
2. 运行 agent-exec-monitor.py reset
3. 输出任务计划（选择上述模板之一）
4. 按计划执行，每步记录到 monitor
5. 完成后运行 monitor.py summary
```

## Pitfalls

1. **过度规划**：简单目标（单个 URL + 已知 CMS）不需要 5 步流程，直接攻击。
2. **计划僵化**：发现关键漏洞后应立即验证，不要按部就班等 Step 4。
3. **产出模糊**：每步产出必须是具体文件/数据/漏洞，不是"已完成侦察"这种空话。
