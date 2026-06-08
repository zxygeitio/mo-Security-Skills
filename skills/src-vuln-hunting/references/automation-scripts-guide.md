# SRC自动化工具链指南 (2026-06-02)

## 问题背景

SRC效率瓶颈: 串行curl + 慢网络(CERNET/教育网) = 192子域探活300秒超时，40分钟完成一轮扫描。
解决方案: 5个Python脚本部署在 `~/.agent/scripts/`，实现批量探测→指纹→漏洞→JS分析→状态持久化。

## 脚本清单

| 脚本 | 功能 | 核心优势 |
|------|------|---------|
| edu-batch-probe.py | 批量子域探测 | DNS预过滤+20并发+指纹识别 |
| auto-vuln-scan.py | 指纹→漏洞自动映射 | 10+产品指纹库，自动测试已知漏洞路径 |
| js-secrets-scanner.py | JS安全分析 | 25+检测规则，支持URL直接扫描 |
| src-workspace.py | 扫描状态持久化 | 断点续扫、漏洞记录、状态查询 |
| edu-full-scan.py | 全自动主控 | 串联所有阶段，支持--resume |

## 详细用法

### edu-batch-probe.py

```bash
# 基本用法
python3 ~/.agent/scripts/edu-batch-probe.py subs.txt

# 完整参数
python3 ~/.agent/scripts/edu-batch-probe.py subs.txt \
  --dns              # DNS预过滤(2秒超时)
  -f                 # 指纹识别(Server/X-Powered-By/Cookie/产品)
  --batch 20         # 并发数
  --timeout 4        # 每请求超时
  -o alive.txt       # 输出文件
  --filter-code 200,301,302,403  # 只显示这些状态码
  --min-size 50      # 最小响应体
  --json             # JSON输出
```

输出格式: `CODE SIZE PROTO://DOMAIN [REDIRECT] [TECH]`
示例: `200 7433B https://webvpn.cuit.edu.cn [WebVPN]`

指纹提取: Server头、X-Powered-By、JSESSIONID/PHPSESSID/CAS-Route Cookie、SeeyonOA/CAS/WebVPN产品特征。

### auto-vuln-scan.py

```bash
# 单目标扫描
python3 ~/.agent/scripts/auto-vuln-scan.py https://target.edu.cn

# 批量扫描+用户枚举
python3 ~/.agent/scripts/auto-vuln-scan.py alive.txt --enum -o vulns.json --json

# 测试所有路径(包括低危)
python3 ~/.agent/scripts/auto-vuln-scan.py https://target.edu.cn --all
```

内置指纹库(FINGERPRINT_DB):
- seeyon_oa: 致远OA REST API、thirdpartyController、downloadServlet等
- cas_authserver: CAS登录API、应用列表、部门统计、注册配置、微信AppID等
- spring_boot: Actuator端点(health/env/heapdump/mappings/configprops)
- druid_monitor: Druid监控页面、数据源、SQL监控
- swagger: Swagger UI、v2/v3/api-docs
- weaver_ecology: 泛微OA API、微信配置
- wisedu_cas: 金智教育CAS密钥泄露、验证码检查
- visual_sitebuilder: VSB配置文件
- shiro: rememberMe Cookie
- sangfor_webvpn: EasyConnect WebVPN登录
- tomcat: Manager页面
- nginx: 状态页

### js-secrets-scanner.py

```bash
# 本地文件
python3 ~/.agent/scripts/js-secrets-scanner.py bundle.js

# URL直接扫描
python3 ~/.agent/scripts/js-secrets-scanner.py https://target/assets/index.js --url

# 只显示中危及以上
python3 ~/.agent/scripts/js-secrets-scanner.py bundle.js --severity medium

# JSON输出
python3 ~/.agent/scripts/js-secrets-scanner.py bundle.js --json -o results.json
```

检测规则(25+):
- api_endpoints: API端点路径
- internal_urls: 内部/测试环境URL
- internal_ips: RFC1918内网IP
- aws_access_key/secret_key: AWS凭据
- generic_secrets: 硬编码API密钥
- hardcoded_passwords: 硬编码密码
- jwt_tokens: JWT Token
- private_keys: 嵌入私钥
- sm4_keys: SM4加密密钥
- database_urls: 数据库连接串
- local_paths: 开发者本地路径泄露
- vue_config/react_env/next_public: 前端环境变量
- cloud_storage: OSS/S3/COS URL
- sentry_dsn/firebase_config: 第三方服务配置

### src-workspace.py

```bash
python3 ~/.agent/scripts/src-workspace.py init target.edu.cn
python3 ~/.agent/scripts/src-workspace.py status target.edu.cn
python3 ~/.agent/scripts/src-workspace.py resume target.edu.cn    # 续扫建议
python3 ~/.agent/scripts/src-workspace.py update target.edu.cn --phase vuln_scan
python3 ~/.agent/scripts/src-workspace.py add-vuln target.edu.cn --json '{"url":"...","severity":"medium","description":"..."}'
python3 ~/.agent/scripts/src-workspace.py mark-tested target.edu.cn /api/base/login
python3 ~/.agent/scripts/src-workspace.py add-note target.edu.cn "WAF blocking on port 8080"
python3 ~/.agent/scripts/src-workspace.py list                    # 列出所有工作区
python3 ~/.agent/scripts/src-workspace.py export target.edu.cn    # 导出完整报告
```

工作区目录: /tmp/vuln_reports/<domain>/
- workspace.json: 扫描状态
- subs.txt: 子域列表
- alive.txt: 存活子域
- vulns.json: 发现的漏洞
- reports/: 报告
- evidence/: 证据

### edu-full-scan.py

```bash
# 完整扫描
python3 ~/.agent/scripts/edu-full-scan.py target.edu.cn

# 快速模式(跳过JS分析和深挖)
python3 ~/.agent/scripts/edu-full-scan.py target.edu.cn --fast

# 断点续扫
python3 ~/.agent/scripts/edu-full-scan.py target.edu.cn --resume

# 只执行特定阶段
python3 ~/.agent/scripts/edu-full-scan.py target.edu.cn --phase recon
python3 ~/.agent/scripts/edu-full-scan.py target.edu.cn --phase fingerprint
python3 ~/.agent/scripts/edu-full-scan.py target.edu.cn --phase vuln_scan
python3 ~/.agent/scripts/edu-full-scan.py target.edu.cn --phase js_scan
python3 ~/.agent/scripts/edu-full-scan.py target.edu.cn --phase report
```

## 实战效果

### cuit.edu.cn (2026-06-02)
- 批量探测: 5域名2.4秒(之前300秒超时) → 效率提升125x
- 自动漏洞扫描: ywtb.cuit.edu.cn自动识别CAS系统，发现7个漏洞
- JS分析: 2.2MB bundle提取58个Vue路由

### 扩展指纹库
在 auto-vuln-scan.py 的 FINGERPRINT_DB 中添加新产品:
```python
'product_name': {
    'name': '产品名称',
    'match': {
        'headers': [r'pattern'],
        'body': [r'pattern'],
        'cookies': [r'pattern'],
    },
    'paths': [
        ('/path', 'GET', '描述', 'severity', lambda b: 'indicator' in b),
    ],
},
```

## Agent使用模式

当Hermes Agent收到SRC任务时:
1. `edu-full-scan.py <domain>` 一键启动
2. 脚本输出结果后，Agent分析高价值目标
3. 对高价值目标手动深挖(auto-vuln-scan + js-secrets-scanner)
4. `src-workspace.py add-vuln` 记录发现
5. `src-workspace.py export` 生成报告
