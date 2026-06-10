# SRC/渗透技能公开发布匿名化规则

## 核心原则

SRC 漏洞报告中的目标公司名、具体子域名、员工姓名等**不能出现在公开仓库中**。
但漏洞类型、技术手法、工具用法等**通用知识必须保留**。

## 公司名替换规则

### 按行业泛化

| 原名 | 替换为 | 行业 |
|:-----|:-------|:-----|
| MGM / 美高梅 | 某博彩集团 | 博彩 |
| 华住 / Huazhu | 某酒店集团 | 酒店 |
| T3出行 | 某出行平台 | 出行 |
| 萤石 / EZVIZ | 某IoT厂商 | IoT |
| 轻松筹 / QSSRC | 某众筹平台 | 众筹 |
| SHEIN | 某跨境电商 | 电商 |
| 携程 / Ctrip | 某OTA平台 | 旅游 |
| 顺丰 / SF | 某物流集团 | 物流 |
| 美团 | 某生活服务平台 | 生活服务 |
| 快手 | 某短视频平台 | 社交媒体 |

### 教育机构泛化

| 原名 | 替换为 |
|:-----|:-------|
| 华中师范大学 | 某综合性高校 |
| 上海体育大学 | 某教育机构 |
| 河南农业职业学院 | 某教育机构 |
| 具体高校名 | 某高校 / 某教育机构 |

### 产品/软件名保留规则

以下**可以保留**（它们是公开的软件产品，不是目标公司）：
- 联奕 / Lianyi（CAS 产品厂商）
- Liferay（开源门户平台）
- 金智 / Wisedu（教育信息化厂商）
- Spring Boot / Actuator（开源框架）
- FWI CMS（内容管理系统）
- ADFS（Active Directory Federation Services）
- Kong / APISIX / Nginx（开源网关/服务器）

以下**需要泛化**：
- `金智CAS` 当指具体部署实例时 → `统一身份认证平台`
- `FWI CMS` 当指具体目标部署时 → `CMS系统`

## 漏洞细节泛化

| 原描述 | 泛化后 | 原因 |
|:-------|:-------|:-----|
| AppSecret→学生数据 | AppSecret→敏感数据 | "学生数据"暴露行业 |
| 296品牌 | 多品牌 | 具体数字可关联目标 |
| GSRM WAF | WAF | 除非 WAF 名称是公开产品 |
| Mlife会员系统 | 会员系统 | 品牌名 |
| portalapi + CORS反射型 | 通用API + CORS反射型 | 具体路径可关联目标 |
| cjia AppSecret | AppSecret | 具体服务名 |

## 数字泛化

- 具体漏洞数量（如"15个漏洞"）→ 保留（这是你的成果统计）
- 具体端口号（如 10030）→ 保留（通用技术信息）
- 具体 IP 地址 → 仅当是目标泄露的内部 IP 时保留（漏洞证据），自己的 VPN/服务器 IP 必须删除

## 检查流程

```python
import os

# 已知目标关键词（按需扩展）
KNOWN_TARGETS = [
    '华住', 'Huazhu', 'MGM', '美高梅', 'T3出行', '萤石', 'EZVIZ',
    '轻松筹', 'QSSRC', 'SHEIN', '携程', 'Ctrip', '顺丰', 'SF Express',
    '美团', '快手', '华中师范', '上海体育', '河南农业',
    'Mlife', 'portalapi', 'cjia', 'signin',
]

def scan_for_targets(directory='skills/'):
    findings = []
    for root, dirs, files in os.walk(directory):
        for fname in files:
            if not fname.endswith(('.md', '.py', '.sh')):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath) as f:
                    for i, line in enumerate(f, 1):
                        for target in KNOWN_TARGETS:
                            if target.lower() in line.lower():
                                findings.append(f"  {fpath}:{i} [{target}] {line.strip()[:80]}")
            except:
                pass
    return findings

results = scan_for_targets()
if results:
    print(f"⚠️  Found {len(results)} target references:")
    for r in results:
        print(r)
else:
    print("✅ No target-specific references found")
```

## 注意事项

1. **行业统计可以保留** — "某酒店集团 15 个漏洞" 不会暴露具体目标
2. **技术手法必须保留** — CORS+IDOR 链、CAS Open Redirect 等是通用知识
3. **工具命令必须保留** — curl/sqlmap/nuclei 命令是公开工具用法
4. **ATT&CK mapping 必须保留** — T1190/T1059 等是通用框架
5. **README 成果卡片** — 用 shields.io badge 时也必须泛化: `🎰_某博彩集团` 而非 `🎰_MGM`
