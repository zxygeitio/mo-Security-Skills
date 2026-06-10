# CPIC GTM域名系统未授权访问漏洞 (2026-05-16)

## 目标
- property.gtm.cpic.com.cn
- life.gtm.cpic.com.cn

## 发现过程
1. 通过Burp代理批量扫描CPIC域名
2. 发现 `*.gtm.cpic.com.cn` 域名所有路径返回200
3. 尝试直接curl访问被DNS解析阻止

## 验证结果（通过Burp代理curl）
```bash
# life.gtm.cpic.com.cn 扫描结果
200 /                           # 主页
200 /actuator/env              # 环境变量泄露
200 /actuator/health           # 健康检查
200 /actuator/heapdump        # 堆转储文件(潜在RCE)
200 /actuator/beans           # Spring beans泄露
200 /actuator/mappings         # URL映射泄露
200 /actuator/configprops       # 配置属性泄露
200 /api/                      # API根目录
200 /api/user                  # 用户API
200 /api/login                 # 登录API
200 /api-docs                  # API文档
200 /swagger-ui.html           # Swagger文档
200 /v2/api-docs              # API v2文档
200 /.git/config               # Git配置泄露
200 /.git/HEAD                 # Git HEAD
200 /.git/index                # Git索引
200 /manager/                  # Weblogic管理
200 /console/                  # Weblogic控制台
200 /web-console/             # JBOSS web控制台
200 /t3/                       # Weblogic T3协议
200 /uddiexplorer/            # Weblogic UDDI
200 /jmx-console/             # JBOSS JMX控制台
```

## 关键问题
- **Burp拦截**: 直接curl/浏览器无法解析内网域名
- **需验证**: 实际数据是否可被未授权用户读取
- **ROT代理**: 103.144.67.x 是ROT集群，按Host头路由

## 漏洞定级建议
| 漏洞 | 风险 | 说明 |
|------|------|------|
| actuator/env未授权 | 高 | 泄露数据库密码/API密钥/云凭证 |
| actuator/heapdump | 严重 | 可导致RCE |
| .git/config | 中 | 源码泄露 |
| manager/console | 严重 | Weblogic未授权管理 |

## 利用条件
需解决Burp DNS解析限制：
1. 设置浏览器系统代理使用Burp
2. 或在hosts文件添加 `103.144.67.x life.gtm.cpic.com.cn`
3. 或用Python socket直接连接
