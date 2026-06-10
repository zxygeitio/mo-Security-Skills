# 旷视科技(Megvii) SRC 测试模式

## 目标概况
- **SRC平台**: 火线(huoxian.cn) - https://megvii.huoxian.cn/
- **核心业务**: www.faceid.com, api.faceid.com, www.megvii.com, cloud9.megvii.com
- **普通业务**: *.brainpp.cn, *.megviirobotics.com, *.megvii-inc.com
- **一般业务**: *.koalacam.net(不含v3), *.xlsdn.com
- **排除资产**: vpn.megvii-inc.com, p6sai.com, xiaoshouyiservice.megvii-inc.com

## 资产指纹(2026-05-31)

### 核心平台
| 子域 | 用途 | 技术栈 |
|------|------|--------|
| srp.megvii.com | 认证平台客户服务中心 | Vue SPA + Prometheus |
| cloud9.megvii.com/aiot | 旷视九霄IoT平台 | React SPA, nginx/1.17.6 |
| faceidenterprise.megvii.com | FaceID企业版 | Nuxt SSR + AWSC |
| console.faceplusplus.com.cn | Face++控制台 | Vue SPA |
| api.megvii.com | Face++ API网关 | 需api_key认证 |
| api-escort.megvii.com | 护送API | 需cappkey+ctimestamp |

### 认证/账号系统
| 子域 | 用途 | 技术栈 |
|------|------|--------|
| account.megvii-inc.com | 密码修改系统 | Vue + AliyunCaptcha |
| sso.megvii-inc.com | SSO(CAS) | Tengine默认页 |
| account-retail.xlsdn.com | 零售用户中心 | Vue + OAuth2/OIDC |
| account-retail-test.xlsdn.com | 零售用户中心(测试) | Vue + OAuth2/OIDC |

### 内部系统
| 子域 | 用途 | 技术栈 |
|------|------|--------|
| megoa.megvii-inc.com | OA系统 | 致远OA |
| onboard-epif.megvii-inc.com | 入职系统 | Vue SPA |
| mlearning.megvii-inc.com | 学习平台(MegEnergy) | Vue + 阿里云视频 |
| jira.megviirobotics.com | JIRA | v8.13.18 Server |
| project.megviirobotics.com | Confluence | REST API可访问 |
| cityiotorder.megvii.com | 城市IoT订单 | Spring Boot + Actuator |
| facestyle.megvii.com | Facestyle | Flask SPA |

## 已验证漏洞模式

### 1. Prometheus Metrics未授权访问 [低危]
- **目标**: srp.megvii.com/metrics
- **特征**: 返回text/plain, version=0.0.4, 38KB+指标
- **泄露**: 36个内部API路径、K8s主机名(mcd-srp-web-external-d-r-p-xxx)、性能指标
- **curl**: `curl -sk 'https://srp.megvii.com/metrics'`

### 2. FaceEE签名凭据泄露 [中危]
- **目标**: account.megvii-inc.com/api/v2/faceee/getFaceSign
- **特征**: 未认证返回Authorization、X-FaceEE-ClientId、Algorithm、Timestamp
- **state参数**: 包含note:"ResetPWD", type:"web_login_without_username"
- **curl**: `curl -sk 'https://account.megvii-inc.com/api/v2/faceee/getFaceSign'`

### 3. 前端JS硬编码Token [低危]
- **目标**: cdn.faceplusplus.com.cn/alpha/assets/app.*.js
- **特征**: Token="9fd116cb2513406f9c7e4e50fefa4219"
- **附带**: WeChat AppID(wx3d89f4cfa10b4a3f, wxff1151586dd57861), 内部API(api.megvii.com/cardpp/beta/templateocr)
- **curl**: `curl -sk 'https://cdn.faceplusplus.com.cn/alpha/assets/app.c2bc52e5f2516f3e4042.js' | grep -oP 'Token="[a-f0-9]{32}"'`

### 4. 测试环境Debug API泄露 [低危]
- **目标**: account-retail-test.xlsdn.com/static/config.js
- **特征**: 注释中暴露account-debug.megyueying.com, solar-debug.megyueying.com
- **curl**: `curl -sk 'https://account-retail-test.xlsdn.com/static/config.js'`

### 5. Spring Boot Actuator暴露 [低危]
- **目标**: cityiotorder.megvii.com/actuator
- **特征**: 返回application/vnd.spring-boot.actuator.v3+json
- **端点**: health(UP), health-path, info
- **curl**: `curl -sk 'https://cityiotorder.megvii.com/actuator'`

### 6. OpenID Connect配置暴露 [信息]
- **目标**: account-retail.xlsdn.com/.well-known/openid-configuration
- **端点**: /oauth/authorize, /oauth/token, /token_keys(JWK)
- **curl**: `curl -sk 'https://account-retail.xlsdn.com/.well-known/openid-configuration'`

## API认证机制

### api-escort.megvii.com
- 需要headers: cappkey + ctimestamp
- ctimestamp有效期15分钟
- /health端点无需认证返回{"status":"UP"}

### api-cn.faceplusplus.com (Face++ API)
- 需要POST参数: api_key + api_secret
- 返回AUTHENTICATION_ERROR表示凭据无效

### cloud9.megvii.com/aiot
- SSO: https://sso.megvii-inc.com/cas/login?service=...
- API前缀: /aiot/
- 关键端点: /aiot/auth/login(POST), /account/*, /appkey/*, /device/export, /person/export

## SPA路由fallback模式
以下域名所有路径返回相同200响应(SPA fallback)，需通过JS分析真实API:
- faceidenterprise.megvii.com (39348字节)
- facestyle-console.megvii.com (2859字节)
- hetu-developer.megvii.com (2640字节)
- onboard-epif.megvii-inc.com (1661字节)
- account.megvii-inc.com (2361字节)
- retail.xlsdn.com/work/ (标注平台)
- retail-test.xlsdn.com/work/ (标注平台测试)

## 报告格式要求
- 平台: 火线漏洞盒子
- 标题: "xxx站xxx处存在xxx漏洞"
- 纯文本不用HTML
- 复现完整可一次性复测
- 分步骤图文
- 单行curl命令
- 【截图位置N】标注
- 危害证明完整

### 7. 测试环境开发模式未授权访问 [中危]
- **目标**: retail-test.xlsdn.com/api/retail/product/v1/users/development/mode
- **特征**: 未认证返回{"code":0,"data":true}，表示开发模式已启用
- **影响**: 开发模式通常禁用安全检查、启用调试功能
- **curl**: `curl -sk 'https://retail-test.xlsdn.com/api/retail/product/v1/users/development/mode'`
- **关联内部域名**: account-test.bibt.cn, account-retailbox-test.basemind.com, retailbox-test.basemind.com, retail-test.bibt.cn

### 8. FaceID API错误信息泄露 [低危]
- **目标**: faceid.com/docs
- **特征**: 返回JSON错误{"errcode":101000003,"errmsg":"对不起，您无权访问此数据"}
- **影响**: 暴露内部错误码体系和API设计
- **curl**: `curl -sk 'https://faceid.com/docs'`

### 9. 零售标注平台API暴露 [信息]
- **目标**: retail.xlsdn.com/work/, retail-test.xlsdn.com/work/
- **平台**: 标注平台(Annotation Platform) - AI训练数据标注
- **JS入口**: /work/assets/js/index.js (1.5MB)
- **API前缀**: /api/retail/product/v1/
- **关键端点**: /users/info(401), /users/development/mode(200), /products, /orders, /categories, /inventory, /reports, /settings, /admin
- **CAS集成**: /api/uc/authenticator/v1/cas/logout?service=
- **baseURL**: https://account-test.bibt.cn

## 测试环境暴露清单
| 域名 | 用途 | 状态 |
|------|------|------|
| account-test.bibt.cn | 用户中心测试 | 可访问 |
| account-retailbox-test.basemind.com | 用户中心测试 | 可访问 |
| retailbox-test.basemind.com | 零售平台测试 | 301重定向 |
| retail-test.bibt.cn | 零售平台测试 | 可访问 |
| account-debug.megyueying.com | Debug API | 配置泄露 |
| solar-debug.megyueying.com | WebSocket | 配置泄露 |

## 新增漏洞模式 (2026-06-02)

### 10. JIRA REST API未授权信息泄露 [低危]
- **目标**: jira.megviirobotics.com (JIRA Server 8.13.18)
- **未授权端点**: /rest/api/2/field, /rest/api/2/priority, /rest/api/2/status, /rest/api/2/issue/createmeta, /rest/api/2/issueLinkType, /secure/QueryComponent!Default.jspa
- **泄露**: 自定义字段(customfield_10000"开发")、优先级配置、Issue关联类型、状态值(Open/In Progress/To Do/Done/active/checking/backing/cancel/In Review)
- **CVE**: CVE-2020-14179
- **curl**: `curl -sk 'https://jira.megviirobotics.com/rest/api/2/field' | python3 -c "import json,sys; [print(f'{f[\"id\"]}: {f[\"name\"]}') for f in json.load(sys.stdin) if f.get('custom')]"`
- **注意**: REST API响应慢(10-20秒)，用timeout 20 curl

### 11. Confluence旧版本暴露公网 [中危]
- **目标**: project.megviirobotics.com (Confluence Server 7.4.17)
- **版本确认**: 响应头 ajs-version-number: 7.4.17
- **已知CVE**: CVE-2021-26084(OGNL注入RCE, CVSS 9.8), CVE-2022-26134(OGNL注入RCE, CVSS 9.8), CVE-2022-26138(硬编码凭据)
- **未授权REST API**: /rest/api/space(200, 空结果), /rest/api/content(200, 空结果)
- **CVE-2021-26084测试**: POST /pages/createpage-entervariables.action 返回302(需登录)，可能已修补或需不同payload
- **CVE-2022-26138测试**: disabledsystemuser/disabled1system1user6708 返回AUTHENTICATED_FAILED
- **curl**: `curl -sk 'https://project.megviirobotics.com/login.action' | grep 'ajs-version-number'`

### 12. srp.megvii.com CORS通配符+凭据 [低危]
- **目标**: srp.megvii.com (全站)
- **特征**: access-control-allow-origin: * + access-control-allow-credentials: true
- **注意**: 浏览器不会在通配符Origin下发送Cookie，实际危害有限
- **curl**: `curl -sk -H 'Origin: https://evil.com' 'https://srp.megvii.com/' -D- | grep access-control`

### 13. cloud9 IoT平台未授权模板下载 [低危]
- **目标**: cloud9.megvii.com/v1/web/usercenter/person/downloadTemplate
- **特征**: 无需认证返回Excel模板文件(员工.xlsx)
- **类型参数**: type=1(10261B), type=2(10362B), type=3(9390B), type=4/5(57B错误)
- **API签名**: 其他/v1/web/usercenter/*端点返回{"msg":"签名错误","code":100008}
- **curl**: `curl -sk 'https://cloud9.megvii.com/v1/web/usercenter/person/downloadTemplate?type=1' -o template.xlsx`

### 14. 零售平台配置泄露调试域名 [低危]
- **目标**: retail.xlsdn.com/work/static/config.js 和 retail-test.xlsdn.com/work/static/config.js
- **泄露域名**: nasa-debug.megyueying.com, account-center-fed-bibt-debug.mcd.megvii-inc.com, retail-fed-bibt-debug.mcd.megvii-inc.com, solar-debug.megyueying.com
- **curl**: `curl -sk 'https://retail.xlsdn.com/work/static/config.js'`

## 新增资产指纹 (2026-06-02)

### FaceEE OAuth系统
| 子域 | 用途 | 技术栈 |
|------|------|--------|
| faceee.megvii-inc.com | FaceEE主站(CAS) | nginx + CAS SSO |
| faceee-pek.megvii-inc.com | FaceEE北京节点 | nginx + OAuth2 |
| enterprise-demo.faceid.com | FaceEE企业演示 | nginx, 302→/faceee/v1/user_center |

- **OAuth流程**: faceee-pek.megvii-inc.com/oauth/authorize → CAS登录 → 回调
- **CAS service验证**: CAS会验证service参数，未注册的域名返回"Service Expired"
- **注意**: faceee-pek接受任意service参数但CAS层会拒绝未注册域名

### megvii.com主站
- **技术栈**: PHP + OpenRASP WAF + Alibaba Cloud CDN
- **WAF指纹**: x-protected-by: OpenRASP; 敏感路径(.env/.git/xmlrpc.php)返回405 Alibaba Cloud拦截页
- **CORS**: access-control-allow-origin: * (通配符)
- **注意**: .env/.git返回405不是文件存在，是WAF拦截

### faceid.com子域状态
- admin-dev/admin-test/admin-v2/admin-v3/api-dev/api-test/request-review-dev.faceid.com: 全部返回nginx 404(162B)，无实际服务
- api-v2.faceid.com: timeout; demo.faceid.com: SSL错误(35)
- **结论**: 大部分faceid.com子域是DNS记录但无实际服务

### 其他内部系统(不可达)
docker-registry.brain.megvii-inc.com / owncloud.megvii-inc.com / git-core.megvii-inc.com / wiki.megvii-inc.com / erp.megvii-inc.com / moa.megvii-inc.com / monitor.brain.megvii-inc.com / csg-faceee.megvii-inc.com — 全部timeout(内网)
www.brainpp.cn — 解析到10.122.236.193(内网IP)

## 测试陷阱 (2026-06-02)

### 并行HTTP探活超时
- 80+子域用concurrent.futures(30线程)探活在180秒内超时
- **原因**: DNS解析不可达域名时hang住，单个超时累积
- **正确做法**: 分批(15-20个)串行curl --max-time 4，或先DNS过滤不可达域名

### faceid.com子域假阳性
- 多个faceid.com子域返回nginx 404(162B)，是CDN默认页不是真实服务
- **验证方法**: 检查多个路径是否都返回相同162B，如果是则为假阳性

### OpenRASP WAF误判
- megvii.com的.env/.git/xmlrpc.php返回405(不是404)，是WAF拦截不是文件存在
- **验证方法**: 检查响应内容是否为Alibaba Cloud拦截页(traceid格式)

## 子域名枚举效率
- **subfinder**: faceid.com(24), megvii-inc.com(54), xlsdn.com(8)效果好; megvii.com和brainpp.cn返回0
- **crt.sh**: megvii.com查询超时(>20秒)
- **手动枚举**: megvii.com的www/admin/mail/console等子域可手动发现
- **DNS**: brainpp.cn无A记录，www.brainpp.cn解析到内网IP(10.122.236.193)

## 测试日期: 2026-06-02 (更新)
## 子域名数量: 86个(新增枚举), 存活~30个
