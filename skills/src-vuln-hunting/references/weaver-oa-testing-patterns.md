# 泛微OA (Weaver E-Cology) 漏洞测试模式

## 概述
泛微网络E-Cology是中国高校和企业广泛使用的协同办公OA系统。本文档记录泛微OA的常见漏洞模式和测试方法。

## 指纹识别

### 快速检测
```bash
# Cookie检测
curl -sk -I 'https://<target>/' | grep -i 'ecology_JSessionid'

# JS后缀检测
curl -sk 'https://<target>/' | grep '_wev8'

# SPA入口检测
curl -sk 'https://<target>/wui/index.html' | head -5

# 云资源路径
curl -sk 'https://<target>/' | grep '/cloudstore/resource/'
```

### 版本识别
| 版本 | 特征 |
|------|------|
| E-Cology 9 | React SPA, `/cloudstore/resource/pc/`, `/spa/` 路径 |
| E-Cology 8 | jQuery, `/wui/` 路径, `_wev8` 后缀 |
| E-Weaver | 微服务架构, `/api/` 前缀 |

## CORS配置错误

### 特征
泛微OA常见CORS配置为 `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`

### 检测
```bash
curl -sk -H 'Origin: https://evil.com' -I 'https://<target>/' | grep access-control
curl -sk -H 'Origin: https://evil.com' -I 'https://<target>/api/login/verifyCode' | grep access-control
```

### 影响
- 泛微OA包含人事管理、工作流程、文档管理等敏感数据
- 如果CORS配置被绕过，可跨域读取敏感信息

## CAS集成

### 特征
泛微OA通常集成CAS SSO认证，登录页重定向到CAS

### 检测
```bash
# 检查CAS服务参数
curl -sk 'https://<target>/login/Login.jsp' | grep -oP 'service=[^"]*'

# 检查HTTP降级
curl -sk 'https://<target>/login/Login.jsp' | grep 'service=http%'
```

### 常见问题
- CAS service参数使用HTTP而非HTTPS
- 泛微OA的CAS回调URL可能泄露

## API端点探测

### 公开API
```bash
# 验证码
curl -sk 'https://<target>/api/login/verifyCode'

# 登录检查
curl -sk 'https://<target>/api/login/checkLogin'

# 系统信息
curl -sk 'https://<target>/api/system/info'
```

### 认证API (返回登录超时)
```bash
# HR SSO
curl -sk 'https://<target>/api/hrm/ssologin'

# 开发模式
curl -sk 'https://<target>/api/ec/devMode/check'

# 工作流
curl -sk 'https://<target>/api/workflow/'

# 文档
curl -sk 'https://<target>/api/doc/'

# 用户
curl -sk 'https://<target>/api/user/'
```

### 标准响应
未认证请求返回:
```json
{"msg":"登录信息超时","errorCode":"002","status":false}
```

## 已知漏洞路径

### SQL注入
```bash
curl -sk 'https://<target>/docs/docs/DocDsp.jsp?id=1'
```

### 文件读取
```bash
curl -sk 'https://<target>/api/ec/devMode/check'
```

### 信息泄露
```bash
curl -sk 'https://<target>/api/system/info'
curl -sk 'https://<target>/api/system/version'
```

## 常见子域名
- `fuwu.<domain>` - 泛微OA服务
- `oa.<domain>` - OA系统
- `workflow.<domain>` - 工作流系统
- `portal.<domain>` - 门户系统

## 测试要点

1. **CORS检查**: 泛微OA常有CORS配置错误
2. **CAS集成**: 检查CAS回调URL的协议(HTTP/HTTPS)
3. **API探测**: 尝试未认证访问敏感API
4. **版本识别**: 不同版本有不同漏洞特征
5. **子域枚举**: 泛微OA可能部署在多个子域名

## 已测试目标

| 目标 | 发现 | 备注 |
|------|------|------|
| fuwu.nau.edu.cn | CORS配置错误(* + credentials) | E-Cology 9, 集成CAS SSO |

## 注意事项

1. 泛微OA是高价值目标，包含敏感业务数据
2. CORS配置错误在泛微OA中很常见
3. 泛微OA通常集成CAS认证，检查CAS漏洞
4. API端点需要认证，但可尝试绕过
5. 不同版本的漏洞特征不同，先识别版本
