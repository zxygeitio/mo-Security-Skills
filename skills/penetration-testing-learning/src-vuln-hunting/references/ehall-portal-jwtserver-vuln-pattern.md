# ehall/portal 统一身份认证系统漏洞模式

## 目标系统特征
- 南京诚勤教育科技有限公司 开发的教育门户系统
- 使用 sems 系列微服务架构
- 典型域名: ehall.{school}.edu.cn, portal.{school}.edu.cn, cas.{school}.edu.cn

## 已确认使用该系统的学校
- qtnu.edu.cn (青海师范大学)
- xjbyxy.cn (巴音郭楞职业技术学院)
- cug.edu.cn (中国地质大学)
- ucas.ac.cn (中国科学院大学)

## 技术架构

### 服务组件
```
gateway.{school}.edu.cn - API网关
├── sems-authc - 认证服务
├── sems-tp-nup - 门户服务
├── sems-tp-core - 核心服务
└── sems-tp-m-eweb - 移动生态
```

### CAS认证系统
- 路径: `/tpass/login` 或 `/cas/login`
- 使用 sw-ui 前端框架 (树维信息)
- 支持: 用户名密码、QQ、微信、钉钉登录

### JWT认证服务
位置: `ehall.{school}.edu.cn/a/manager/identify/identify.js`

配置参数:
```javascript
{
    jwtserver: '/a/jwtservermanager/',
    websocketserver: '/a/jwtservermanager/ws',
    tokenname: 'token',
    tokentime: '120',  // 分钟
    savetype: '0',     // 0=cookie, 1=localStorage
    pwdlength: 8,
    socketlength: 6
}
```

## 关键API端点 (jwtservermanager)

| 端点 | 方法 | 说明 |
|------|------|------|
| `/a/jwtservermanager/login` | POST | 登录 |
| `/a/jwtservermanager/changepassword` | POST | 修改密码 |
| `/a/jwtservermanager/getvalidateimage` | GET | 获取验证码 |
| `/a/jwtservermanager/changetoken` | POST | 更换token |
| `/a/jwtservermanager/relogin` | POST | 重新登录 |
| `/a/jwtservermanager/logout` | POST | 登出 |
| `/a/jwtservermanager/wxlogin` | GET | 微信登录 |
| `/a/jwtservermanager/ws` | WebSocket | WebSocket连接 |

## 已发现的漏洞模式

### 1. changepassword 未授权访问
```bash
curl "https://ehall.qtnu.edu.cn/a/jwtservermanager/changepassword"
```
响应:
```json
{"code":2000,"token":null,"data":{},"message":"系统错误","status":"changepassword"}
```
**问题**: 未验证身份即可访问修改密码接口，返回系统错误而非权限拒绝

### 2. 潜在攻击向量
- JWT token 伪造/绕过
- WebSocket 未授权访问
- 密码重置逻辑漏洞
- 验证码绕过
- Token 刷新机制漏洞

## 测试命令汇总

```bash
# 检测是否存在 ehall 系统
curl -s "https://ehall.{target}/a/manager/identify/identify.js" -k | head -20

# 检测 jwtservermanager 端点
curl -s "https://ehall.{target}/a/jwtservermanager/changepassword" -k

# 检测 portal 系统
curl -s "https://portal.{target}/tp_nup/defaults/js/constant.js" -k | head -30

# 检测 CAS tpass
curl -s "https://cas.{target}/tpass/login" -k | grep -oP 'src="[^"]*"' | head -20

# 检测 gateway
curl -s "https://gateway.{target}/sems-authc" -k
```

## 识别指纹
1. 访问 `/a/manager/identify/identify.js` 存在
2. portal 页面引用 `sems-tp-nup` 或 `sems-tp-core`
3. CAS 页面使用 sw-ui 框架
4. constant.js 中定义 `gateway_url` 和 `cas_path`

## 参考
- 漏洞类型: 逻辑漏洞 + 代码执行
- 报告路径: /tmp/vuln_reports/{school}/
