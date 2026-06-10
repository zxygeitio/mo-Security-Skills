# wengine-auth (网瑞达) 认证网关指纹与测试模式

## 概述

网瑞达(wengine)是中国高校常用的统一认证网关，保护教务、办事大厅、图书馆等系统。由北京网瑞达科技有限公司/成都网瑞达科技有限公司开发。

## 指纹特征

### HTTP响应特征
- 重定向URL: `wengine-auth/login?id=XX&path=/&from=https://target/`
- Server: none（故意隐藏）
- Cookie: `wengine_new_ticket=xxx`
- 404页面包含: `/wengine-auth-failed.png` 图片
- 登录页标题: `网络应用认证`

### 页面关键词
- `网瑞达`
- `北京网瑞达科技有限公司`
- `资源访问控制系统`
- `访问控制`
- `堡垒机`
- `SSLVPN`
- `CASB`
- `成都网瑞达科技有限公司`
- `图书馆认证`
- `图书馆统计`
- `图书馆下载分析`
- `电子资源访问控制`

### 认证流程
1. 访问受保护系统（如 jwgl.cust.edu.cn）
2. 302重定向到 `wwwn.cust.edu.cn/wengine-auth/login?id=15&path=/&from=https://jwgl.cust.edu.cn/`
3. 再302重定向到CAS登录（如 `mysso.cust.edu.cn/cas/login?service=http://wwwn.cust.edu.cn/wengine-auth/login?cas_login=true`）

### 常见子域名模式
- `wwwn.cust.edu.cn` - wengine-auth认证网关
- `webvpn.cust.edu.cn` - WebVPN入口
- `my-cust-edu-cn.webvpn.cust.edu.cn` - WebVPN代理

## 测试要点

### 1. CAS漏洞影响范围
如果CAS有Open Redirect漏洞，所有wengine保护的系统都受影响：
- 教务管理系统（jwgl/jwglxt/jsxsd/eams）
- 办事大厅（ehall）
- 图书馆（lib）
- 一卡通（ecard）

### 2. wengine-auth端点检查
```bash
# 检查认证网关
curl -sk 'https://wwwn.cust.edu.cn/wengine-auth/login'

# 检查Actuator端点
curl -sk 'https://wwwn.cust.edu.cn/actuator/health'
curl -sk 'https://wwwn.cust.edu.cn/swagger-ui.html'

# 检查静态资源
curl -sk 'https://wwwn.cust.edu.cn/wengine-auth-static/js/css/login.css'
```

### 3. WebVPN线路选择
WebVPN使用线路选择逻辑，检查：
```bash
# 检查WebVPN入口
curl -sk 'https://webvpn.cust.edu.cn/'

# 检查线路配置
curl -sk 'https://webvpn.cust.edu.cn/' | grep -oP 'line_list[^;]*'
```

## 实战案例

### 长春理工大学 (cust.edu.cn)
- wengine-auth保护: jwgl.cust.edu.cn, ehall.cust.edu.cn, lib.cust.edu.cn
- CAS: mysso.cust.edu.cn (自研CAS, 非金智)
- WebVPN: webvpn.cust.edu.cn
- 发现: CAS Open Redirect (clientredirect验证法)

## 相关技能

- `education-src-blueprint` - 教育SRC蓝图
- `pentest-recon-driven` - 信息收集驱动渗透
