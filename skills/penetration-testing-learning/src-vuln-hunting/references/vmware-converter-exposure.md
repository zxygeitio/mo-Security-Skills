# VMware vCenter Converter Standalone Exposure Pattern

## 指纹识别
- 主页HTML: `<meta name="description" content="VMware vCenter Converter Standalone">`
- JS文件: `./en/welcomeRes.js` 含 `ID_Converter = "VMware vCenter Converter Standalone X.Y.Z"`
- 页面包含Windows/Linux客户端下载链接: `/converter/VMware-Converter-Client.exe`
- 页面使用JS动态设置title: `document.write("<title>" + ID_Converter_Welcome + "</title>")`

## 高价值端点 (无需认证)

### 版本信息
```bash
curl -sk "https://TARGET/en/welcomeRes.js" | grep "ID_Converter ="
# 返回: var ID_Converter = "VMware vCenter Converter Standalone 6.1.1";
```

### SOAP API (活跃确认)
```bash
curl -sk -X POST "https://TARGET/converter/sdk/" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test/></soap:Body></soap:Envelope>'
# 返回SOAP Fault XML → 确认API端点活跃
# 正确命名空间: urn:vim25 (不带版本号)
```

### Managed Object Browser (MOB) - 内部路径泄露
```bash
curl -sk "https://TARGET/converter/mob/"
# 返回503，泄露:
# pipeName =\\.\pipe\vmware-converter-server-mob
# class Vmacore::Http::NamedPipeServiceSpec
# _serverNamespace = /converter/mob
```

### 其他端点
```bash
# /converter/ → 303→/converter/
# /converter/sdk/ → 501 (GET) 或 SOAP响应 (POST)
# /converter/mob/ → 503 (泄露内部路径)
# /converter/VMware-Converter-Client.exe → 200 (23MB下载)
```

## 已知CVE (6.1.1受影响)
| CVE | 类型 | CVSS | 描述 |
|-----|------|------|------|
| CVE-2022-22957 | RCE | 8.8 | 远程代码执行 |
| CVE-2022-22959 | XSS | 6.1 | 跨站脚本 |
| CVE-2022-22960 | 本地提权 | 7.8 | 本地权限提升 |
| CVE-2022-22957/22958 | RCE | 8.8 | 远程代码执行(多个) |

## 报告角度
- 标题: "xxx学校VMware vCenter Converter Standalone存在未授权访问漏洞"
- 等级: 中危 (版本暴露+SOAP API活跃+内部路径泄露+已知CVE)
- 影响: SOAP API可被用于信息收集，MOB泄露内部Windows命名管道，客户端可被下载逆向分析，已知CVE可被利用
- 修复: 升级到最新版本 + 限制内网/VPN访问 + 关闭不需要的服务

## cuit.edu.cn 实战案例 (2026-05-28)
- 域名: wlzf.cuit.edu.cn
- 版本: 6.1.1
- 客户端大小: 23,118,856 bytes (23MB)
- SOAP API: 活跃 (POST返回XML错误)
- MOB: 503 (泄露pipeName)
- CERNET IP: 210.41.x.x
- 与Shibboleth IdP暴露在同一学校

## 常见子域名命名
wlzf, converter, vmware, migrate, vconverter, p2v
