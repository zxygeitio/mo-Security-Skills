# DNS劫持/WARP环境下的真实IP发现

## 问题描述

在Kali环境中使用Cloudflare WARP时，DNS解析会被劫持到198.18.0.x范围。虽然WARP代理转发使连接正常工作，但无法获取目标真实IP，也无法进行直接IP访问测试。

## 识别特征

```bash
# DNS解析到198.18.0.x范围
dig @8.8.8.8 +short www.target.com A
# 返回 198.18.0.xx → WARP劫持

# 所有域名返回相同网段
dig @8.8.8.8 +short domain1.com A  # 198.18.0.11
dig @8.8.8.8 +short domain2.com A  # 198.18.0.34
```

## 解决方案

### 方法1: 外部DNS查询
```bash
# 使用外部DNS服务器获取真实IP
dig @8.8.8.8 +short www.target.com A
dig @114.114.114.114 +short www.target.com A
dig @223.5.5.5 +short www.target.com A

# 如果仍返回198.18.0.x，说明WARP在系统层面劫持了DNS
```

### 方法2: 直接IP访问测试
```bash
# 用获取的真实IP直接访问
curl -sk http://REAL_IP/ -H 'Host: www.target.com'
curl -sk https://REAL_IP/ -H 'Host: www.target.com' -k

# 检查是否绕过CDN/WAF
curl -sk http://REAL_IP/ -H 'Host: www.target.com' | grep -i "server:"
```

### 方法3: 真实IP端口扫描
```bash
# 扫描真实IP的端口
nmap -Pn -sT --top-ports 20 -T4 --open REAL_IP

# 对比WARP代理和真实IP的端口差异
nmap -Pn -sT --top-ports 20 -T4 --open www.target.com  # 通过WARP
nmap -Pn -sT --top-ports 20 -T4 --open REAL_IP          # 直接访问
```

## 实战案例

### 新疆交通职业技术大学 (2026-06-01)
- WARP劫持: 所有域名解析到198.18.0.x范围
- 真实IP发现:
  - www.xjjtedu.com → 124.119.15.220
  - www.xjjtxy.cn → 124.119.15.215
- 真实IP端口: 80/tcp, 443/tcp (与WARP代理一致)
- 直接IP访问: 成功获取主站HTML内容

## 注意事项

1. **WARP代理仍可用**: 198.18.0.x范围的连接通过WARP代理转发，测试结果仍然有效
2. **真实IP可能被CDN保护**: 某些目标的真实IP可能被Cloudflare/阿里云等CDN保护
3. **端口差异**: 真实IP可能暴露更多端口（内网服务）
4. **Host头必须匹配**: 直接IP访问时必须设置正确的Host头
5. **SSL证书**: 直接IP访问时可能需要忽略证书验证(-k参数)

## 相关工具

- `dig` - DNS查询
- `nmap` - 端口扫描
- `curl` - HTTP请求
- `host` - DNS查询
- `nslookup` - DNS查询

## 关联技能

- `src-vuln-hunting` - SRC漏洞挖掘主流程
- `pentest-recon-driven` - 信息收集驱动渗透测试
- `auto-recon-lowhanging` - 自动化初始侦察
