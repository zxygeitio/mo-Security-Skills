# CPIC VPN路由与新IP段ROT验证 (2026-05-16)

## VPN路由现状

| 路由段 | VPN可达 | 说明 |
|--------|---------|------|
| 116.228.0.0/16 | ✅ 是 | 太保主站相关 |
| 116.236.67.182 | ❌ 否 | www.cpic.com.cn真实IP，不在VPN路由内 |
| 101.204.0.0/14 | ✅ 是 | amass发现的新段 |
| 101.207.0.0/16 | ✅ 是 | amass发现 |
| 103.144.0.0/16 | ✅ 是 | amass发现 |
| 103.230.0.0/16 | ✅ 是 | amass发现 |
| 182.150.0.0/16 | ✅ 是 | amass发现 |

**问题**：太保VPN分配出口IP 118.113.85.152（公网IP），VPN路由表中有116.228/101.204/101.207/103.144/103.230/182.150等段，但www.cpic.com.cn解析到的116.236.67.182不在任何路由段内。

**可能原因**：
1. 太保VPN是商业VPN（非真正的内网专线接入）
2. 需要.p12客户端证书才能建立真正的内网TLS连接
3. VPN配置不完整，缺少内网路由

**检查方法**：
```bash
# 检查VPN安装目录是否有.p12证书
ls -la /opt/cpicvpn/*.p12 2>/dev/null
ls -la ~/OpenVpn/*.p12 2>/dev/null
ls -la /etc/openvpn/*.p12 2>/dev/null

# 检查VPN分配的真实IP
ip addr show tun0

# 测试VPN出口IP
curl -s ifconfig.me
```

## 新发现ROT代理IP (2026-05-16)

| 域名 | IP | 证书O字段 |
|------|-----|-----------|
| mcdsit.cdgslb.cpic.com.cn | 101.204.252.25 | ROT Proxy |
| o2osit.cpic.com.cn | 182.150.61.78 | ROT Proxy |
| capitaloa-sit.cdgslb.cpic.com.cn | 101.207.140.87 | ROT Proxy |
| activityflatform.gtm.cpic.com.cn | 103.144.67.159 | ROT Proxy |
| m25.sjgtm.cpic.com.cn | 103.230.111.70 | ROT Proxy |

## ROT代理TLS阻断验证

所有新IP段的443端口均被ROT代理阻断，curl出现：
```
TLS alert internal error (592)
TLS connect error: error:0A000438:SSL routines::tlsv1 alert internal error
```

OpenSSL s_client能获取证书（证明TCP可达），但curl/wget无法完成TLS握手。

**证书指纹**：
```
Subject: O=ROT Proxy, CN=mcdsit.cdgslb.cpic.com.cn
Issuer:  O=ROT Proxy, CN=rot.proxy
```

## 扫描策略更新

### 优先扫描80端口
ROT代理对80端口的阻断不如443彻底，部分80端口可发现真实业务：
```bash
masscan -p 80 --rate=2000 101.204.0.0/14 -oJ /tmp/masscan_101_80.json
masscan -p 80 --rate=2000 103.144.0.0/16 -oJ /tmp/masscan_103_80.json
```

### 快速验证VPN可达性
```bash
# TCP检测（不依赖TLS）
timeout 2 bash -c 'echo >/dev/tcp/IP/443' && echo "可达" || echo "不可达"
```

## 118个域名侦察结果

Subfinder发现94个有效域名 + Amass被动发现24个 = 118个总域名。

重点B类测试环境：
- onesit.cpic.com.cn
- o2osit.cpic.com.cn  
- wxtest.cdgslb.cpic.com.cn
- mcdsit.cdgslb.cpic.com.cn
- service-sit.cpic.com.cn
- lva7-sit.cpic.com.cn
- newmail-sit.cpic.com.cn

WAF检测：
- life.cpic.com.cn: 阿里云WAF
- asset.cpic.com.cn: 阿里云WAF
