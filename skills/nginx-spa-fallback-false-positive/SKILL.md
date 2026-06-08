---
name: nginx-spa-fallback-false-positive
description: Detect nginx SPA fallback causing false positive vulnerability reports. Critical for Web pentest.
tags:
  - penetration-testing
  - web-security
  - false-positive
  - nginx
---

# Nginx SPA Fallback False Positive Detection

## Problem
When nginx serves a Single Page Application (SPA) with fallback configuration, ALL non-existent paths return HTTP 200 with React/Vue HTML. This causes massive false positive vulnerability reports:

| Path Claimed Exposed | HTTP Status | Reality |
|---------------------|-------------|---------|
| /.git/config | 200 | ❌ NOT a git repo - SPA fallback |
| /backup | 200 | ❌ NOT a backup dir - SPA fallback |
| /actuator/env | 200 | ❌ NOT Spring Actuator - SPA fallback |
| /swagger-ui.html | 200 | ❌ NOT Swagger docs - SPA fallback |

## Root Cause
Typical nginx SPA config:
```nginx
location / {
    try_files $uri $uri/ /index.html;  # ALL paths fallback to SPA
}
```

## Critical Detection Method
Check `Content-Type` header, NOT just HTTP status code:

```bash
# WRONG: Only checking status code → false positive
curl -sk -o /dev/null -w "%{http_code}" "https://target/.git/config"
# Returns: 200  ← DON'T trust this!

# CORRECT: Verify Content-Type
curl -sk -I "https://target/.git/config" | grep "content-type"
# SPA fallback  → text/html
# Real git file → text/plain or application/octet-stream
```

## Verification Checklist
For ANY sensitive path returning HTTP 200:
1. Check `Content-Type` header — text/html on non-HTML paths = SPA fallback
2. Check response body — real files have distinctive content signatures
3. Compare multiple paths — if ALL return identical HTML, it's definitely fallback
4. Cross-reference with known good pages — if /login and /admin return same HTML as /.git, it's fallback

## Example: Spring Actuator Verification
```bash
# Step 1: Check Content-Type
curl -sk -I "https://target/actuator/env" | grep content-type

# Real Actuator     → application/json
# SPA fallback     → text/html

# Step 2: Check body
curl -sk "https://target/actuator/env" | head -c 200

# Real Actuator → {"propertySources":[{"name":"systemProperties",...
# SPA fallback → <!DOCTYPE html><html...><div id="root">...
```

## Workflow for Web Vulnerability Assessment
1. Enumerate all HTTP 200 paths via dirb/gobuster/nmap
2. For each path, verify Content-Type BEFORE claiming a finding
3. Flag as "UNCONFIRMED" if Content-Type is text/html on non-HTML paths
4. Only promote to "CONFIRMED" when:
   - Content-Type matches expected type, OR
   - Response body has distinctive content (not the standard SPA HTML)

## BFF Proxy返回内容的判断标准

BFF (Backend-For-Frontend) Proxy返回的CMS/广告内容是否算漏洞：
- CMS广告内容（如"/bffportal/proxy/cms/v2/api/datas/query?tag=ads"返回17条营销广告）= **不是漏洞**（公开营销内容，非用户数据）
- 需验证：Content-Type + 返回内容是否包含真实用户信息（姓名/手机/订单/身份证等）
- 营销内容（广告/公告/活动页）= 正常功能
- 用户数据泄露 = 漏洞

## SPA + Swagger API-Docs判断

Vue SPA站点的`/v2/api-docs`、`/swagger-ui.html`等路径：
- 返回HTML（text/html）+ Vue SPA特征内容 = **不是Swagger**，是nginx SPA fallback
- 返回JSON（application/json）+ OpenAPI规范结构 = 真正的Swagger文档
- 即使HTTP状态码是200，也要验证Content-Type

## 专用协议的识别

NTRIP（RTK差分定位）、MQTT等专用协议：
- 端口2101 NTRIP：需要ntripcaller或RTKLIB等专用客户端，curl/scan无法测试
- 端口1883 MQTT：需要mqtt客户端订阅主题，HTTP工具无法测试
- 直接TCP连接超时或协议握手失败 = 正常（协议层需要专用工具）

## Real Assessment Example
```
Path:      /.git/config
Status:    200
Content-Type: text/html  ← SPA fallback, NOT a vulnerability
Body:      <!DOCTYPE html><html lang="en">...<div id="root">...
Result:    ❌ FALSE POSITIVE — nginx SPA fallback
```

```
Path:      /api/user
Status:    200
Content-Type: application/json  ← Real API!
Body:      {"code":-1,"message":"未提供Token"}
Result:    ✅ CONFIRMED — Unauthenticated API endpoint
```
