# 批量教育目标扫描流程

## 扫描流程

### Phase 1: 域名解析 (2分钟)
```bash
# 标准域名
for domain in xxx.edu.cn; do
  ip=$(dig +short $domain A | grep -E '^[0-9]' | head -1)
  [ -n "$ip" ] && echo "$domain -> $ip"
done

# 域名变体(学校缩写)
for ext in .edu.cn .cn .com; do
  dig +short "${school}${ext}" A
done
```

### Phase 2: 可达性预检 (1分钟/目标)
```bash
code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "https://$domain/")
# HTTP 000 = 不可达, 跳过
# HTTP 200 = 可用, 继续
# HTTP 403/405 = 部分可用, 尝试子域名
# HTTP 301/302 = 重定向, 跟踪
```

### Phase 3: 子域名枚举 (3分钟/目标)
```bash
for sub in www mail oa vpn ehall cas sso jwxt lib webvpn news auth idp api portal; do
  ip=$(dig +short ${sub}.${domain} A | grep -E '^[0-9]' | head -1)
  [ -n "$ip" ] && echo "${sub}.${domain} -> $ip"
done
```

### Phase 4: CMS指纹 (1分钟/目标)
```bash
curl -sk "https://$domain/" | grep -iE 'generator|cms|powered|sudy|博达|visual|sitebuilder|seeyon|bocai|金智'
```

### Phase 5: 敏感路径扫描 (2分钟/目标)
```bash
for path in /robots.txt /.git/config /.svn/entries /actuator /actuator/env /swagger-ui.html /admin.php /admin /login; do
  code=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "https://$domain${path}")
  [ "$code" != "000" ] && [ "$code" != "404" ] && echo "[${code}] ${path}"
done
```

## 常见失败模式
1. **CERNET-only**: DNS解析成功但HTTP不可达 → 跳过
2. **域名已售**: 标题含"出售" → 跳过
3. **SPA Fallback**: 所有路径返回200同一页面 → 测试API路由
4. **WAF拦截**: 宝塔/云锁/360 → 降低请求频率
5. **DNS超时**: 192.168.x.x内部DNS → 换DNS服务器测试

## 已知高价值目标模式
- ehall + 金智教育 → 测试 /jsonp/ API
- 致远OA → /seeyon/management/index.jsp
- SUDY CMS → 搜索API
- BoCaiCMS → /admin.php
- Spring Boot → /actuator
