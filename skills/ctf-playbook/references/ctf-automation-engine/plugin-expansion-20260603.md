# 引擎插件扩展记录 — 2026-06-03

## 新增插件 (v3→v6, 16→29个)

### 高级Web漏洞插件
- **XXEPlugin** — XML外部实体注入。检测API/import/parse/xml/soap端点,发送`<!ENTITY xxe SYSTEM "file:///etc/passwd">`payload,检查`root:`响应。含表单盲XXE。
- **RaceConditionPlugin** — 并发竞态。识别redeem/transfer/vote等端点,10线程并发POST,8/10成功即报。
- **WAFDetectPlugin** — WAF指纹。12种WAF签名(Cloudflare/Akamai/Imperva/SafeLine/ModSecurity等),攻击payload触发403/406/419响应检测。
- **SubdomainEnumPlugin** — 子域名枚举。60+常见前缀DNS爆破(www/mail/ftp/admin/test/dev/api/jenkins/grafana等)。
- **CredentialRelayPlugin** — 凭证复用。从loot/creds.txt读取已发现凭证,尝试9个login端点。
- **SSRFBlindPlugin** — 盲SSRF。Burp Collaborator风格canary探测。
- **IDORAdvancedPlugin** — 高级IDOR。自动识别数字端点(/api/user/N),对比不同ID,敏感字段检测,批量dump。
- **GraphQLAdvancedPlugin** — GraphQL高级。路径探测9个常见路径,内省查询,敏感字段定向查询(flag/secret/admin/password等)。

### 增强插件
- **DeserializationPlugin** 增强 — 新增.NET(`AAEAAAD/////`)和Ruby(`BAhJ`)指纹,增加Cookie检测。
- **NoSQLiPlugin** 增强 — 新增`$regex bypass`。

### 新增服务利用
- **Memcached** — socket直连stats未授权 + stats cachedump + get key + flag搜索
- **Elasticsearch** — /_cat/indices /_search /_nodes /_cluster/health
- **Docker API** — /containers/json /images/json /version /info (2375/2376端口)
- **K8s API** — /api/v1/namespaces /api/v1/secrets /apis /version (6443/10250/10255端口)
- **PostgreSQL** — 3用户×6密码弱口令 + 表枚举

### Flag提取增强
- 正则扩展: `flag|FLAG|ctf|CTF|key|KEY|secret|token` + `{3-80字符}`
- 搜索范围: / /home /var /tmp /opt /root /srv /etc 分区扫描
- 数据库文件: .rdb/.sql/.sqlite 自动搜索
