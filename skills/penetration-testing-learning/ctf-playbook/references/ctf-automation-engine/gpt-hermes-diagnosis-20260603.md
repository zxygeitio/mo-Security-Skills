# GPT+Hermes联合诊断报告 — CTF引擎优化路线图

## 10个最高优先级修复
1. 目标规范化 — GUI默认"http://"会破坏nmap/masscan
2. masscan端口解析 — parts[3]是host不是port
3. HTTP返回headers — 指纹识别当前无法获取响应头
4. 结构化输出 — Finding数据类 + JSON事件流
5. 插件架构 — 当前909行单文件，添加新漏洞类型要改5处
6. 补充SSRF/GraphQL/JWT/XXE/重定向/下载穿越
7. 上传利用闭环 — 当前只检测不验证shell执行
8. SQLi提取DBMS感知 — UNION查询对SQLite/PG/MSSQL无效
9. 爬虫+表单解析 — 当前靠硬编码路径/参数
10. 破坏性操作门控 — Redis写webshell应默认关闭

## 缺失漏洞类型 (15种)
JWT(alg:none/弱密钥/kid注入), GraphQL(内省/IDOR), SSRF(云元数据/file协议),
XXE, 反序列化(PHP/Java/Python), 开放重定向, 下载穿越, API批量赋值,
NoSQL注入(Mongo $ne), 竞态条件, CSRF, Host头注入, CRLF注入,
WebSocket探测, 源码泄露利用(.git dump)

## 自动利用缺口
- SQLi POST: 检测到但不自动利用
- SSTI: POST不利用/Freemarker payload错误
- Upload: 不验证shell执行
- CORS: 不测试凭据+敏感端点
- IDOR: 不批量枚举
- Redis: 不按类型dump所有key

## 性能优化
- HTTP连接池(urllib无连接池→考虑requests/httpx)
- 响应缓存(同一URL重复请求)
- 自适应timeout(基线RTT×4)
- 响应标准化(去时间戳/CSRF token再比较)
- 阴性对照(XSS nonce/CMDi nonce/SQLi baseline)

## AWD防御能力
- 文件完整性监控(hash基线+变化检测)
- Webshell扫描器(YARA模式匹配)
- WAF规则生成(nginx deny)
- 流量攻击payload提取
- 自动修补+回滚
- Flag提交客户端
- SLA健康检查
