# 批量教育目标扫描结果 (2026-05-20)

## 扫描目标 (14所学校)

| 学校 | 域名 | IP | HTTP状态 | CMS | 漏洞 |
|------|------|-----|---------|-----|------|
| 湖北大学 | hubu.edu.cn | 202.114.144.124 | 200 | 博达CMS | 无 |
| 六盘水幼儿师范 | lpsyz.cn | 61.189.243.28 | 200 | 博达CMS | 无 |
| 南宁商贸学校 | nnsmxx.com | 211.149.226.66 | 200 | BoCaiCMS | 管理后台暴露 |
| 南京师范大学泰州学院 | nnutc.edu.cn | 58.192.111.139 | 405 | NNUTC CLOUD | WAF拦截 |
| 广西电力职业技术学院 | gxdy.cn | 103.126.210.42 | 200 | - | 域名已出售 |
| 无锡学院 | wxic.edu.cn | 61.177.124.50 | 200 | SUDY CMS | .git被WAF拦截 |
| 湖南交通职业技术学院 | hnjt.edu.cn | 59.51.42.155 | 200 | 自研PHP | 后台无验证码 |
| 湖北水利水电职业技术学院 | hbsy.cn | 61.183.174.52 | 200 | 博达CMS | 无 |

## 不可达目标 (9/14)

- 六盘水师范学院: lpssy.edu.cn 无DNS
- 广西电力职业技术学院: gxdyxy.edu.cn 无DNS
- 合肥一六八中学: hf168.cn 不可达
- 福清一中: fqyz.cn 不可达
- 黄河科技学院: hhstu.edu.cn 无DNS
- 四川乐山一中: lsyz.cn 不可达
- 河南工业大学: haut.edu.cn 无DNS
- 广州卫生职业技术学院: gzwsxy.edu.cn 无DNS
- 武汉体育学院: wipe.edu.cn 无DNS
- 洛阳师范学院: lynu.edu.cn 无DNS
- 山东铝业职业学院: sdlyzyxy.edu.cn 无DNS

## 域名解析成功率

- .edu.cn域名: 约30%外网可达
- .cn域名: 部分可达，但需验证是否为学校网站
- 已售/过期域名: gxdy.cn, hnsw.cn, hbty.cn

## WAF类型汇总

1. **宝塔网站防火墙免费版** - nnsmxx.com
   - 拦截XSS/SQLi
   - 绕过困难

2. **NNUTC CLOUD** - nnutc.edu.cn
   - 所有子域名返回Error页面
   - 无法利用

3. **SUDY CMS WAF** - wxic.edu.cn
   - .git访问被"访问禁止"拦截
   - 事件编号: 202605201410000055

## 建议

1. 确认学校正确域名后重新测试
2. 使用VPN访问CERNET-only目标
3. 优先测试无WAF的自研系统
4. ehall金智教育平台是高价值目标