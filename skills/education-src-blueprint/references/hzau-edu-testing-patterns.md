# 华中农业大学 hzau.edu.cn 测试记录 (2026-05-28)

## 资产概况
- 32个子域名, 全部211.69.x.x CERNET段
- 12个HTTP可达: www/ehall/portal/vpn/my/idp/zs/yjs/lib/mail/news/cas
- 技术栈: VSB CMS + nginx/1.27.0 + Coremail + 金智教育ehall + WebberRASP
- DMARC/DKIM缺失, SPF -all (hard fail)

## 确认漏洞

### VSB CMS getSession.jsp 未授权会话获取 (中危)
- 影响: www/my/zs/yjs 共4个子站
- 每次请求返回唯一32位JSESSIONID
- getToken.jsp返回"preview"(CMS预览模式)
- 报告: /tmp/vuln_reports/hzau/hzau-vsb-getsession-jsessionid-leak.txt

复现:
```bash
curl -sk 'https://www.hzau.edu.cn/system/resource/getSession.jsp?r=0.1'
curl -sk 'https://my.hzau.edu.cn/system/resource/getSession.jsp?r=0.1'
curl -sk 'https://zs.hzau.edu.cn/system/resource/getSession.jsp?r=0.1'
curl -sk 'https://yjs.hzau.edu.cn/system/resource/getSession.jsp?r=0.1'
```

## 负证据

### ehall SPA版本
- 所有/jsonp/*.json路径返回SPA HTML壳(~7KB), 旧JSONP API不存在
- actuator/swagger/druid返回403(WAF拦截)
- 结论: 金智教育JSONP测试不适用

### WebberRASP拦截
- news.hzau.edu.cn的getSession.jsp被RASP拦截
- 拦截页: "您的访问请求可能对网站造成安全威胁"
- 特征: `X-Protected-By: WebberRASP` header, event_id + TYPE: A in HTML comments
- 其他子站(www/my/zs/yjs)同一接口未被拦截 → RASP规则按子站独立配置

### CSP泄露内部服务 (低价值)
- portal CSP头泄露: portal-minio.hzau.edu.cn, leoagent.hzau.edu.cn(含token), agentest.hzau.edu.cn, 211.69.128.148:8080, 211.69.128.144:8000
- portal-minio/leoagent均403, 内网IP不可达

### Coremail
- mail.hzau.edu.cn所有端点403

### CAS/SSO
- cas.hzau.edu.cn所有路径403
- sso.hzau.edu.cn不可达(超时)

### DMARC/DKIM
- DMARC缺失 + DKIM缺失 + SPF -all
- 不单独提交(教育SRC不收纯配置缺陷)
