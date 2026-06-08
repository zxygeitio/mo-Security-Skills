# 邮件安全审计 (Email Security Audit)

## 适用场景
教育/企业SRC目标外网不可达时, 邮件系统往往是唯一可访问的攻击面.
特别适用于CERNET-only的高校目标.

## 快速检查流程 (2分钟)

```bash
# 1. DMARC检查 - 缺失=邮件伪造(高危)
dig +short _dmarc.target.edu.cn TXT

# 2. SPF检查 - ~all(softfail)比-all(hardfail)弱
dig +short target.edu.cn TXT | grep -i spf

# 3. DKIM selector枚举
for sel in default s1 s2 google k1 k2 selector1 selector2 mail dkim dkim1; do
    result=$(dig +short "$sel._domainkey.target.edu.cn" TXT 2>/dev/null)
    [ -n "$result" ] && echo "$sel -> $result"
done

# 4. MX记录确认邮件服务商
dig +short target.edu.cn MX
```

## 漏洞判定标准

### DMARC缺失 (高危, CVSS 7.5)
- 无DMARC记录: `dig +short _dmarc.xxx TXT` 返回空
- 可伪造任意@xxx.edu.cn发件人发送钓鱼邮件
- 接收方(QQ/Gmail/Outlook)不会拒绝伪造邮件
- 教育机构学生信任校方邮件, 钓鱼成功率极高

### SPF softfail (中危)
- `~all` = 非授权服务器邮件标记为"可疑"但不拒绝
- `-all` = 非授权服务器邮件直接拒绝(正确配置)
- `+all` = 所有服务器都允许发邮件(极罕见, 严重)

### DKIM缺失 (中危)
- 无法验证邮件完整性和发件人真实性
- 配合DMARC缺失, 攻击者可发送完全无法验证的伪造邮件

## 常见邮件服务商指纹

| MX记录 | 服务商 | 特点 |
|--------|--------|------|
| mxbiz1.qq.com / mxbiz2.qq.com | 腾讯企业邮箱(Exmail) | CSP严格, 无SMTP开放中继 |
| mx*.qq.com | QQ邮箱 | 同上 |
| *.icoremail.net | Coremail | 常见于高校, 可能有旧版本漏洞 |
| *.mail.edu.cn | 教育邮件网关 | CERNET提供, 可能有独立漏洞 |
| *.hichina.com | 阿里云企业邮箱 | |
| smtp.exmail.qq.com | 腾讯Exmail SMTP | 端口465(SSL)/587(STARTTLS), 需认证 |

## QQ Exmail (腾讯企业邮箱) 账号枚举

```bash
# 数字学号账号 vs 字母账号 响应大小差异明显
curl -sk "https://mail.target.edu.cn/cgi-bin/login" \
    -d "uin=admin&domain=target.edu.cn&pp=wrong&f=mail_html" \
    -H "Content-Type: application/x-www-form-urlencoded" | wc -c
# 字母账号: ~8400字节
# 数字学号: ~4000字节
# 不存在:  ~8440字节

# 无验证码保护 - 可暴力破解
for i in $(seq 1 20); do
    curl -sk "https://mail.target.edu.cn/cgi-bin/login" \
        -d "uin=admin&domain=target.edu.cn&pp=test$i&f=mail_html" \
        -H "Content-Type: application/x-www-form-urlencoded" | wc -c
done
# 每次均正常返回, 无验证码拦截
```

## Exmail已知路径

```bash
/cgi-bin/login          # 登录接口(POST)
/cgi-bin/folderlist     # 文件夹列表(需登录)
/cgi-bin/readtemplate   # 模板读取
```

## 报告模板 (DMARC缺失)

```
标题: [学校名]邮件系统存在DMARC缺失漏洞可伪造校方邮件进行钓鱼攻击

域名: [target.edu.cn]

漏洞类型: 邮件安全配置缺陷

漏洞等级: 高危

复现步骤:
1. dig +short _dmarc.target.edu.cn TXT → (无输出)
2. dig +short target.edu.cn TXT → "v=spf1 include:spf.mail.qq.com ~all"
3. 攻击者使用自己SMTP服务器伪造 jwc@target.edu.cn 发送钓鱼邮件
4. 接收方无DMARC策略可依据, 邮件不会被拒绝

影响: 可伪造教务处/财务处/网络中心发送钓鱼邮件, 针对学生教职工

修复建议:
1. 配置DMARC: _dmarc.target.edu.cn TXT "v=DMARC1; p=reject; rua=mailto:dmarc@target.edu.cn"
2. SPF改为-all: "v=spf1 include:spf.mail.qq.com -all"
3. 开启DKIM签名
```

## 注意事项
- DMARC缺失是**DNS配置漏洞**, 不需要登录任何系统即可验证
- SPF ~all vs -all 差异在很多高校都存在, 是批量挖洞的好方向
- 教育网目标优先检查邮件安全, 因为邮件系统通常托管在公有云(腾讯/阿里)
- 补天/漏洞盒子对DMARC缺失的评级通常是中危到高危
