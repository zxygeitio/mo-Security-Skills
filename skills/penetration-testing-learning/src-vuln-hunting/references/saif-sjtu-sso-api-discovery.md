# SAIF SJTU SSO API Discovery

**Forwarding:** 完整内容见 `education-src-blueprint` skill 的 `references/saif-sjtu-sso-api-discovery.md`。

## 核心模式（简要）

- **SAIF SSO**: 上海交通大学上海高级金融学院SSO系统
- **API发现**: CAS/SAML/OAuth端点枚举
- **用户信息泄露**: `/api/user/info` 或 `/api/student/detail`
- **Token绕过**: JWT未验证签名/弱密钥

## 测试命令

```bash
# SSO端点枚举
curl -s "https://sso.saif.sjtu.edu.cn/.well-known/openid-configuration"
curl -s "https://sso.saif.sjtu.edu.cn/cas/protocol/openid-connect"
```
