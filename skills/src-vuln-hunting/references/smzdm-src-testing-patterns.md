# 值得买 SRC 测试模式记录（2026-05-31）

适用范围：`*.smzdm.com`、`*.zhidemai.com`、`*.zdm.net`、`matrix.datazhi.com`。

## 已验证资产与入口

- 子域收集约 153 个，HTTP 可达约 128 个；大量 `*-api.smzdm.com` 根路径统一返回：
  `{"error_code": -1,"error_msg": "Sign param not enough","smzdm_id": "0","s": "","data": []}`。
- 钱包/提现 H5：`qianbao.smzdm.com`，前端 JS 暴露接口清单：
  - `/v1/app/myBalance`
  - `/v1/app/bankcardList`
  - `/v1/app/getWithdrawPageInfo`
  - `/v1/app/withdrawContractList`
  - `/v1/app/orders`
  - `/v1/app/invoice/history`
  - `/v1/app/checkPWD`
  - `/v1/app/mobileSend`
  - `/v1/app/bind/account`
  - `/v1/app/geetestResponse`
- 身份认证 H5：`zhiyou.m.smzdm.com/user/identity/*`，JS 暴露：
  - `/user/identity/ajax_get_identity_info_new`
  - `/user/identity/ajax_check_identity_new`
  - `/user/identity/ajax_send_identity_captcha_new`
  - `/user/identity/ajax_ocr`
  - `/user/identity/ajax_back`
  - `/user/identity/ajax_cancel`
  - `/user/identity/ajax_contry_auth`
- Agent/AI 站：`agent.smzdm.com`，SPA fallback 明显，路径如 `/auth/third-party/yuanbao`、`/protocol/user/v1` 返回同一前端壳，不能直接当 API 命中。
- 补充域名：`matrix.datazhi.com` 全站 Basic Auth，realm 为 `aiv`；常见路径仍 401，未发现绕过。
- 邮箱：`zmail.smzdm.com/webmail/` 暴露 Roundcube/Apache/PHP 老组件指纹，但 README/CHANGELOG/config/logs/installer 未泄露。

## 关键验证结论

- API 签名绕过未成功：Android UA、Referer/Origin、`f=android`、`v=10.8.0`、`device_id`、`smzdm_id=0`、公开接口返回的 `s` 值、空 `s` 等组合仍返回 `Sign param not enough`。
- 钱包敏感接口未授权访问均被拦截，典型返回：
  `{"error_code":4,"error_msg":"还未登录!","data":null,"success":false,"fail":true}`。
- 公开接口 `/v1/app/geetestResponse` 只返回极验初始化参数；`/v1/app/withdrawLimitTips` 只返回提现规则，不构成漏洞。
- `api.smzdm.com/v1/weixin/getSignPackage` 存在 `Access-Control-Allow-Origin: *`，但返回微信 JS-SDK 签名包，未含用户敏感数据，且无 credentials 放大证据；不建议按 CORS 提交。
- `static.smzdm.com/obj/h5/mobile_shequ_ssr/app.e1c0582.js.map` 可访问 SourceMap，可提取约 2.97MB 源码和内部服务名：
  - `http://article-service.smzdm.com:809/`
  - `http://go-user-service.smzdm.com:8109/user/current_user_v1`
  但未发现 AppSecret/API Key/签名密钥，公网替换验证也未返回敏感数据。单独 SourceMap 暴露不满足用户“只报实质漏洞”标准。
- `/push` 与 `/app_download/to` 易返回 WAF challenge/空壳页；未拿到 APK 直链时，不要把 challenge 当漏洞。

## 后续有效路线

1. 优先从 Android APK 第三方渠道/应用市场下载真实安装包，逆向 native/Java 层签名算法，而不是继续猜测 `s` 参数。
2. 找到签名算法后再批量测 `*-api.smzdm.com` 用户、钱包、订单、发票、身份认证接口。
3. 若只有 SourceMap、老组件指纹、公开业务规则、WAF challenge、签名缺失提示，结论应为“不建议提交”。

## 报告门槛

仅在以下任一条件成立时进入报告：

- 成功构造 API 签名并读取未授权敏感数据。
- 钱包/身份/订单/发票接口出现未授权或越权数据。
- zmail/Roundcube 验证到配置泄露、RCE、账号枚举或认证绕过。
- matrix.datazhi.com Basic Auth 有明确绕过或未授权后台数据。

否则不要输出报告，避免把弱信息泄露或公开配置包装成漏洞。
