# 嘀嗒出行 Phoenix/Enterprise 定向后台探测核验记录（2026-05-22）

适用场景：对嘀嗒出行 `e.didachuxing.com` Phoenix/SaaS、`b.didachuxing.com` 企业版、`capis.didapinche.com` APISIX 网关做低频 SRC 验证，尤其是用后台进程跑定向接口探测时。

## 关键结论

本轮没有发现可提交漏洞；不要把 403、登录过期、SPA fallback、公开城市配置、验证码前置流程或 JS 残留测试账号包装成报告。

## 后台进程核验纪律

当后台探测进程返回以下状态时，不能只看终端输出下结论：

- `exit code 143`：通常是 SIGTERM/终止。
- `exit code -15`：同样表示 SIGTERM。
- 输出只有 locale/tty/job-control 警告，没有 `DONE` 或 `HIT`。

必须读回落盘文件：

- hits 文件是否存在且非空。
- log 文件是否有真实业务数据，而不是 403/401/登录过期。
- 脚本是否打印 `DONE count hits path`；没有 DONE 时按“未完整完成”处理。

本轮验证样例：

- `/tmp/dida_src/evidence/dida_safe_targeted_hits.txt` 为空。
- `/tmp/dida_src/evidence/dida_safe_targeted_probe.log` 仅有少量采样记录，响应均为：
  - `{"code":403,"message":"非法访问!"}`
  - `登录信息过期，请重新登录`
- `/tmp/dida_src/evidence/dida_e_targeted_log.txt`、`/tmp/dida_src/evidence/dida_e_targeted_hits.txt` 未生成时，说明对应后台脚本没有有效落盘产物。

## 判定规则

命中以下任一情况，不能提交：

1. Phoenix 接口返回 HTTP 200 但 body 是 `code=403` 或 `非法访问`。
2. 伪造 `X-Phoenix-Userkey`、`router-type: cp/ac` 后只返回“登录信息过期，请重新登录”。
3. 企业版 `didaweb_auth.php` 返回 401 登录超时。
4. `localStorage.userKey=222` 只影响前端路由，后端仍 401。
5. `checkCompany` 对真实/随机企业名都返回空成功，不能形成稳定枚举差异。
6. JS 里有测试账号/手机号，但登录链路没有证明可登录或可读业务数据。
7. APISIX 根路径/猜测路径只返回 `404 Route Not Found` 或空响应。

## 推荐下一步

无授权态上下文时，不要继续大量重复无认证接口探测。收益更高的方向：

- 合法测试账号下做企业/司机/订单 IDOR 与越权。
- 移动端 App/小程序包逆向，提取签名算法、AppSecret、接口基地址。
- 合法注册链或短信链路做单次低频验证，严禁批量轰炸。
- 已知 JS/API 清单只作为授权态测试字典，不作为无认证漏洞证据。

## 报告门槛

只有拿到以下证据之一才写报告：

- 未登录可读取真实敏感业务数据。
- 低权限账号可越权读取/修改其他企业、司机、订单数据。
- 泄露密钥能真实调用后端 API 获取数据。
- 上传接口可未授权上传并访问有效攻击演示文件，且不违反厂商禁止行为。
- 认证/验证码/短信链路存在可复现业务绕过或资源滥用，并有低影响实证。
