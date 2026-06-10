# 嘀嗒出行移动端/APK静态线索续测记录（2026-05-22）

适用场景：嘀嗒出行 SRC 在无授权态 Web/Phoenix/Enterprise 接口矩阵已经多轮 401/403/404/空响应后，转向移动端公开包、应用商店线索、移动端 API 边界路径验证。

## 已确认官方移动端包名

公开 App Store / 市场线索确认的官方包名：

- 嘀嗒出行：`com.didapinche.taxi`
- 嘀嗒车主：`com.didapinche.carpooldriver`
- 嘀嗒出租司机：`com.didapinche.taxi.driver`

这些信息只用于移动端攻击面定位，不构成漏洞。

## APK获取经验

公开下载源不稳定，直接从 Web 环境拉包成功率低：

- 应用宝相关页面可能返回 TLS EOF、空响应或连接异常。
- APKPure 直链/搜索可能返回 404、TLS EOF 或超时。
- apkcombo、apk.support、evozi 等公开源可能返回 403/超时/无可用 APK。
- 若本地没有实际 `.apk` 文件，不要声称完成静态反编译，也不要推断存在硬编码 Secret/签名算法。

推荐后续路径：通过手机/模拟器官方渠道安装 App 后导出 APK，再做 jadx/apktool/aapt 离线分析。

## 低影响移动端边界探测结论

常见移动端配置/版本/DeepLink 路径：

- `/api/config`
- `/app/version`
- `/.well-known/assetlinks.json`
- `/apple-app-site-association`
- `/config.json`
- `/api/app/version`

嘀嗒目标中已观察到的误报模式：

- `capis.didapinche.com` 对 `/api/config`、`/app/version`、`/.well-known/assetlinks.json`、`/apple-app-site-association` 返回 APISIX `404 Route Not Found`，不是配置泄露。
- `ten-capis.didapinche.com` 对多个路径返回 `200` 但 `Content-Length=0`、空 body；随机不存在路径同样返回 `200` 空 body，属于网关空响应行为，不是 Swagger/Actuator/API 暴露。
- `open.didachuxing.com` 多路径 TLS EOF/连接关闭，不能当作漏洞证据。
- `www.didachuxing.com`、`www.didapinche.com` 的 assetlinks / apple-app-site-association 返回 404，不是 DeepLink 接管证据。

## 判定门槛

只有满足以下条件之一才继续形成报告链：

1. 成功获取 APK，并从包内提取到可验证的 `baseURL`、签名算法、AppSecret/API Key、证书绑定弱点；
2. 用包内签名/密钥构造请求后，单个低风险接口返回真实业务数据；
3. DeepLink/Universal Link 配置真实暴露且可导致账号接管、Token 泄露或敏感跳转；
4. 合法授权态下证明企业/司机/订单/发票/员工等接口存在 IDOR/越权。

以下不提交：

- 应用包名、版本、开发者名称等公开信息；
- APK 下载失败、TLS EOF、超时、403/404；
- APISIX `404 Route Not Found`；
- `200` 空 body，尤其是随机不存在路径也同样空响应；
- 只发现候选主机/候选路径但无业务数据返回。

## 证据文件命名建议

- `/tmp/dida_src/raw/apk_market_curl_probe.txt`
- `/tmp/dida_src/raw/apk_direct_download_probe.txt`
- `/tmp/dida_src/raw/apk_search_engine_links.txt`
- `/tmp/dida_src/raw/mobile_candidate_hosts.txt`
- `/tmp/dida_src/raw/mobile_candidate_paths.txt`
- `/tmp/dida_src/evidence/mobile_static_fallback_probe_redacted.txt`

报告结论模板：继续移动端/APK公开线索和少量配置路径验证后，未发现硬编码密钥、签名绕过、未授权业务数据或可提交 DeepLink 风险；累计可提交漏洞数为 0，不建议提交。
