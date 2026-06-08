# 嘀嗒出行移动端/公开包线索深挖记录

适用场景：`*.didachuxing.com` / `*.didapinche.com` 的 Phoenix/Enterprise 无认证矩阵已进入低收益区，需要转向移动端 App、公开应用商店、APK 反编译、移动端 API 边界验证。

## 低影响流程

1. 被动确认官方应用与包名。
   - iOS App Store 搜索可用于确认开发者、包名、版本和应用分工。
   - 嘀嗒当前已确认的官方包名线索：
     - `com.didapinche.taxi`：嘀嗒出行主 App。
     - `com.didapinche.carpooldriver`：嘀嗒车主。
     - `com.didapinche.taxi.driver`：嘀嗒出租司机。
   - 版本号会变化，只作为当次证据，不要写入长期结论。

2. 获取 Android APK 后再做静态分析。
   - 优先官方/主流应用商店页面；若网页只返回通用页、403、TLS EOF，不要包装成问题。
   - 本机有 `aapt` 时可先读取包名、版本、权限；有 `jadx/apktool` 时再反编译。
   - 重点搜索：`baseURL`、`api`、`capis`、`mapi`、`openapi`、`sign`、`signature`、`appKey`、`appSecret`、`client_secret`、`nonce`、`timestamp`、证书绑定/SSL pinning、网关路径。

3. 只在发现签名算法或密钥后做最小化验证。
   - 先复现算法：参数排序、时间戳/nonce、MD5/SHA/HMAC、Header 名称。
   - 再选择低风险只读接口做一次请求对照。
   - 只有返回真实业务数据、认证绕过、越权、可构造合法签名访问受保护 API，才进入报告链。

## 嘀嗒本轮误报排除规则

- `capis.didapinche.com` 常见 API/Swagger/Actuator 路径返回 APISIX `404 Route Not Found`，表示网关未命中路由，不是接口泄露。
- `ten-capis.didapinche.com` 多路径可返回 `200 text/plain Content-Length: 0`；必须用随机不存在路径对照。若随机路径同样 `200` 且空 body，应判定为空响应/网关行为，不是未授权 API。
- `api.didachuxing.com`、`app.didachuxing.com` 出现 TLS EOF/连接关闭时，只记录为连通性/网关现象，不构成漏洞。
- 应用商店公开包名、版本、开发者名称属于公开信息；没有密钥、签名算法、业务数据访问链路时不提交。

## 证据落盘建议

- `/tmp/<target>/raw/mobile_store_passive.txt`：应用商店被动信息。
- `/tmp/<target>/raw/mobile_market_pages.txt`：APK 市场页面/下载线索。
- `/tmp/<target>/evidence/mobile_api_surface_probe_redacted.txt`：移动端 API 边界低频探测。
- `/tmp/<target>/evidence/ten_capis_empty_200_diff_redacted.txt`：空 200 与随机不存在路径对照。

## 后续高收益方向

1. 合法测试账号下企业/司机/订单/发票/员工 IDOR。
2. 官方 APK 离线反编译后提取签名算法和接口基地址。
3. 包内密钥或签名算法可用时，只做单接口低风险验证。
4. 不要继续重复无认证 Phoenix/Enterprise/capis 通用路径探测；已有充分 401/403/404/空响应对照后收益很低。
