# Web 游戏类 CTF 解题模式

## 典型结构

Web游戏CTF通常：
- 前端JS实现游戏逻辑（贪吃蛇、2048、flappy bird等）
- 分数/状态存储在客户端变量中
- 游戏结束时通过fetch/XMLHttpRequest将分数POST到后端
- 后端验证分数达标后返回flag

## 解题步骤

1. **查看源码** — 浏览器F12或curl获取HTML，找<script>标签中的游戏逻辑
2. **定位提交函数** — 搜索 `fetch`、`XMLHttpRequest`、`FormData`、`checkWin`、`submit` 等关键词
3. **分析验证逻辑** — 确认服务端是否只验证score值，还是有额外校验（签名/token/时间戳）
4. **伪造提交** — 两种方式：
   - 浏览器Console直接调用提交函数：`checkWin(300)`
   - curl直接POST：`curl -X POST 'URL' -F 'score=300'`

## 常见绕过点

- 修改客户端变量：`score = 300; checkWin(score);`
- 拦截fetch重写：`window.fetch = ...` 可以观察请求/响应
- 直接curl：脱离浏览器环境，注意Cookie/Session
- 游戏速度修改：`setInterval(draw, 10)` 加速游戏循环

## Flag格式调试

当服务器返回的flag在竞赛平台被拒绝时，按以下顺序排查：

1. **检查多余字符** — 去掉空格/换行/BOM
2. **尝试不同wrapper** — `flag{...}` / `FLAG{...}` / `{...}` / 无wrapper
3. **尝试方括号** — `flag[...]` 有些平台用方括号
4. **只提交hash** — 去掉 `flag{}` 只提交内部内容
5. **检查是否需要解码** — flag可能是base64/hex编码的，需要先解码
6. **确认平台要求** — 查看竞赛平台的提交说明/格式要求
7. **MD5哈希提示** — 32位hex字符串通常是MD5，flag可能需要crack后的明文

## 参考案例：贪吃蛇游戏 (御网杯2026)

- 靶机：120.27.146.76:22226
- 技术栈：PHP 7.4.33 + Apache 2.4.54
- 漏洞：客户端score POST无签名校验
- POC：`curl -X POST 'http://120.27.146.76:22226/index.php' -F 'score=300'`
- 服务器返回：`flag{5cf1ef3539860b778211db423b4f6558}`
- 注意：MD5哈希可能需要crack才能得到平台接受的答案
