# 湖南农业大学 wzhd 问卷系统 CORS 验证记录

## 适用场景
教育 SRC 中验证问卷/活动/开放接口的 CORS 配置不当。该记录作为 `education-src-blueprint` 的案例参考：如何把 CORS 响应头、业务 JSON 字段、截图重点整理成可提交证据。

## 目标与接口
- 目标：湖南农业大学问卷调查系统
- 主域：`wzhd.hunau.edu.cn`
- 验证接口：`https://wzhd.hunau.edu.cn/IGI/open/answer/getSurvey`
- 测试 Origin：`https://evil.example`
- 请求体：`id=82b182fd95f029700197b05849000000&siteId=160`
- 请求头：
  - `Origin: https://evil.example`
  - `formdata: 1`
  - `Content-Type: application/x-www-form-urlencoded`
  - `distributionType: 1`

## 成立证据
响应头同时出现：
- `HTTP/1.1 200`
- `Content-Type: application/json`
- `Access-Control-Allow-Origin: https://evil.example`
- `Access-Control-Allow-Credentials: true`

判定：任意 Origin 反射 + Credentials=true，CORS 配置不当成立。

## 业务 JSON 证据
接口返回可解析 JSON，关键字段包括：
- `statusCode: 200`
- `message: 访问成功`
- `surveyId: 82b182fd95f029700197b05849000000`
- `siteId: 160`
- 问卷标题：关于开展第二轮“献策湘农‘十五五’”金点子征集活动的公告
- `question_count: 6`
- 问卷字段：姓名、联系电话、邮箱、标题、内容

## 边界与不可夸大点
- 不要写 RCE、SQL 注入、后台越权、答卷导出、任意提交有效问卷。
- `/IGI/open/answer/collect` 当前返回“问卷已结束回收”，不能作为任意提交证据。
- `/IGI/survey/getSurveyById` 未登录失败，不能作为后台问卷未授权证据。
- 建议定级：中危或低危偏中；漏洞类型：CORS 配置不当 / 安全配置错误。

## 用户偏好的验证脚本形态
用户在 SRC 复现阶段偏好直接给可运行 Python 脚本路径，而不是长 heredoc 或超长单行命令。脚本应：
1. 打印目标接口、测试 Origin、请求参数。
2. 输出等价 curl 命令，便于报告引用。
3. 保存响应头、响应体、OPTIONS 预检头到 `/tmp/...`。
4. 分区打印“截图重点”：CORS 响应头、`[VULN]` 判定、JSON 业务字段、问卷字段结构。
5. 避免写入目标系统，仅做低影响读取和 OPTIONS 预检。

### 脚本可用性注意点
- 优先使用 `curl` 子进程并设置 `--connect-timeout` 与 `--max-time`，避免 Python `urllib`/长连接在复杂网络环境下卡住。
- 运行命令前加 `LC_ALL=C LANG=C`，避免 Kali/容器未生成 `en_US.UTF-8` 时刷 `setlocale` 警告；locale 警告不是漏洞证据，不要截图。
- 如果后台旧进程输出全是 locale warning，应先忽略/清理旧进程，再在前台执行脚本获取可截图正文。
- 验证脚本必须用分区标题明确标注“CORS 响应头证据”“漏洞判定”“JSON 解析结果”“问卷字段结构”，减少用户截图选择成本。

## 截图建议
- 第一张：同屏包含 `Access-Control-Allow-Origin: https://evil.example`、`Access-Control-Allow-Credentials: true`、`[VULN] CORS 任意 Origin 反射 + Credentials=true 漏洞成立`。
- 第二张：包含 JSON 解析结果和问卷字段结构，尤其是 `statusCode: 200`、问卷标题、`question_count`、姓名/联系电话/邮箱/标题/内容。
- 第三张：OPTIONS 预检响应头作为补充。
