#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Hermes on-demand vulnerability intelligence query.

Usage:
  hermes-vuln-query.sh [options] [keyword/product/CVE...]

Examples:
  hermes-vuln-query.sh --keyword "spring boot" --days 30 --github-limit 10
  hermes-vuln-query.sh "CVE-2021-44228"
  hermes-vuln-query.sh --local "nginx"
  hermes-vuln-query.sh --refresh --keyword "wordpress plugin" --min-score 40

Options:
  --keyword TEXT       Product/keyword or CVE to search. Positional terms are joined if omitted.
  --days N            NVD recent window for refresh mode (default: 14).
  --github-limit N    GitHub PoC CVE lookup cap for refresh mode (default: 10).
  --min-score N       Minimum score when regenerating local latest.md (default: 35).
  --refresh           Refresh local cache first, then query it.
  --local             Query only existing local SQLite cache (default unless --refresh).
  --limit N           Rows to print from local query (default: 20).
  --json              Output JSON rows from local query.
  -h, --help          Show help.

Policy:
  No scheduled fetch. Run on demand when a target fingerprint/product/CVE matters.
EOF
}

keyword=""
days=14
github_limit=10
min_score=35
refresh=0
limit=20
json=0
pos=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keyword|-k) keyword="${2:-}"; shift 2 ;;
    --days) days="${2:-14}"; shift 2 ;;
    --github-limit) github_limit="${2:-10}"; shift 2 ;;
    --min-score) min_score="${2:-35}"; shift 2 ;;
    --refresh) refresh=1; shift ;;
    --local) refresh=0; shift ;;
    --limit) limit="${2:-20}"; shift 2 ;;
    --json) json=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; pos+=("$@"); break ;;
    *) pos+=("$1"); shift ;;
  esac
done

if [[ -z "$keyword" && ${#pos[@]} -gt 0 ]]; then
  keyword="${pos[*]}"
fi
if [[ -z "$keyword" ]]; then
  usage >&2
  exit 2
fi

UPDATER="/root/.hermes/scripts/update-vuln-intel.py"
DB="/root/.hermes/vuln-intel/vuln_intel.db"
PY="/root/.hermes/hermes-agent/venv/bin/python"
[[ -x "$PY" ]] || PY="/usr/bin/python3"

if [[ "$refresh" == "1" ]]; then
  "$UPDATER" --days "$days" --github-limit "$github_limit" --min-score "$min_score" --quiet
fi

"$PY" - "$keyword" "$limit" "$json" "$DB" <<'PY'
import json, sqlite3, sys
from pathlib import Path
kw=sys.argv[1].strip()
limit=int(sys.argv[2])
as_json=sys.argv[3]=='1'
db=Path(sys.argv[4])
if not db.exists():
    print(f"local vuln DB missing: {db}; rerun with --refresh", file=sys.stderr)
    sys.exit(1)
con=sqlite3.connect(str(db))
con.row_factory=sqlite3.Row
like=f"%{kw.lower()}%"
rows=[]
if kw.upper().startswith('CVE-'):
    cur=con.execute('''
      select cve_id,published,cvss,severity,score,products,description,exploit_refs_json,references_json,tags
      from cves where upper(cve_id)=upper(?)
      order by score desc limit ?
    ''',(kw,limit))
else:
    cur=con.execute('''
      select cve_id,published,cvss,severity,score,products,description,exploit_refs_json,references_json,tags
      from cves
      where lower(description) like ? or lower(products) like ? or lower(cve_id) like ?
      order by score desc, cvss desc, published desc
      limit ?
    ''',(like,like,like,limit))
rows=[dict(r) for r in cur]
# attach local poc_refs table results
for r in rows:
    refs=[]
    try:
        refs=json.loads(r.get('exploit_refs_json') or '[]')
    except Exception:
        refs=[]
    poc=list(con.execute('select source,title,url,stars,updated_at from poc_refs where cve_id=? order by stars desc limit 5',(r['cve_id'],)))
    r['local_poc_refs']=[dict(x) for x in poc]
    r['exploit_refs'] = refs[:5]
con.close()
if as_json:
    print(json.dumps(rows,ensure_ascii=False,indent=2))
else:
    print(f"Query: {kw} | rows: {len(rows)} | db: {db}")
    for i,r in enumerate(rows,1):
        print(f"\n[{i}] {r['cve_id']} | CVSS:{r.get('cvss')} | {r.get('severity') or ''} | score:{r.get('score')} | published:{(r.get('published') or '')[:10]}")
        if r.get('products'):
            print(f"products: {r['products']}")
        desc=(r.get('description') or '').replace('\n',' ')
        print('desc:', desc[:500])
        refs=r.get('exploit_refs') or []
        poc=r.get('local_poc_refs') or []
        if refs:
            print('refs:')
            for x in refs[:3]:
                if isinstance(x,dict):
                    print(' -', x.get('url') or x)
                else:
                    print(' -', x)
        if poc:
            print('github_poc:')
            for x in poc[:3]:
                print(f" - ⭐{x.get('stars')} {x.get('title')} {x.get('url')}")
PY
