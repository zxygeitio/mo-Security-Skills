#!/usr/bin/env python3
"""Gate a plain-text SRC report against the user's submission format preferences.

This is an offline format/quality checker, not a vulnerability validator.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REQUIRED_FIELDS = ['标题', '域名', '类型', '等级', '行业', '地址', 'URL', '详情', '复现', '影响', '修复']
CURL_RE = re.compile(r'curl\s+(?:-[^\n]*\s+)*["\']?https?://', re.I)
SCREENSHOT_RE = re.compile(r'【截图位置\d+】')
HTML_RE = re.compile(r'<(?:html|body|p|br|div|span|h[1-6])\b|</(?:p|div|span|h[1-6])>', re.I)
VAGUE_RE = re.compile(r'疑似|可能存在|建议排查|未验证|无法确认|理论上|看起来', re.I)
WEAK_ONLY_RE = re.compile(r'WAF|403|404|SPA fallback|登录页|未登录|Token失效|连接失败|超时|空响应', re.I)


def split_reports(text: str) -> list[str]:
    parts = [p.strip() for p in re.split(r'\n={3,}\n', text) if p.strip()]
    return parts or [text.strip()]


def field_present(report: str, field: str) -> bool:
    return bool(re.search(rf'(^|\n)\s*(?:【)?{re.escape(field)}(?:】)?\s*[:：]', report))


def assess_report(report: str) -> dict:
    missing = [f for f in REQUIRED_FIELDS if not field_present(report, f)]
    warnings = []
    failures = []
    if missing:
        failures.append('missing_fields:' + ','.join(missing))
    if not CURL_RE.search(report):
        failures.append('missing_single_line_curl')
    if not SCREENSHOT_RE.search(report):
        warnings.append('missing_screenshot_position_marker')
    if HTML_RE.search(report):
        failures.append('contains_html_markup')
    if VAGUE_RE.search(report):
        warnings.append('contains_vague_unverified_wording')
    weak_hits = WEAK_ONLY_RE.findall(report)
    if weak_hits and not re.search(r'未授权|越权|敏感|数据|RCE|SQL|上传成功|fileUrl|resId|身份证|手机号|token|AppSecret|secret', report, re.I):
        failures.append('weak_or_negative_evidence_only')
    if '复现命令汇总' not in report:
        warnings.append('missing_reproduction_command_summary')
    if re.search(r'地址\s*[:：]\s*[^\n]*(省|市)\s*$', report):
        warnings.append('address_may_not_be_district_level')
    return {'missing': missing, 'warnings': warnings, 'failures': failures, 'status': 'PASS' if not failures else 'FAIL'}


def main() -> int:
    ap = argparse.ArgumentParser(description='Check SRC report text format before submission')
    ap.add_argument('report')
    ap.add_argument('--json-out', default='')
    args = ap.parse_args()
    path = Path(args.report)
    text = path.read_text(encoding='utf-8', errors='replace')
    reports = split_reports(text)
    results = []
    for i, report in enumerate(reports, 1):
        r = assess_report(report)
        r['index'] = i
        results.append(r)
    overall = 'PASS' if all(r['status'] == 'PASS' for r in results) else 'FAIL'
    payload = {'success': overall == 'PASS', 'overall': overall, 'report_count': len(results), 'results': results}
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(payload, ensure_ascii=False))
    return 0 if overall == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
