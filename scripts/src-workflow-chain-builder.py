#!/usr/bin/env python3
"""Generate workflow-chain testing templates for SRC logic vulnerabilities.

The output is an evidence workspace skeleton for multi-step business logic
chains (reset password, registration/SMS, upload/download, OAuth/SSO,
export/download, order/payment). It is intentionally non-invasive: it plans and
structures evidence collection; Hermes still performs safe manual verification.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

CHAINS = {
    "reset-password": {
        "title": "找回密码/账号恢复链",
        "steps": ["identify_account", "send_code_or_question", "verify_code_or_answer", "reset_password", "login_with_new_state"],
        "controls": ["random nonexistent account", "wrong captcha/code", "missing prior session", "different account same flow"],
        "submit_gate": "必须证明稳定账号枚举、任意验证码发送、前序状态绕过或账号接管；标准错误/验证码拦截不提交。",
        "keywords": ["forgot", "forget", "reset", "password", "pwd", "captcha", "sms", "verify", "question"],
    },
    "register-sms": {
        "title": "注册/短信/邮箱验证码链",
        "steps": ["check_phone_or_email", "send_sms_or_email", "verify_code", "submit_register", "read_profile"],
        "controls": ["invalid phone/email", "same target repeated low-frequency", "wrong code", "missing session/state"],
        "submit_gate": "必须证明未授权短信/邮件可发送、验证码绕过、注册认证绕过或敏感回显；不做轰炸。",
        "keywords": ["register", "signup", "sms", "email", "send", "verify", "code", "phone"],
    },
    "upload-download": {
        "title": "文件上传/下载链",
        "steps": ["get_upload_token_or_policy", "upload_harmless_marker", "obtain_file_id_or_url", "download_or_preview", "delete_or_access_control_check"],
        "controls": ["no token upload", "invalid token", "random fileId/resId", "different content-type marker"],
        "submit_gate": "必须证明未授权上传/可访问URL/下载越权/浏览器处理影响；强制下载或普通存储按真实影响降级。",
        "keywords": ["upload", "file", "attachment", "oss", "policy", "signature", "download", "preview", "resId", "fileId"],
    },
    "export-download": {
        "title": "查询/导出/下载链",
        "steps": ["query_list", "create_export_task", "poll_export_status", "download_export_file", "object_or_tenant_control"],
        "controls": ["no token", "invalid token", "random taskId", "different user/tenant id", "empty filter vs scoped filter"],
        "submit_gate": "必须证明越权导出、未授权下载或跨租户/跨用户数据；仅空文件/公开列表不提交。",
        "keywords": ["export", "download", "task", "excel", "xlsx", "csv", "report", "list", "page", "tenantId", "userId"],
    },
    "oauth-sso": {
        "title": "OAuth/SSO/CAS链",
        "steps": ["authorize_or_login_entry", "redirect_uri_check", "code_or_ticket_issue", "token_exchange_or_service_validate", "userinfo_or_callback"],
        "controls": ["unregistered redirect_uri", "evil domain", "state mismatch", "reused code/ticket", "wrong client_id"],
        "submit_gate": "必须证明开放重定向可劫持授权、ticket/code/token可滥用或用户信息可读；标准CAS错误不提交。",
        "keywords": ["oauth", "sso", "cas", "authorize", "redirect_uri", "callback", "ticket", "code", "client_id", "token"],
    },
    "order-payment": {
        "title": "订单/支付/退款链",
        "steps": ["create_order", "read_order_detail", "change_amount_or_owner", "pay_or_callback", "refund_or_status_change"],
        "controls": ["random orderId", "different userId", "tampered amount/status", "invalid callback sign"],
        "submit_gate": "必须证明订单越权、金额/状态篡改、回调验签缺失或退款滥用；只返回错误不提交。",
        "keywords": ["order", "pay", "payment", "refund", "invoice", "amount", "price", "callback", "trade", "status"],
    },
}


def slug_target(target: str) -> str:
    raw = target
    if not re.match(r"https?://", raw):
        raw = "https://" + raw
    p = urlparse(raw)
    s = p.netloc or target
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)[:80] or "target"


def render_chain(chain_id: str, chain: dict, target: str, cdir: Path) -> str:
    lines = []
    lines.append(f"# Workflow Chain: {chain_id} {chain['title']}\n\n")
    lines.append(f"Target: {target}\n")
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n\n")
    lines.append("## Steps\n")
    for i, step in enumerate(chain["steps"], 1):
        lines.append(f"{i}. {step}\n")
        lines.append(f"   - request: requests/{i:02d}-{step}.req.txt\n")
        lines.append(f"   - response headers/body: responses/{i:02d}-{step}.headers / responses/{i:02d}-{step}.body\n")
        lines.append(f"   - curl: curls/{i:02d}-{step}.sh\n")
    lines.append("\n## Required controls\n")
    for ctrl in chain["controls"]:
        lines.append(f"- {ctrl}\n")
    lines.append("\n## Submit gate\n")
    lines.append(chain["submit_gate"] + "\n\n")
    lines.append("## Evidence commands\n")
    lines.append(f"/usr/bin/python3 /root/.hermes/scripts/src-evidence-gate.py {cdir} --out {cdir}/evidence_gate.md\n")
    lines.append("\n## Notes\n")
    lines.append("- 只做低影响验证；禁止爆破、短信轰炸、破坏性写入和真实支付/退款。\n")
    lines.append("- 每一步必须包含正向请求、失败对照、响应体/头和单行curl。\n")
    lines.append("- 任一链路只有错误页/登录页/WAF/空数据时归档为负证据，不写报告。\n")
    return "".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Create workflow-chain evidence templates")
    ap.add_argument("target")
    ap.add_argument("--outdir", default="")
    ap.add_argument("--chains", default="all", help="Comma-separated chain ids or all")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    selected = list(CHAINS) if args.chains == "all" else [x.strip() for x in args.chains.split(",") if x.strip()]
    unknown = [x for x in selected if x not in CHAINS]
    if unknown:
        raise SystemExit("unknown chain(s): " + ",".join(unknown) + "; known=" + ",".join(CHAINS))

    root = Path(args.outdir or f"/tmp/src-workflow-chains-{slug_target(args.target)}-{datetime.now().strftime('%Y%m%d_%H%M%S')}").resolve()
    root.mkdir(parents=True, exist_ok=True)
    manifest = {"target": args.target, "root": str(root), "chains": []}
    for cid in selected:
        chain = CHAINS[cid]
        cdir = root / cid
        for sub in ["requests", "responses", "controls", "curls", "screenshots", "notes"]:
            (cdir / sub).mkdir(parents=True, exist_ok=True)
        (cdir / "README.md").write_text(render_chain(cid, chain, args.target, cdir), encoding="utf-8")
        (cdir / "notes" / "classification.md").write_text("候选归类: 可提交 / 可深挖 / 负证据 / 放弃\n截图位置:\n对照组:\n敏感数据/攻击结果:\n", encoding="utf-8")
        (cdir / "controls" / "README.md").write_text("放置随机ID、无效token、未登录、错误验证码、不同用户/租户等对照证据。\n", encoding="utf-8")
        manifest["chains"].append({"id": cid, "title": chain["title"], "dir": str(cdir), "keywords": chain["keywords"], "submit_gate": chain["submit_gate"]})
    (root / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    index = ["# SRC Workflow Chains\n\n", f"Target: {args.target}\n\n"]
    for ch in manifest["chains"]:
        index.append(f"- {ch['id']} {ch['title']} -> {ch['dir']}\n")
    (root / "README.md").write_text("".join(index), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2 if args.json else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
