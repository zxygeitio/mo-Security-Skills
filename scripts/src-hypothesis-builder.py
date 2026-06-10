#!/usr/bin/env python3
"""Generate human-pentester SRC hypotheses and evidence workspace skeletons.

This gives Hermes more "hands": for a target profile it emits attack hypotheses,
small-batch verification tasks, evidence directories, and commands to feed
src-http-probe.py / src-evidence-gate.py.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

ROLE_BY_HINT = {
    "edu": ["游客", "学生", "教师", "管理员", "供应商", "考生"],
    "education": ["游客", "学生", "教师", "管理员", "供应商", "考生"],
    "ai": ["游客", "普通用户", "组织管理员", "开发者", "平台管理员"],
    "hotel": ["游客", "会员", "门店员工", "加盟商", "管理员"],
    "iot": ["游客", "设备用户", "运维", "经销商", "管理员"],
    "default": ["游客", "注册用户", "普通员工", "管理员", "第三方应用"],
}

COMMON_OBJECTS = ["userId", "studentId", "orderId", "fileId", "resId", "appId", "orgId", "tenantId", "token", "apiKey", "phone", "idcard"]

HYPOTHESES = [
    {
        "id": "H1-auth-boundary",
        "title": "认证边界绕过 / 未授权敏感API",
        "signals": ["/api/", "/user", "/admin", "/info", "/list", "/detail"],
        "tests": [
            "无Cookie/无Authorization访问高价值API，记录状态码、长度、关键字段",
            "使用无效token/随机token对照，确认不是公开设计",
            "对同类公开接口和需登录接口做差异对照",
        ],
        "submit_gate": "必须返回真实敏感业务数据或可执行敏感操作，不接受401/403/登录页/公开配置。",
    },
    {
        "id": "H2-idor-object",
        "title": "IDOR / 对象归属校验缺失",
        "signals": ["id=", "userId", "studentId", "orderId", "fileId", "resId"],
        "tests": [
            "挑选2-5个低影响ID做最小遍历，确认返回对象是否不同",
            "加入不存在ID/随机ID对照，过滤固定响应",
            "如有测试账号，做A/B账号归属对照",
        ],
        "submit_gate": "必须证明跨用户/跨组织/非本人对象可读写。",
    },
    {
        "id": "H3-upload-download",
        "title": "文件上传/下载链路",
        "signals": ["upload", "file", "attachment", "download", "oss", "resId"],
        "tests": [
            "上传无害txt/html/pdf marker，记录fileUrl/resId/genName",
            "访问返回URL，记录Content-Type/Content-Disposition/浏览器处理",
            "测试下载是否只凭fileId/resId，加入随机ID对照",
        ],
        "submit_gate": "必须有公网可访问URL和实际影响；强制下载/不解析则按真实影响降级。",
    },
    {
        "id": "H4-secret-token-chain",
        "title": "前端密钥 / appSecret / API Key 到数据访问链",
        "signals": ["appSecret", "apiKey", "accessToken", "clientSecret", "sign", "signature"],
        "tests": [
            "从JS/配置提取密钥位置和来源，不在报告中明文展示",
            "用最小低影响请求验证密钥是否可换token或调用只读接口",
            "验证密钥是否绑定appId/来源/时间，使用错误密钥对照",
        ],
        "submit_gate": "必须证明密钥仍有效且可访问真实接口，JS存在密钥本身不够。",
    },
    {
        "id": "H5-cors-browser-read",
        "title": "CORS 凭证态敏感读取",
        "signals": ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "cors"],
        "tests": [
            "evil Origin 请求敏感接口，确认ACAO反射和ACC=true",
            "准备浏览器PoC读取响应，截图console/network",
            "无敏感数据接口不作为高危提交",
        ],
        "submit_gate": "必须证明浏览器可读敏感接口。",
    },
    {
        "id": "H6-reset-enum",
        "title": "找回密码/验证码/账号枚举逻辑",
        "signals": ["forgot", "reset", "captcha", "sms", "verify", "check"],
        "tests": [
            "自有账号、随机不存在账号、格式错误账号对照",
            "只做低频一次验证，禁止短信轰炸",
            "记录稳定差异、掩码泄露或真实发送证明",
        ],
        "submit_gate": "必须有稳定差异或真实低频发送/接管链证据。",
    },
    {
        "id": "H7-runtime-browser",
        "title": "浏览器运行态接口/本地状态分析",
        "signals": ["localStorage", "sessionStorage", "webpack", "vite", "next"],
        "tests": [
            "用浏览器打开高价值页面，查看localStorage/sessionStorage/cookie",
            "抓运行态接口顺序：captcha -> token -> login -> userInfo",
            "提取隐藏chunk/sourceMap/import-map/remoteEntry",
        ],
        "submit_gate": "运行态发现必须继续链到未授权、越权、密钥可用或敏感数据。",
    },
]


def infer_domain(target: str) -> str:
    if not re.match(r"https?://", target):
        target = "https://" + target
    return urlparse(target).netloc or target


def roles_for(scope: str):
    s = scope.lower()
    for k, v in ROLE_BY_HINT.items():
        if k in s:
            return v
    return ROLE_BY_HINT["default"]


def render_markdown(target: str, scope: str, outdir: Path) -> str:
    domain = infer_domain(target)
    roles = roles_for(scope + " " + target)
    lines = []
    lines.append(f"# SRC Human Pentester Plan: {domain}\n\n")
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n\n")
    lines.append("## Business model\n")
    lines.append(f"- Target: {target}\n")
    lines.append(f"- Scope/type hint: {scope or 'default'}\n")
    lines.append("- Roles: " + ", ".join(roles) + "\n")
    lines.append("- Core objects: " + ", ".join(COMMON_OBJECTS) + "\n")
    lines.append("- Rule: 每批最多20个请求；每个候选必须归类为可提交/可深挖/负证据/放弃。\n\n")
    lines.append("## Hypotheses\n")
    for h in HYPOTHESES:
        hdir = outdir / h["id"]
        lines.append(f"### {h['id']} {h['title']}\n")
        lines.append("Signals: " + ", ".join(h["signals"]) + "\n\n")
        lines.append("Small-batch tests:\n")
        for t in h["tests"]:
            lines.append(f"- {t}\n")
        lines.append(f"Submit gate: {h['submit_gate']}\n")
        lines.append(f"Evidence dir: {hdir}\n")
        lines.append(f"Gate command: /usr/bin/python3 /root/.hermes/scripts/src-evidence-gate.py {hdir} --out {hdir}/evidence_gate.md\n\n")
    lines.append("## Stop conditions\n")
    lines.append("- 连续20个高价值接口均认证正常/空数据：停止泛测，转向登录态或新业务入口。\n")
    lines.append("- SPA fallback、WAF页、公开文章、WordPress默认公开面、Swagger仅文档暴露：归为负证据。\n")
    lines.append("- 无攻击结果、无对照组、无可复制curl：不写报告。\n")
    return "".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate SRC attack hypotheses and evidence dirs")
    ap.add_argument("target")
    ap.add_argument("--scope", default="", help="target type/scope hint, e.g. education, ai, hotel")
    ap.add_argument("--outdir", default="", help="workspace output dir")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    domain = infer_domain(args.target).replace(":", "_")
    outdir = Path(args.outdir or f"/tmp/src_human_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}").resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    for h in HYPOTHESES:
        hdir = outdir / h["id"]
        hdir.mkdir(parents=True, exist_ok=True)
        (hdir / "README.md").write_text(f"# {h['id']} {h['title']}\n\nSubmit gate: {h['submit_gate']}\n", encoding="utf-8")
        (hdir / "urls.txt").write_text("# one URL per line for src-http-probe.py\n", encoding="utf-8")
        (hdir / "notes.md").write_text("候选归类: 可提交 / 可深挖 / 负证据 / 放弃\n对照组:\n截图位置:\n", encoding="utf-8")
    plan = render_markdown(args.target, args.scope, outdir)
    plan_path = outdir / "human_pentester_plan.md"
    plan_path.write_text(plan, encoding="utf-8")
    result = {"outdir": str(outdir), "plan": str(plan_path), "hypotheses": len(HYPOTHESES)}
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.json else None))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
