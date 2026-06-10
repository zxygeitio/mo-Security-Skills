#!/usr/bin/env python
"""Convert accepted Chain Workspace findings into copyable SRC report text."""
from __future__ import annotations
import argparse, json
from pathlib import Path

def load_jsonl(p: Path):
    if not p.exists(): return []
    out=[]
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.strip():
            try: out.append(json.loads(line))
            except Exception: pass
    return out

def val(x):
    if isinstance(x, (dict,list)): return json.dumps(x, ensure_ascii=False)
    return str(x or "")

def main():
    ap=argparse.ArgumentParser(description="Generate plain text SRC report from Chain Workspace")
    ap.add_argument("workspace")
    ap.add_argument("--out", default="")
    args=ap.parse_args()
    ws=Path(args.workspace).expanduser().resolve()
    scope=json.loads((ws/"scope.json").read_text(encoding="utf-8")) if (ws/"scope.json").exists() else {}
    findings=[f for f in load_jsonl(ws/"findings.jsonl") if f.get("status","") not in ["reject","rejected"]]
    evidence=load_jsonl(ws/"evidence.jsonl")
    validations=load_jsonl(ws/"validations.jsonl")
    parts=[]
    for idx,f in enumerate(findings,1):
        parent=f.get("parent") or f.get("id")
        ev=[e for e in evidence if e.get("parent")==parent or e.get("url")==f.get("url")]
        va=[v for v in validations if v.get("parent")==parent or v.get("url")==f.get("url")]
        data=f.get("data",{}) if isinstance(f.get("data"),dict) else {}
        curl=data.get("curl") or data.get("poc") or "见复现步骤，使用最小化安全 PoC 验证"
        parts.append("\n".join([
            f"标题：{f.get('title') or '授权范围内实质漏洞验证'}",
            f"域名：{scope.get('target','')}",
            f"类型：{data.get('type') or ','.join(f.get('tags',[])) or '业务逻辑/授权缺陷'}",
            f"等级：{f.get('severity') or data.get('severity') or '待平台评估'}",
            f"行业：{data.get('industry') or '按平台目标分类填写'}",
            f"精确到区地址：{data.get('address') or '按目标主体工商/备案地址填写到区'}",
            f"URL：{f.get('url','')}",
            "详情：" + (data.get("detail") or val(f.get("data")) or f.get("title", "")),
            "复现：",
            f"1. 确认测试范围：{scope.get('scope') or scope.get('program') or scope.get('target','')}",
            f"2. 执行最小化安全 PoC：{curl}",
            "3. 对照正常用户/未授权用户/越权用户响应，确认非公开对象或业务状态可被访问/修改。",
            "4. 保存响应头、响应体摘要和截图。【截图位置1】",
            "影响：" + (data.get("impact") or "攻击者可在授权验证条件下证明访问控制/业务规则缺失，可能导致非公开数据访问、越权操作或业务流程异常。"),
            "修复：" + (data.get("fix") or "服务端基于登录态和对象归属做强制鉴权；禁止仅依赖前端控制；关键操作增加状态机校验、CSRF/重放防护和审计。"),
            "复现命令汇总：",
            curl,
            "证据索引：" + "; ".join([e.get("id","") for e in ev][:5]),
            "验证索引：" + "; ".join([v.get("id","") for v in va][:5]),
        ]))
    report="\n===\n".join(parts) if parts else "无 accepted findings。请先记录 finding/evidence/validation 并通过 critic gate。\n"
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(json.dumps({"ok":True,"out":str(Path(args.out).resolve()),"findings":len(findings)}, ensure_ascii=False))
    else:
        print(report)

if __name__ == "__main__":
    main()
