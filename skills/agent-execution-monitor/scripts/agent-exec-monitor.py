#!/usr/bin/env python3
"""
Agent Execution Monitor / Loop Guard
借鉴 PentAGI v2.0 的 Execution Monitor 机制
防止 agent 陷入无效循环、管理工具调用预算、记录因果图
"""
import json, os, sys, time
from datetime import datetime, timezone
from collections import Counter, defaultdict

DATA_DIR = "/tmp"
MONITOR_FILE = os.path.join(DATA_DIR, "hermes-exec-monitor.jsonl")
ALERTS_FILE = os.path.join(DATA_DIR, "hermes-exec-alerts.jsonl")

TASK_BUDGETS = {
    "quick-scan": 30,
    "standard": 80,
    "deep-hunt": 150,
    "unlimited": 999999,
}

SAME_TOOL_WARN = 5
SAME_TOOL_FORCE = 8

def load_records(path=MONITOR_FILE, limit=500):
    records = []
    if not os.path.exists(path):
        return records
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except:
                    pass
    return records[-limit:]

def append_record(record, path=MONITOR_FILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def cmd_log(args):
    if len(args) < 2:
        print("Usage: monitor.py log <tool> <target> [evidence] [hypothesis]")
        return
    tool, target = args[0], args[1]
    evidence = args[2] if len(args) > 2 else ""
    hypothesis = args[3] if len(args) > 3 else ""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool, "target": target,
        "evidence": evidence, "hypothesis": hypothesis,
        "validation_tool": "", "validation_result": "", "severity": ""
    }
    append_record(record)
    records = load_records(limit=20)
    check_loop(records, tool, target)

def check_loop(records, current_tool, current_target):
    if len(records) < SAME_TOOL_WARN:
        return
    consecutive = 0
    for r in reversed(records):
        if r.get("tool") == current_tool and r.get("target") == current_target:
            consecutive += 1
        else:
            break
    if consecutive >= SAME_TOOL_FORCE:
        alert = {"ts": datetime.now(timezone.utc).isoformat(), "type": "LOOP_FORCE_STOP",
                 "tool": current_tool, "target": current_target, "consecutive": consecutive,
                 "message": f"LOOP DETECTED: {current_tool} called {consecutive}x on {current_target}. Forced stop."}
        append_record(alert, ALERTS_FILE)
        print(f"\n🚨 LOOP FORCE STOP: {current_tool} x{consecutive} on {current_target}")
        sys.exit(2)
    elif consecutive >= SAME_TOOL_WARN:
        alert = {"ts": datetime.now(timezone.utc).isoformat(), "type": "LOOP_WARNING",
                 "tool": current_tool, "target": current_target, "consecutive": consecutive,
                 "message": f"WARNING: {current_tool} called {consecutive}x on {current_target}."}
        append_record(alert, ALERTS_FILE)
        print(f"\n⚠️  LOOP WARNING: {current_tool} x{consecutive} on {current_target}")

def cmd_stats(args):
    records = load_records()
    if not records:
        print("No records found."); return
    tool_counts = Counter(r.get("tool", "?") for r in records)
    target_counts = Counter(r.get("target", "?") for r in records)
    confirmed = [r for r in records if r.get("validation_result") == "confirmed"]
    print(f"=== Agent Execution Monitor Stats ===")
    print(f"Total tool calls: {len(records)}")
    print(f"Confirmed findings: {len(confirmed)}")
    print(f"\nTool usage:")
    for tool, count in tool_counts.most_common(15):
        print(f"  {tool}: {count}")
    print(f"\nTop targets:")
    for target, count in target_counts.most_common(10):
        print(f"  {target}: {count}")
    mode = args[0] if args else "standard"
    budget = TASK_BUDGETS.get(mode, 80)
    remaining = budget - len(records)
    if remaining <= 0:
        print(f"\n🔴 BUDGET EXHAUSTED: {len(records)}/{budget} ({mode})")
    elif remaining <= budget * 0.2:
        print(f"\n🟡 BUDGET WARNING: {len(records)}/{budget} ({mode}), {remaining} remaining")
    else:
        print(f"\n🟢 Budget: {len(records)}/{budget} ({mode}), {remaining} remaining")

def cmd_alerts(args):
    if not os.path.exists(ALERTS_FILE):
        print("No alerts."); return
    with open(ALERTS_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    a = json.loads(line)
                    icon = "🚨" if a.get("type") == "LOOP_FORCE_STOP" else "⚠️"
                    print(f"{icon} [{a.get('ts','')[:19]}] {a.get('message','')}")
                except: pass

def cmd_graph(args):
    records = load_records()
    if not records: print("No records."); return
    print("=== Evidence → Hypothesis → Validation Graph ===\n")
    for r in records:
        if r.get("evidence") or r.get("hypothesis"):
            ts = r.get("ts", "")[:19]
            print(f"[{ts}] {r.get('tool','?')} → {r.get('target','?')}")
            if r.get("evidence"): print(f"  Evidence: {r['evidence']}")
            if r.get("hypothesis"): print(f"  Hypothesis: {r['hypothesis']}")
            if r.get("validation_result"):
                icon = "✅" if r["validation_result"] == "confirmed" else "❌"
                print(f"  Validation: {icon} {r['validation_result']}")
            if r.get("severity"): print(f"  Severity: {r['severity']}")
            print()

def cmd_confirm(args):
    if len(args) < 3:
        print("Usage: monitor.py confirm <tool> <target> <confirmed|denied> [severity]"); return
    record = {"ts": datetime.now(timezone.utc).isoformat(), "tool": args[0], "target": args[1],
              "validation_result": args[2], "severity": args[3] if len(args) > 3 else "",
              "evidence": "", "hypothesis": "", "validation_tool": "manual"}
    append_record(record)
    icon = "✅" if args[2] == "confirmed" else "❌"
    print(f"{icon} Finding {args[2]}: {args[0]} on {args[1]}")

def cmd_reset(args):
    for f in [MONITOR_FILE, ALERTS_FILE]:
        if os.path.exists(f): os.remove(f)
    print("Monitor data reset.")

def cmd_budget(args):
    mode = args[0] if args else "standard"
    extend = int(args[1]) if len(args) > 1 else 0
    records = load_records()
    base_budget = TASK_BUDGETS.get(mode, 80)
    budget = base_budget + extend
    used = len(records)
    remaining = budget - used
    print(f"Mode: {mode}\nBudget: {budget} (base: {base_budget} + extended: {extend})")
    print(f"Used: {used}\nRemaining: {remaining}")
    print("Status:", "🔴 EXHAUSTED" if remaining <= 0 else "🟡 LOW" if remaining <= budget * 0.2 else "🟢 OK")

def cmd_summary(args):
    records = load_records()
    confirmed = [r for r in records if r.get("validation_result") == "confirmed"]
    pending = [r for r in records if r.get("hypothesis") and not r.get("validation_result")]
    print("=== Task Summary (for context handoff) ===\n")
    print(f"Total actions: {len(records)}\nConfirmed findings: {len(confirmed)}\nPending hypotheses: {len(pending)}")
    if confirmed:
        print(f"\n--- Confirmed Findings ---")
        for r in confirmed:
            print(f"  [{r.get('severity','?')}] {r.get('tool','?')} → {r.get('target','?')}: {r.get('evidence','')}")
    if pending:
        print(f"\n--- Pending Hypotheses ---")
        for r in pending:
            print(f"  {r.get('hypothesis','')} (via {r.get('tool','?')} on {r.get('target','?')})")

COMMANDS = {"log": cmd_log, "stats": cmd_stats, "alerts": cmd_alerts, "graph": cmd_graph,
            "confirm": cmd_confirm, "reset": cmd_reset, "budget": cmd_budget, "summary": cmd_summary}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Agent Execution Monitor / Loop Guard")
        print(f"\nUsage: {sys.argv[0]} <command> [args...]")
        print("\nCommands: log, stats, alerts, graph, confirm, budget, summary, reset")
        print(f"Task modes: {', '.join(TASK_BUDGETS.keys())}")
        sys.exit(0)
    cmd = sys.argv[1]
    if cmd in COMMANDS: COMMANDS[cmd](sys.argv[2:])
    else: print(f"Unknown command: {cmd}"); sys.exit(1)
