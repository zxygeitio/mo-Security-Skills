#!/usr/bin/python3
"""
Agent Execution Monitor / Loop Guard v2.1
借鉴 PentAGI v2.0 的 Execution Monitor 机制

v2.0 升级 (2026-06-09 基于 NJMU 测试教训):
  1. 语义循环检测: 检测"相同测试方案"重复，不仅追踪 tool+target
  2. 时间门限: 自上次确认发现后 N 分钟无进展，强制切换策略
  3. 负面记忆: 记录被用户拒绝的发现类型，重复产出时警告
  4. 进展停滞检测: 连续 N 次调用无新证据，强制切换
  5. 测试方案签名: 哈希最近 N 步操作序列，检测方案级重复

v2.1 升级 (2026-06-09 GPT审计修复):
  6. 按workspace隔离状态: --workspace参数，避免跨目标状态污染
"""
import json, os, sys, hashlib
from datetime import datetime, timezone
from collections import Counter

DATA_DIR = "/tmp"
MONITOR_FILE = os.path.join(DATA_DIR, "hermes-exec-monitor.jsonl")
ALERTS_FILE = os.path.join(DATA_DIR, "hermes-exec-alerts.jsonl")
REJECTED_FILE = os.path.join(DATA_DIR, "hermes-exec-rejected.jsonl")

# v2.1: Workspace isolation support
def get_data_dir(workspace=None):
    """Return data directory, optionally per-workspace isolated."""
    if workspace:
        ws_dir = os.path.join(DATA_DIR, f"hermes-monitor-{workspace}")
        os.makedirs(ws_dir, exist_ok=True)
        return ws_dir
    return DATA_DIR

def get_files(workspace=None):
    """Get monitor/alerts/rejected file paths for given workspace."""
    d = get_data_dir(workspace)
    return (
        os.path.join(d, "hermes-exec-monitor.jsonl"),
        os.path.join(d, "hermes-exec-alerts.jsonl"),
        os.path.join(d, "hermes-exec-rejected.jsonl"),
    )

# Budget by task mode
TASK_BUDGETS = {
    "quick-scan": 30,
    "standard": 80,
    "deep-hunt": 150,
    "unlimited": 999999,
}

# Loop detection thresholds
SAME_TOOL_WARN = 5
SAME_TOOL_FORCE = 8

# v2.0: Semantic loop detection
PLAN_WINDOW = 10          # 用最近 N 步生成方案签名
PLAN_REPEAT_WARN = 3      # 相同方案签名出现 N 次警告
PLAN_REPEAT_FORCE = 5     # 相同方案签名出现 N 次强制停止

# v2.0: Time-based exit gate
STALE_MINUTES_WARN = 10   # 上次确认发现后 N 分钟无进展警告
STALE_MINUTES_FORCE = 20  # N 分钟强制停止

# v2.0: Progress stagnation
STAGNATION_WARN = 8       # 连续 N 次调用无新证据警告
STAGNATION_FORCE = 12     # 连续 N 次强制停止

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

def load_rejected():
    """Load rejected finding types"""
    if not os.path.exists(REJECTED_FILE):
        return []
    records = []
    with open(REJECTED_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except:
                    pass
    return records

def append_record(record, path=MONITOR_FILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def compute_plan_signature(records, window=PLAN_WINDOW):
    """v2.0: Compute hash of recent N tool+target+evidence_pattern"""
    recent = records[-window:]
    sig_parts = []
    for r in recent:
        tool = r.get("tool", "?")
        target = r.get("target", "?")
        # Normalize: strip exact URLs/params, keep domain/endpoint pattern
        sig_parts.append(f"{tool}:{target[:60]}")
    sig_str = "|".join(sig_parts)
    return hashlib.md5(sig_str.encode()).hexdigest()[:12]

def find_last_confirmed_time(records):
    """v2.0: Find timestamp of last confirmed finding"""
    for r in reversed(records):
        if r.get("validation_result") == "confirmed":
            return r.get("ts", "")
    return ""

def minutes_since(iso_ts):
    """v2.0: Minutes since an ISO timestamp"""
    if not iso_ts:
        return 999
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (now - dt).total_seconds() / 60
    except:
        return 999

def cmd_log(args):
    """Log a tool call: log <tool> <target> [evidence] [hypothesis]
    Multi-word args after target are joined; evidence and hypothesis separated by '||'.
    """
    if len(args) < 2:
        print("Usage: monitor.py log <tool> <target> [evidence] [hypothesis]")
        return
    tool, target = args[0], args[1]
    # Join remaining args, split on || for evidence|hypothesis
    rest = " ".join(args[2:])
    parts = rest.split("||", 1)
    evidence = parts[0].strip() if parts else ""
    hypothesis = parts[1].strip() if len(parts) > 1 else ""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "target": target,
        "evidence": evidence,
        "hypothesis": hypothesis,
        "validation_tool": "",
        "validation_result": "",
        "severity": "",
        "new_evidence": bool(evidence)
    }
    append_record(record)

    # Check all guards
    records = load_records(limit=200)
    check_loop(records, tool, target)
    check_semantic_loop(records)
    check_staleness(records)
    check_stagnation(records)
    check_rejected_repetition(records, tool, target, evidence)

def check_loop(records, current_tool, current_target):
    """Check if agent is stuck in a loop (same tool+target)"""
    if len(records) < SAME_TOOL_WARN:
        return

    consecutive = 0
    for r in reversed(records):
        if r.get("tool") == current_tool and r.get("target") == current_target:
            consecutive += 1
        else:
            break

    if consecutive >= SAME_TOOL_FORCE:
        alert = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "LOOP_FORCE_STOP",
            "tool": current_tool,
            "target": current_target,
            "consecutive": consecutive,
            "message": f"LOOP DETECTED: {current_tool} called {consecutive}x on {current_target}. Forced stop. Switch strategy."
        }
        append_record(alert, ALERTS_FILE)
        print(f"\n🚨 LOOP FORCE STOP: {current_tool} x{consecutive} on {current_target}")
        print("   Suggestion: Switch tool, change angle, or report existing findings")
        sys.exit(2)
    elif consecutive >= SAME_TOOL_WARN:
        alert = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "LOOP_WARNING",
            "tool": current_tool,
            "target": current_target,
            "consecutive": consecutive,
            "message": f"WARNING: {current_tool} called {consecutive}x on {current_target}. Consider switching."
        }
        append_record(alert, ALERTS_FILE)
        print(f"\n⚠️  LOOP WARNING: {current_tool} x{consecutive} on {current_target}")

def check_semantic_loop(records):
    """v2.0: Check if agent is repeating the same test plan"""
    if len(records) < PLAN_WINDOW * 2:
        return

    # Compute signatures for sliding windows
    sig_counts = Counter()
    for i in range(len(records) - PLAN_WINDOW + 1):
        window = records[i:i + PLAN_WINDOW]
        sig_parts = []
        for r in window:
            sig_parts.append(f"{r.get('tool','?')}:{r.get('target','?')[:60]}")
        sig = hashlib.md5("|".join(sig_parts).encode()).hexdigest()[:12]
        sig_counts[sig] += 1

    # Check for repeated plans
    for sig, count in sig_counts.most_common(3):
        if count >= PLAN_REPEAT_FORCE:
            alert = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "type": "SEMANTIC_LOOP_FORCE",
                "plan_signature": sig,
                "repeat_count": count,
                "message": f"SEMANTIC LOOP: Same test plan repeated {count}x (sig={sig}). STOP and switch strategy."
            }
            append_record(alert, ALERTS_FILE)
            print(f"\n🚨 SEMANTIC LOOP FORCE STOP: Same plan repeated {count}x")
            print(f"   Plan signature: {sig}")
            print("   Action: STOP all testing, report findings, or switch to different target")
            sys.exit(2)
        elif count >= PLAN_REPEAT_WARN:
            alert = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "type": "SEMANTIC_LOOP_WARN",
                "plan_signature": sig,
                "repeat_count": count,
                "message": f"SEMANTIC LOOP WARNING: Same test plan repeated {count}x (sig={sig})."
            }
            append_record(alert, ALERTS_FILE)
            print(f"\n⚠️  SEMANTIC LOOP WARNING: Same plan repeated {count}x")
            print("   Consider: Are you generating new results or repeating negatives?")

def check_staleness(records):
    """v2.0: Time-based exit gate. Only triggers AFTER first confirmed finding."""
    last_confirmed = find_last_confirmed_time(records)
    if not last_confirmed:
        # No confirmed findings yet — use session start as baseline
        if records:
            last_confirmed = records[0].get("ts", "")
        else:
            return  # No records at all
    minutes = minutes_since(last_confirmed)

    if minutes >= STALE_MINUTES_FORCE:
        alert = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "STALE_FORCE_STOP",
            "minutes_without_progress": int(minutes),
            "message": f"STALE: {int(minutes)} minutes since last confirmed finding. Force stop."
        }
        append_record(alert, ALERTS_FILE)
        print(f"\n🚨 STALENESS FORCE STOP: {int(minutes)} min without confirmed findings")
        print("   Action: Report existing findings or switch to different target/angle")
        # Don't sys.exit(2) here - let the agent decide. Just emit a strong warning.
    elif minutes >= STALE_MINUTES_WARN:
        print(f"\n⚠️  STALENESS WARNING: {int(minutes)} min since last confirmed finding")

def check_stagnation(records):
    """v2.0: Progress stagnation - consecutive calls with no new evidence"""
    if len(records) < STAGNATION_WARN:
        return

    no_evidence_count = 0
    for r in reversed(records):
        if r.get("new_evidence"):
            break
        no_evidence_count += 1

    if no_evidence_count >= STAGNATION_FORCE:
        alert = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "STAGNATION_FORCE",
            "consecutive_no_evidence": no_evidence_count,
            "message": f"STAGNATION: {no_evidence_count} consecutive tool calls with no new evidence."
        }
        append_record(alert, ALERTS_FILE)
        print(f"\n🚨 STAGNATION FORCE: {no_evidence_count} calls without new evidence")
        print("   Action: Report findings, try completely different approach, or switch target")
        sys.exit(2)
    elif no_evidence_count >= STAGNATION_WARN:
        print(f"\n⚠️  STAGNATION WARNING: {no_evidence_count} calls without new evidence")

def check_rejected_repetition(records, tool, target, evidence):
    """v2.0: Check if producing findings similar to rejected ones"""
    rejected = load_rejected()
    if not rejected:
        return

    # Check if current tool+target matches any rejected pattern
    for rej in rejected:
        rej_tool = rej.get("tool", "")
        rej_target = rej.get("target", "")
        rej_type = rej.get("finding_type", "")

        if rej_tool and rej_target and tool == rej_tool and target == rej_target:
            print(f"\n⚠️  REJECTED PATTERN: {tool} on {target} was previously rejected ({rej_type})")
            print(f"   User feedback: {rej.get('user_feedback', 'N/A')}")
            return

        # Check finding type match
        if rej_type and rej_type in evidence.lower():
            print(f"\n⚠️  REJECTED FINDING TYPE: '{rej_type}' was previously rejected")
            print(f"   User feedback: {rej.get('user_feedback', 'N/A')}")

def cmd_reject(args):
    """v2.0: Record user's rejection of a finding: reject <tool> <target> <finding_type> [user_feedback]"""
    if len(args) < 3:
        print("Usage: monitor.py reject <tool> <target> <finding_type> [user_feedback]")
        return
    tool, target, finding_type = args[0], args[1], args[2]
    feedback = args[3] if len(args) > 3 else ""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "target": target,
        "finding_type": finding_type,
        "user_feedback": feedback
    }
    append_record(record, REJECTED_FILE)
    print(f"📝 Rejected pattern recorded: {tool}/{target}/{finding_type}")
    print("   Future similar findings will trigger warnings")

def cmd_stats(args):
    """Show execution statistics"""
    records = load_records()
    if not records:
        print("No records found.")
        return

    tool_counts = Counter(r.get("tool", "?") for r in records)
    target_counts = Counter(r.get("target", "?") for r in records)
    confirmed = [r for r in records if r.get("validation_result") == "confirmed"]
    rejected = load_rejected()

    print("=== Agent Execution Monitor Stats v2.0 ===")
    print(f"Total tool calls: {len(records)}")
    print(f"Confirmed findings: {len(confirmed)}")
    print(f"Rejected patterns: {len(rejected)}")

    # v2.0: Staleness
    last_confirmed = find_last_confirmed_time(records)
    if last_confirmed:
        minutes = minutes_since(last_confirmed)
        print(f"Time since last confirmed: {int(minutes)} min")
    else:
        print("Time since last confirmed: N/A (none confirmed)")

    # v2.0: Stagnation
    no_evidence = 0
    for r in reversed(records):
        if r.get("new_evidence"):
            break
        no_evidence += 1
    print(f"Consecutive no-evidence: {no_evidence}")

    # v2.0: Plan signatures
    if len(records) >= PLAN_WINDOW:
        sig = compute_plan_signature(records)
        print(f"Current plan signature: {sig}")

    print("\nTool usage:")
    for tool, count in tool_counts.most_common(15):
        print(f"  {tool}: {count}")
    print("\nTop targets:")
    for target, count in target_counts.most_common(10):
        print(f"  {target}: {count}")

    # Budget check
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
    """Show loop detection alerts"""
    if not os.path.exists(ALERTS_FILE):
        print("No alerts.")
        return
    with open(ALERTS_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    a = json.loads(line)
                    atype = a.get("type", "")
                    if "FORCE" in atype:
                        icon = "🚨"
                    elif "WARN" in atype:
                        icon = "⚠️"
                    else:
                        icon = "📋"
                    print(f"{icon} [{a.get('ts','')[:19]}] {a.get('message','')}")
                except:
                    pass

def cmd_graph(args):
    """Show Evidence→Hypothesis→Validation causal graph"""
    records = load_records()
    if not records:
        print("No records.")
        return

    print("=== Evidence → Hypothesis → Validation Graph ===\n")
    for r in records:
        if r.get("evidence") or r.get("hypothesis"):
            ts = r.get("ts", "")[:19]
            tool = r.get("tool", "?")
            target = r.get("target", "?")
            ev = r.get("evidence", "")
            hyp = r.get("hypothesis", "")
            val = r.get("validation_result", "")
            sev = r.get("severity", "")

            print(f"[{ts}] {tool} → {target}")
            if ev:
                print(f"  Evidence: {ev}")
            if hyp:
                print(f"  Hypothesis: {hyp}")
            if val:
                icon = "✅" if val == "confirmed" else "❌" if val == "denied" else "⏳"
                print(f"  Validation: {icon} {val}")
            if sev:
                print(f"  Severity: {sev}")
            print()

def cmd_confirm(args):
    """Confirm/deny a finding: confirm <tool> <target> <confirmed|denied> [severity]"""
    if len(args) < 3:
        print("Usage: monitor.py confirm <tool> <target> <confirmed|denied> [severity]")
        return
    tool, target, result = args[0], args[1], args[2]
    severity = args[3] if len(args) > 3 else ""

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "target": target,
        "validation_result": result,
        "severity": severity,
        "evidence": "",
        "hypothesis": "",
        "validation_tool": "manual",
        "new_evidence": True  # Confirmations count as progress
    }
    append_record(record)
    icon = "✅" if result == "confirmed" else "❌"
    print(f"{icon} Finding {result}: {tool} on {target}")

def cmd_reset(args):
    """Reset monitor data"""
    for f in [MONITOR_FILE, ALERTS_FILE, REJECTED_FILE]:
        if os.path.exists(f):
            os.remove(f)
    print("Monitor data reset (including rejected patterns).")

def cmd_budget(args):
    """Check/extend budget: budget <mode> [extend_amount]"""
    mode = args[0] if args else "standard"
    extend = int(args[1]) if len(args) > 1 else 0

    records = load_records()
    base_budget = TASK_BUDGETS.get(mode, 80)
    budget = base_budget + extend
    used = len(records)
    remaining = budget - used

    print(f"Mode: {mode}")
    print(f"Budget: {budget} (base: {base_budget} + extended: {extend})")
    print(f"Used: {used}")
    print(f"Remaining: {remaining}")
    if remaining <= 0:
        print("Status: 🔴 EXHAUSTED")
    elif remaining <= budget * 0.2:
        print("Status: 🟡 LOW")
    else:
        print("Status: 🟢 OK")

def cmd_summary(args):
    """Generate task summary for context handoff"""
    records = load_records()
    confirmed = [r for r in records if r.get("validation_result") == "confirmed"]
    pending = [r for r in records if r.get("hypothesis") and not r.get("validation_result")]
    rejected = load_rejected()

    print("=== Task Summary (for context handoff) ===\n")
    print(f"Total actions: {len(records)}")
    print(f"Confirmed findings: {len(confirmed)}")
    print(f"Pending hypotheses: {len(pending)}")
    print(f"Rejected patterns: {len(rejected)}")

    # v2.0: Staleness in summary
    last_confirmed = find_last_confirmed_time(records)
    if last_confirmed:
        minutes = minutes_since(last_confirmed)
        print(f"Time since last confirmed: {int(minutes)} min")
        if minutes >= STALE_MINUTES_WARN:
            print("  ⚠️  Recommend: switch strategy or report existing findings")

    if confirmed:
        print("\n--- Confirmed Findings ---")
        for r in confirmed:
            print(f"  [{r.get('severity','?')}] {r.get('tool','?')} → {r.get('target','?')}: {r.get('evidence','')}")

    if pending:
        print("\n--- Pending Hypotheses ---")
        for r in pending:
            print(f"  {r.get('hypothesis','')} (via {r.get('tool','?')} on {r.get('target','?')})")

    if rejected:
        print("\n--- Rejected Patterns (avoid these) ---")
        for r in rejected:
            print(f"  {r.get('tool','?')}/{r.get('target','?')}/{r.get('finding_type','')} - {r.get('user_feedback','')}")

def cmd_health(args):
    """v2.0: Quick health check - all guards in one view"""
    records = load_records()
    rejected = load_rejected()
    alerts = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE) as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except:
                    pass

    print("=== Monitor Health Check v2.0 ===\n")

    # Budget
    mode = args[0] if args else "standard"
    budget = TASK_BUDGETS.get(mode, 80)
    used = len(records)
    remaining = budget - used
    budget_icon = "🔴" if remaining <= 0 else "🟡" if remaining <= budget * 0.2 else "🟢"
    print(f"{budget_icon} Budget: {used}/{budget} ({mode}), {remaining} remaining")

    # Staleness
    last_confirmed = find_last_confirmed_time(records)
    if last_confirmed:
        minutes = minutes_since(last_confirmed)
    elif records:
        minutes = minutes_since(records[0].get("ts", ""))
    else:
        minutes = 0
    stale_icon = "🔴" if minutes >= STALE_MINUTES_FORCE else "🟡" if minutes >= STALE_MINUTES_WARN else "🟢"
    label = "since session start" if not last_confirmed else "since last confirmed"
    print(f"{stale_icon} Staleness: {int(minutes)} min {label}")

    # Stagnation
    no_evidence = 0
    for r in reversed(records):
        if r.get("new_evidence"):
            break
        no_evidence += 1
    stag_icon = "🔴" if no_evidence >= STAGNATION_FORCE else "🟡" if no_evidence >= STAGNATION_WARN else "🟢"
    print(f"{stag_icon} Stagnation: {no_evidence} consecutive no-evidence calls")

    # Loop
    loop_alerts = [a for a in alerts if "LOOP" in a.get("type", "")]
    loop_icon = "🔴" if any("FORCE" in a.get("type", "") for a in loop_alerts[-5:]) else "🟢"
    print(f"{loop_icon} Loop alerts: {len(loop_alerts)} total ({sum(1 for a in loop_alerts if 'FORCE' in a.get('type',''))} force-stops)")

    # Rejected patterns
    print(f"📝 Rejected patterns: {len(rejected)} (will warn on repetition)")

    # Current plan
    if len(records) >= PLAN_WINDOW:
        sig = compute_plan_signature(records)
        print(f"🔍 Current plan signature: {sig}")

COMMANDS = {
    "log": cmd_log,
    "stats": cmd_stats,
    "alerts": cmd_alerts,
    "graph": cmd_graph,
    "confirm": cmd_confirm,
    "reject": cmd_reject,
    "reset": cmd_reset,
    "budget": cmd_budget,
    "summary": cmd_summary,
    "health": cmd_health,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Agent Execution Monitor / Loop Guard v2.1")
        print(f"\nUsage: {sys.argv[0]} [--workspace NAME] <command> [args...]")
        print("\nOptions:")
        print("  --workspace NAME    Isolate state per workspace/target (default: global)")
        print("\nCommands:")
        print("  log <tool> <target> [evidence] [hypothesis]  - Log a tool call")
        print("  stats [mode]                                  - Show execution stats")
        print("  alerts                                        - Show all alerts")
        print("  graph                                         - Show causal graph")
        print("  confirm <tool> <target> <result> [severity]   - Confirm/deny finding")
        print("  reject <tool> <target> <type> [feedback]      - Record rejected finding")
        print("  budget <mode> [extend]                        - Check/extend budget")
        print("  summary                                       - Task summary for handoff")
        print("  health [mode]                                 - Quick health check")
        print("  reset                                         - Reset all data")
        print(f"\nTask modes: {', '.join(TASK_BUDGETS.keys())}")
        print("\nv2.1 Guards:")
        print(f"  Semantic loop: warn@{PLAN_REPEAT_WARN}x, force@{PLAN_REPEAT_FORCE}x")
        print(f"  Staleness: warn@{STALE_MINUTES_WARN}min, force@{STALE_MINUTES_FORCE}min")
        print(f"  Stagnation: warn@{STAGNATION_WARN}, force@{STAGNATION_FORCE}")
        print("  Rejected memory: persistent across calls")
        print("  Workspace isolation: --workspace NAME")
        sys.exit(0)

    # Parse --workspace before command
    args = sys.argv[1:]
    workspace = None
    if "--workspace" in args:
        idx = args.index("--workspace")
        if idx + 1 < len(args):
            workspace = args[idx + 1]
            args = args[:idx] + args[idx+2:]
        else:
            print("Error: --workspace requires a name argument")
            sys.exit(1)

    # Apply workspace isolation to global file paths
    MONITOR_FILE, ALERTS_FILE, REJECTED_FILE = get_files(workspace)

    cmd = args[0] if args else ""
    if cmd in COMMANDS:
        COMMANDS[cmd](args[1:])
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
