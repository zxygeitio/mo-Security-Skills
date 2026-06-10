#!/usr/bin/env python3
"""
工具成功率记忆系统
记录哪些工具对哪种指纹/目标类型成功过，提升后续渗透效率
借鉴 PentAGI 的 Graphiti "successful_tools" 概念
"""
import json, os, sys, sqlite3
from datetime import datetime, timezone

DB_PATH = "/root/.hermes/data/tool_success.db"

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tool_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            tool TEXT NOT NULL,
            target TEXT NOT NULL,
            fingerprint TEXT,
            target_type TEXT,
            success INTEGER DEFAULT 0,
            severity TEXT,
            vuln_type TEXT,
            duration_sec REAL,
            notes TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_tool ON tool_runs(tool)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_fingerprint ON tool_runs(fingerprint)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_success ON tool_runs(success)
    """)
    conn.commit()
    return conn

def cmd_record(args):
    """Record a tool run: record <tool> <target> <fingerprint> <success> [severity] [vuln_type]"""
    if len(args) < 4:
        print("Usage: tool-memory.py record <tool> <target> <fingerprint> <0|1> [severity] [vuln_type]")
        return
    
    tool, target, fingerprint, success = args[0], args[1], args[2], int(args[3])
    severity = args[4] if len(args) > 4 else ""
    vuln_type = args[5] if len(args) > 5 else ""
    
    # Determine target type from fingerprint
    target_type = classify_target(fingerprint)
    
    conn = get_db()
    conn.execute("""
        INSERT INTO tool_runs (ts, tool, target, fingerprint, target_type, success, severity, vuln_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now(timezone.utc).isoformat(), tool, target, fingerprint, target_type, success, severity, vuln_type))
    conn.commit()
    conn.close()
    
    icon = "✅" if success else "❌"
    print(f"{icon} Recorded: {tool} on {target} (fingerprint: {fingerprint}, success: {success})")

def classify_target(fingerprint):
    """Classify target type from fingerprint string"""
    fp = fingerprint.lower()
    if any(x in fp for x in ["wordpress", "wp-", "wp_"]):
        return "wordpress"
    elif any(x in fp for x in ["drupal"]):
        return "drupal"
    elif any(x in fp for x in ["joomla"]):
        return "joomla"
    elif any(x in fp for x in ["spring", "tomcat", "java"]):
        return "java-web"
    elif any(x in fp for x in ["flask", "django", "python"]):
        return "python-web"
    elif any(x in fp for x in ["express", "node", "next.js", "nuxt"]):
        return "node-web"
    elif any(x in fp for x in ["laravel", "php"]):
        return "php-web"
    elif any(x in fp for x in ["asp.net", "iis"]):
        return "dotnet-web"
    elif any(x in fp for x in ["nginx"]):
        return "nginx"
    elif any(x in fp for x in ["apache"]):
        return "apache"
    elif any(x in fp for x in ["泛微", "e-cology", "weaver"]):
        return "weaver-oa"
    elif any(x in fp for x in ["金智", "wisedu", "cas"]):
        return "wisedu-cas"
    elif any(x in fp for x in ["蓝凌", "landray", "ekp"]):
        return "landray-oa"
    elif any(x in fp for x in ["深信服", "sangfor", "vpn"]):
        return "sangfor-vpn"
    else:
        return "generic"

def cmd_recommend(args):
    """Recommend tools for a fingerprint: recommend <fingerprint>"""
    if not args:
        print("Usage: tool-memory.py recommend <fingerprint>")
        return
    
    fingerprint = " ".join(args)
    target_type = classify_target(fingerprint)
    
    conn = get_db()
    
    # Find successful tools for this target type
    rows = conn.execute("""
        SELECT tool, 
               COUNT(*) as total_runs,
               SUM(success) as successes,
               ROUND(100.0 * SUM(success) / COUNT(*), 1) as success_rate,
               GROUP_CONCAT(DISTINCT vuln_type) as vuln_types,
               MAX(severity) as max_severity
        FROM tool_runs 
        WHERE target_type = ? AND success = 1
        GROUP BY tool
        ORDER BY success_rate DESC, successes DESC
        LIMIT 10
    """, (target_type,)).fetchall()
    
    conn.close()
    
    if not rows:
        print(f"No successful tool records for target type: {target_type}")
        print(f"(Classified from fingerprint: {fingerprint})")
        print("\nRun some tools first and record results with:")
        print(f"  tool-memory.py record <tool> <target> '{fingerprint}' 1 [severity] [vuln_type]")
        return
    
    print(f"=== Recommended Tools for {target_type} ===")
    print(f"Fingerprint: {fingerprint}\n")
    
    for r in rows:
        print(f"  {r['tool']}")
        print(f"    Success rate: {r['success_rate']}% ({r['successes']}/{r['total_runs']})")
        if r['vuln_types']:
            print(f"    Found vulns: {r['vuln_types']}")
        if r['max_severity']:
            print(f"    Max severity: {r['max_severity']}")
        print()

def cmd_stats(args):
    """Show overall statistics"""
    conn = get_db()
    
    total = conn.execute("SELECT COUNT(*) as c FROM tool_runs").fetchone()['c']
    successes = conn.execute("SELECT COUNT(*) as c FROM tool_runs WHERE success=1").fetchone()['c']
    
    print("=== Tool Success Memory Stats ===")
    print(f"Total records: {total}")
    print(f"Successes: {successes}")
    if total > 0:
        print(f"Overall success rate: {100*successes/total:.1f}%")
    
    # Top tools by success rate
    print("\n--- Top Tools by Success Rate (min 3 runs) ---")
    rows = conn.execute("""
        SELECT tool, COUNT(*) as runs, SUM(success) as wins,
               ROUND(100.0 * SUM(success) / COUNT(*), 1) as rate
        FROM tool_runs
        GROUP BY tool
        HAVING runs >= 3
        ORDER BY rate DESC
        LIMIT 10
    """).fetchall()
    for r in rows:
        print(f"  {r['tool']}: {r['rate']}% ({r['wins']}/{r['runs']})")
    
    # Top target types
    print("\n--- Target Type Distribution ---")
    rows = conn.execute("""
        SELECT target_type, COUNT(*) as c, SUM(success) as s
        FROM tool_runs
        GROUP BY target_type
        ORDER BY c DESC
        LIMIT 10
    """).fetchall()
    for r in rows:
        print(f"  {r['target_type']}: {r['c']} runs, {r['s']} successes")
    
    conn.close()

def cmd_history(args):
    """Show recent tool runs"""
    limit = int(args[0]) if args else 20
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM tool_runs ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    
    if not rows:
        print("No records.")
        return
    
    print(f"=== Last {len(rows)} Tool Runs ===\n")
    for r in rows:
        icon = "✅" if r['success'] else "❌"
        print(f"{icon} [{r['ts'][:19]}] {r['tool']} → {r['target']}")
        print(f"   Fingerprint: {r['fingerprint']} | Type: {r['target_type']}")
        if r['vuln_type']:
            print(f"   Vuln: {r['vuln_type']} | Severity: {r['severity']}")
        print()

def cmd_export(args):
    """Export data as JSON"""
    conn = get_db()
    rows = conn.execute("SELECT * FROM tool_runs ORDER BY id").fetchall()
    conn.close()
    
    data = [dict(r) for r in rows]
    output = args[0] if args else "/tmp/tool_success_export.json"
    with open(output, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Exported {len(data)} records to {output}")

COMMANDS = {
    "record": cmd_record,
    "recommend": cmd_recommend,
    "stats": cmd_stats,
    "history": cmd_history,
    "export": cmd_export,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Tool Success Memory System")
        print(f"\nUsage: {sys.argv[0]} <command> [args...]")
        print("\nCommands:")
        print("  record <tool> <target> <fingerprint> <0|1> [severity] [vuln_type]")
        print("  recommend <fingerprint>")
        print("  stats")
        print("  history [limit]")
        print("  export [output_file]")
        sys.exit(0)
    
    cmd = sys.argv[1]
    if cmd in COMMANDS:
        COMMANDS[cmd](sys.argv[2:])
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
