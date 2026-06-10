#!/usr/bin/env python3
"""
Sploitus漏洞搜索引擎集成
聚合 ExploitDB + Packet Storm + GitHub Security Advisories
用法: sploitus-search.py <query> [--type exploits|tools] [--limit N]
"""
import json, sys, urllib.request, urllib.parse, urllib.error, ssl

SPLOITUS_API = "https://sploitus.com/search"
SPLOITUS_EXPLOITS = "https://sploitus.com/exploits"
SPLOITUS_TOOLS = "https://sploitus.com/tools"

# Disable SSL verification for pentest environments
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Origin": "https://sploitus.com",
    "Referer": "https://sploitus.com/"
}

def search_sploitus(query, search_type="exploits", limit=10, offset=0):
    """Search Sploitus for exploits or tools"""
    payload = {
        "query": query,
        "sort": "default",
        "title": False,
        "offset": offset,
        "type": search_type
    }
    
    data = json.dumps(payload).encode()
    req = urllib.request.Request(SPLOITUS_API, data=data, headers=HEADERS, method="POST")
    
    try:
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        result = json.loads(resp.read())
        return result
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()[:200]}"}
    except Exception as e:
        return {"error": str(e)}

def format_results(data, search_type="exploits", limit=10):
    """Format search results for display"""
    if "error" in data:
        print(f"Error: {data['error']}")
        return []
    
    results = []
    
    # Handle different response formats
    if isinstance(data, dict):
        items = data.get("exploits", data.get("tools", data.get("results", [])))
    elif isinstance(data, list):
        items = data
    else:
        print(f"Unexpected response format: {type(data)}")
        return []
    
    if not items:
        print("No results found.")
        return []
    
    print(f"=== Sploitus {search_type.title()} Results ===\n")
    for i, item in enumerate(items[:limit]):
        title = item.get("title", item.get("name", "Untitled"))
        source = item.get("source", item.get("platform", ""))
        url = item.get("url", item.get("href", ""))
        date = item.get("published", item.get("date", ""))
        score = item.get("score", item.get("cvss", ""))
        desc = item.get("description", item.get("excerpt", ""))[:150]
        
        print(f"[{i+1}] {title}")
        if source:
            print(f"    Source: {source}")
        if date:
            print(f"    Date: {date}")
        if score:
            print(f"    Score: {score}")
        if url:
            print(f"    URL: {url}")
        if desc:
            print(f"    Desc: {desc}...")
        print()
        
        results.append({
            "title": title,
            "source": source,
            "url": url,
            "date": date,
            "score": score
        })
    
    return results

def cmd_search(args):
    """Main search command"""
    if not args:
        print("Usage: sploitus-search.py <query> [--type exploits|tools] [--limit N]")
        print("\nExamples:")
        print("  sploitus-search.py 'CVE-2024-1234'")
        print("  sploitus-search.py 'apache struts rce' --type exploits --limit 5")
        print("  sploitus-search.py 'sql injection' --type tools")
        sys.exit(1)
    
    query = []
    search_type = "exploits"
    limit = 10
    
    i = 0
    while i < len(args):
        if args[i] == "--type" and i + 1 < len(args):
            search_type = args[i + 1]
            i += 2
        elif args[i] == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])
            i += 2
        else:
            query.append(args[i])
            i += 1
    
    query_str = " ".join(query)
    print(f"Searching Sploitus for: {query_str} (type: {search_type})\n")
    
    data = search_sploitus(query_str, search_type, limit)
    results = format_results(data, search_type, limit)
    
    # Save to file for agent consumption
    output_file = "/tmp/sploitus_results.json"
    with open(output_file, "w") as f:
        json.dump({"query": query_str, "type": search_type, "results": results}, f, indent=2)
    print(f"Results saved to: {output_file}")

def cmd_cve(args):
    """Search by CVE number"""
    if not args:
        print("Usage: sploitus-search.py cve <CVE-ID>")
        sys.exit(1)
    cve_id = args[0]
    cmd_search([cve_id, "--type", "exploits", "--limit", "10"])

def cmd_product(args):
    """Search by product name"""
    if not args:
        print("Usage: sploitus-search.py product <name> [--rce] [--sqli]")
        sys.exit(1)
    query = " ".join(args)
    cmd_search([query, "--type", "exploits", "--limit", "10"])

def cmd_tools(args):
    """Search for offensive security tools"""
    if not args:
        print("Usage: sploitus-search.py tools <vulnerability-type>")
        sys.exit(1)
    query = " ".join(args)
    cmd_search([query, "--type", "tools", "--limit", "10"])

COMMANDS = {
    "search": cmd_search,
    "cve": cmd_cve,
    "product": cmd_product,
    "tools": cmd_tools,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Sploitus漏洞搜索引擎")
        print(f"\nUsage: {sys.argv[0]} <command> [args...]")
        print("\nCommands:")
        print("  search <query> [--type exploits|tools] [--limit N]")
        print("  cve <CVE-ID>")
        print("  product <name>")
        print("  tools <vulnerability-type>")
        sys.exit(0)
    
    cmd = sys.argv[1]
    if cmd in COMMANDS:
        COMMANDS[cmd](sys.argv[2:])
    else:
        # Default: treat as search query
        cmd_search(sys.argv[1:])
