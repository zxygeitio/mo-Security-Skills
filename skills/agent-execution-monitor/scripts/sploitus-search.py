#!/usr/bin/env python3
"""
Sploitus漏洞搜索引擎集成
聚合 ExploitDB + Packet Storm + GitHub Security Advisories
用法: sploitus-search.py <query> [--type exploits|tools] [--limit N]

注意: Sploitus 使用 Cloudflare 保护，直接 API 调用可能返回 403。
Fallback: 用 browser 工具访问 https://sploitus.com/ 手动搜索。
"""
import json, sys, os, urllib.request, urllib.parse, urllib.error, ssl

SPLOITUS_API = "https://sploitus.com/search"

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
    payload = {"query": query, "sort": "default", "title": False, "offset": offset, "type": search_type}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(SPLOITUS_API, data=data, headers=HEADERS, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()[:200]}"}
    except Exception as e:
        return {"error": str(e)}

def format_results(data, search_type="exploits", limit=10):
    if "error" in data:
        print(f"Error: {data['error']}"); return []
    items = data.get("exploits", data.get("tools", data.get("results", []))) if isinstance(data, dict) else data
    if not items: print("No results found."); return []
    print(f"=== Sploitus {search_type.title()} Results ===\n")
    results = []
    for i, item in enumerate(items[:limit]):
        title = item.get("title", item.get("name", "Untitled"))
        source = item.get("source", item.get("platform", ""))
        url = item.get("url", item.get("href", ""))
        date = item.get("published", item.get("date", ""))
        score = item.get("score", item.get("cvss", ""))
        desc = item.get("description", item.get("excerpt", ""))[:150]
        print(f"[{i+1}] {title}")
        if source: print(f"    Source: {source}")
        if date: print(f"    Date: {date}")
        if score: print(f"    Score: {score}")
        if url: print(f"    URL: {url}")
        if desc: print(f"    Desc: {desc}...")
        print()
        results.append({"title": title, "source": source, "url": url, "date": date, "score": score})
    return results

def cmd_search(args):
    if not args:
        print("Usage: sploitus-search.py <query> [--type exploits|tools] [--limit N]"); sys.exit(1)
    query, search_type, limit, i = [], "exploits", 10, 0
    while i < len(args):
        if args[i] == "--type" and i+1 < len(args): search_type = args[i+1]; i += 2
        elif args[i] == "--limit" and i+1 < len(args): limit = int(args[i+1]); i += 2
        else: query.append(args[i]); i += 1
    query_str = " ".join(query)
    print(f"Searching Sploitus for: {query_str} (type: {search_type})\n")
    data = search_sploitus(query_str, search_type, limit)
    results = format_results(data, search_type, limit)
    output_file = "/tmp/sploitus_results.json"
    with open(output_file, "w") as f:
        json.dump({"query": query_str, "type": search_type, "results": results}, f, indent=2)
    print(f"Results saved to: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Sploitus漏洞搜索引擎\nUsage: sploitus-search.py <query> [--type exploits|tools] [--limit N]")
        sys.exit(0)
    cmd_search(sys.argv[1:])
