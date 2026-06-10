#!/usr/bin/python3
"""
edu-batch-probe.py - 批量子域探测脚本
解决CERNET/慢网络下串行curl超时问题

用法:
  python3 edu-batch-probe.py subs.txt                    # 默认: 4秒超时, 20并发, 分批
  python3 edu-batch-probe.py subs.txt --timeout 6        # 6秒超时
  python3 edu-batch-probe.py subs.txt --batch 30 --dns   # DNS预过滤 + 30并发
  python3 edu-batch-probe.py subs.txt -o alive.txt       # 输出到文件
  python3 edu-batch-probe.py subs.txt --fingerprint      # 同时做指纹识别

输出格式: CODE SIZE PROTO://DOMAIN [REDIRECT] [TECH]
"""

import sys
import os
import time
import json
import argparse
import socket
import ssl
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed


CACHE_FILE = "/tmp/.probe_cache.json"
CACHE_TTL = 3600


def now():
    return int(time.time())


def load_cache():
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"dns": {}, "http": {}}
        if not isinstance(data.get("dns"), dict):
            data["dns"] = {}
        if not isinstance(data.get("http"), dict):
            data["http"] = {}
        return data
    except Exception:
        return {"dns": {}, "http": {}}


def save_cache(cache):
    try:
        t = now()
        dns = {}
        http = {}

        for k, v in cache.get("dns", {}).items():
            if isinstance(v, dict) and t - int(v.get("time", 0)) <= CACHE_TTL:
                dns[k] = v

        for k, v in cache.get("http", {}).items():
            if isinstance(v, dict) and t - int(v.get("time", 0)) <= CACHE_TTL:
                http[k] = v

        data = {"dns": dns, "http": http}
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, CACHE_FILE)
    except Exception:
        pass


def cache_get(section, key, cache):
    try:
        item = cache.get(section, {}).get(key)
        if not isinstance(item, dict):
            return False, None
        if now() - int(item.get("time", 0)) > CACHE_TTL:
            return False, None
        return True, item.get("result")
    except Exception:
        return False, None


def dns_check(sub, timeout, cache):
    key = sub.lower()
    hit, result = cache_get("dns", key, cache)
    if hit:
        return result, None

    result = None
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(sub, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if infos:
            ip = infos[0][4][0]
            result = [sub, ip]
    except Exception:
        result = None
    finally:
        try:
            socket.setdefaulttimeout(old_timeout)
        except Exception:
            pass

    return result, (key, {"time": now(), "result": result})


def dns_filter(subs, timeout=2, workers=10, cache=None):
    alive = []
    updates = []
    cache = cache or {"dns": {}, "http": {}}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(dns_check, s, timeout, cache) for s in subs]
        for f in as_completed(futures):
            try:
                result, update = f.result()
                if update:
                    updates.append(update)
                if result:
                    alive.append(result)
            except Exception:
                pass

    return alive, updates


def extract_tech(headers, sub):
    techs = []
    seen = set()
    all_headers = []

    try:
        for k, v in headers:
            line = "%s: %s" % (k, v)
            all_headers.append(line)
            kl = k.lower().strip()
            vl = str(v).strip()

            if kl == "server":
                srv = vl.strip()
                if srv and srv != "*********" and srv.lower() != "server":
                    item = "S:%s" % srv
                    if item not in seen:
                        seen.add(item)
                        techs.append(item)

            elif kl == "x-powered-by":
                xpb = vl.strip()
                if xpb:
                    item = "XPB:%s" % xpb
                    if item not in seen:
                        seen.add(item)
                        techs.append(item)
    except Exception:
        pass

    h = "\n".join(all_headers).lower()

    if "jsessionid" in h and "Java" not in seen:
        seen.add("Java")
        techs.append("Java")
    if "phpsessid" in h and "PHP" not in seen:
        seen.add("PHP")
        techs.append("PHP")

    return ",".join(techs)


def redirect_url(proto, host, location):
    if not location:
        return ""
    loc = location.strip()
    low = loc.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return loc
    if loc.startswith("//"):
        return proto + ":" + loc
    if loc.startswith("/"):
        return "%s://%s%s" % (proto, host, loc)
    return "%s://%s/%s" % (proto, host, loc)


def http_request(proto, sub, timeout, fingerprint):
    headers = {
        "Host": sub,
        "User-Agent": "curl/7.68.0",
        "Connection": "close",
    }

    conn = None
    try:
        if proto == "https":
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(
                sub,
                443,
                timeout=timeout,
                context=ctx,
            )
        else:
            conn = http.client.HTTPConnection(sub, 80, timeout=timeout)

        conn.request("GET", "/", headers=headers)
        resp = conn.getresponse()

        body = resp.read()
        code = str(resp.status)
        size = str(len(body))
        resp_headers = resp.getheaders()

        loc = ""
        for k, v in resp_headers:
            if k.lower() == "location":
                loc = redirect_url(proto, sub, v)
                break

        tech = extract_tech(resp_headers, sub) if fingerprint else ""
        return [sub, proto, code, size, loc, tech]
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def probe(sub, timeout=4, fingerprint=False, cache=None):
    cache = cache or {"dns": {}, "http": {}}
    key = "%s|%s|%s" % (sub.lower(), str(timeout), "1" if fingerprint else "0")

    hit, result = cache_get("http", key, cache)
    if hit:
        return result, None

    result = None

    for proto in ("https", "http"):
        try:
            r = http_request(proto, sub, timeout, fingerprint)
            if r and r[2] and r[2] != "000":
                result = r
                break
        except Exception:
            pass

    return result, (key, {"time": now(), "result": result})


def format_result(r):
    sub, proto, code, size, redir, tech = r
    parts = [str(code), str(size), "%s://%s" % (proto, sub)]
    if redir:
        parts.append(str(redir))
    if tech:
        parts.append(str(tech))
    return " ".join(parts)


def read_subs(path):
    subs = []
    seen = set()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            s = s.rstrip("/")
            if "://" in s:
                s = s.split("://", 1)[1].split("/", 1)[0]
            else:
                s = s.split("/", 1)[0]
            if not s or s in seen:
                continue
            seen.add(s)
            subs.append(s)

    return subs


def main():
    parser = argparse.ArgumentParser(
        description="edu-batch-probe.py - 批量子域探测脚本"
    )
    parser.add_argument("input", help="子域名列表文件")
    parser.add_argument("--timeout", type=float, default=4, help="HTTP超时秒数，默认4")
    parser.add_argument("--batch", type=int, default=20, help="并发数，默认20")
    parser.add_argument("--dns", action="store_true", help="启用DNS预过滤")
    parser.add_argument("-o", "--output", help="输出文件")
    parser.add_argument("--fingerprint", action="store_true", help="提取响应头指纹")
    args = parser.parse_args()

    try:
        subs = read_subs(args.input)
    except Exception as e:
        print("读取输入文件失败: %s" % e, file=sys.stderr)
        sys.exit(1)

    if not subs:
        sys.exit(0)

    workers = max(1, int(args.batch))
    cache = load_cache()
    dns_updates = []
    http_updates = []

    if args.dns:
        alive, dns_updates = dns_filter(
            subs,
            timeout=min(float(args.timeout), 2.0),
            workers=workers,
            cache=cache,
        )
        subs = [x[0] for x in alive]

    results = []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(probe, s, float(args.timeout), args.fingerprint, cache) for s in subs]
        for f in as_completed(futures):
            try:
                result, update = f.result()
                if update:
                    http_updates.append(update)
                if result:
                    line = format_result(result)
                    results.append(line)
                    if not args.output:
                        print(line, flush=True)
            except Exception:
                pass

    for k, v in dns_updates:
        cache.setdefault("dns", {})[k] = v
    for k, v in http_updates:
        cache.setdefault("http", {})[k] = v

    save_cache(cache)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                for line in results:
                    f.write(line + "\n")
        except Exception as e:
            print("写入输出文件失败: %s" % e, file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()