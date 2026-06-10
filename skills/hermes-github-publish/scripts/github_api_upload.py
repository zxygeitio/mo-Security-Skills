#!/usr/bin/env python3
"""GitHub API-based file upload - bypasses git push auth issues.
Use when fine-grained PAT lacks git push permission but has Contents:write.

Usage:
  1. Write token to /tmp/.gh_token.txt
  2. python3 github_api_upload.py <owner/repo> <local_dir>
  3. rm -f /tmp/.gh_token.txt  # cleanup!
"""
import urllib.request, json, base64, os, sys

def api(token, method, path, data=None):
    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/json",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"https://api.github.com{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        raise Exception(f"HTTP {e.code}: {err[:200]}")

def upload_repo(repo, local_dir, token):
    # Get file list from git
    import subprocess
    result = subprocess.run(["git", "ls-files"], capture_output=True, text=True, cwd=local_dir)
    files = [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
    
    print(f"Uploading {len(files)} files to {repo}...")
    uploaded, failed = 0, 0
    
    for i, filepath in enumerate(files):
        full_path = os.path.join(local_dir, filepath)
        if not os.path.isfile(full_path):
            continue
        try:
            with open(full_path, 'rb') as f:
                content_b64 = base64.b64encode(f.read()).decode()
            
            payload = {"message": f"feat: add {filepath}", "content": content_b64, "branch": "main"}
            
            # Check if file exists (update vs create)
            try:
                existing = api(token, "GET", f"/repos/{repo}/contents/{filepath}")
                payload["sha"] = existing["sha"]
            except:
                pass
            
            api(token, "PUT", f"/repos/{repo}/contents/{filepath}", payload)
            uploaded += 1
            if (i+1) % 10 == 0:
                print(f"  [{i+1}/{len(files)}]")
        except Exception as e:
            failed += 1
            print(f"  FAIL {filepath}: {str(e)[:80]}")
    
    print(f"\nDone: {uploaded} uploaded, {failed} failed")
    print(f"https://github.com/{repo}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 github_api_upload.py <owner/repo> <local_dir>")
        sys.exit(1)
    
    token_file = "/tmp/.gh_token.txt"
    if not os.path.exists(token_file):
        print(f"Write token to {token_file} first!")
        sys.exit(1)
    
    with open(token_file) as f:
        token = f.read().strip()
    
    repo = sys.argv[1]
    local_dir = sys.argv[2]
    
    # Verify token
    user = api(token, "GET", "/user")
    print(f"Authenticated as: {user['login']}")
    
    upload_repo(repo, local_dir, token)
