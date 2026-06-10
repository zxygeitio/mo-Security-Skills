# Casdoor SSO + One API Gateway Testing Patterns

## Casdoor SSO Fingerprinting

Casdoor is an open-source SSO/IAM system built on Casbin. Widely deployed in Chinese SaaS/enterprise.

### Fingerprint Indicators
- HTML: `<link rel="apple-touch-icon" href="https://cdn.casbin.org/img/favicon.png">`
- JS: `main.e025e02b.js` (version-specific hash)
- API responses: `{"status":"error","msg":"Unauthorized operation"}`
- OIDC well-known: `/.well-known/openid-configuration` returns full OAuth2 config
- Server: Tengine (Alibaba Cloud) common but not required

### Key API Endpoints (all return JSON, require auth unless noted)
```
GET  /.well-known/openid-configuration    # PUBLIC - full OIDC config
GET  /.well-known/jwks                     # PUBLIC - RSA signing keys + x5c certs
GET  /api/get-users                        # Requires auth
GET  /api/get-applications                 # Requires auth
GET  /api/get-organizations                # Requires auth
GET  /api/get-roles                        # Requires auth
GET  /api/get-resources                    # Requires auth
GET  /api/get-user-count                   # Requires auth
GET  /api/get-version                      # Requires auth
GET  /api/get-account                      # "Please login first"
POST /api/login                            # Login endpoint
POST /api/login/oauth/access_token         # OAuth token endpoint
GET  /api/userinfo                         # Requires auth token
POST /api/logout                           # Logout
POST /api/signup                           # Registration (if enabled)
```

### OIDC Configuration Analysis
The /.well-known/openid-configuration reveals:
- `grant_types_supported`: If "password" is listed, direct token acquisition with credentials
- `claims_supported`: Look for `isAdmin`, `isForbidden`, `ldap` (internal role indicators)
- `request_object_signing_alg_values_supported`: HS256/HS384/HS512 (symmetric, weaker than RS256)
- `response_types_supported`: "none" type may allow token-less flows

### JWKS Certificate Analysis
x5c certificates reveal:
- CN/O fields: Internal CA identity (e.g., CN=cert-built-in, O=admin)
- Validity dates: Long-lived certs (20 years) indicate no rotation policy
- kid values: Key management naming conventions

### Login Password Encoding
Casdoor expects passwords in specific encoding. The error "illegal base64 data at input byte 4" indicates the password field is processed through base64 decoding. Try:
1. Plain text (may work on older versions)
2. Base64-encoded (standard btoa)
3. The frontend JS handles encoding - check `main.*.js` for the exact method

### Attack Vectors
1. **Information Disclosure**: OIDC config + JWKS expose internal infrastructure
2. **Password Grant**: If supported, direct token acquisition with stolen credentials
3. **User Enumeration**: Login error messages may differ for valid/invalid users
4. **Default Credentials**: admin/123, admin/admin (Casdoor defaults)
5. **Registration Abuse**: If signup enabled without CAPTCHA/email verification
6. **OAuth Client ID Leak**: Check docs site sitemap.xml — client_id may appear in OAuth callback URLs embedded in documentation pages (e.g., `client_id=cb4dcdeb3113cfd834b4` found in docs.alayanew.com sitemap content)

## One API Gateway (AI Model Proxy)

One API is an open-source OpenAI-compatible API gateway. Used for aggregating multiple LLM providers.

### Fingerprint Indicators
- Error: `{"error":{"message":"未提供令牌 (request id: ...)","type":"one_api_error"}}`
- Error: `{"error":{"message":"无效的令牌 (request id: ...)","type":"one_api_error"}}`
- Error: `{"error":{"message":"Invalid URL (GET /api/config)","type":"invalid_request_error"}}`
- Title: "Alaya Code" or similar AI platform branding
- API paths: /v1/chat/completions, /v1/models (OpenAI-compatible)

### Key API Endpoints
```
GET  /api/status                           # PUBLIC - FULL SYSTEM CONFIG (CRITICAL!)
GET  /api/user/self                        # Requires auth
POST /api/user/register                    # May be public (check config)
POST /api/user/login                       # Login
GET  /v1/models                            # Requires Bearer token
POST /v1/chat/completions                  # Requires Bearer token
POST /anthropic/v1/messages                # Anthropic-compatible endpoint
```

### /api/status Information Disclosure (CRITICAL)
Returns full system configuration without authentication:
```json
{
    "data": {
        "backend_url": "https://...",
        "oidc_client_id": "...",
        "oidc_authorization_endpoint": "...",
        "password_login_enabled": true,
        "password_register_enabled": true,
        "email_verification": false,
        "turnstile_check": false,
        "tenant_admin_whitelist": "UUID",
        "quota_per_unit": 500000,
        "server_address": "https://...",
        "system_name": "...",
        "oss_url": "https://..."
    }
}
```

Key fields to report:
- `tenant_admin_whitelist`: Admin UUID - can be used for targeted attacks
- `oidc_client_id`: OAuth client ID for SSO integration
- `password_register_enabled` + `email_verification: false` + `turnstile_check: false`: Open registration without verification
- `backend_url`: Internal backend address
- `quota_per_unit`: Resource allocation per user

### Open Registration Attack
When `password_register_enabled: true` + `email_verification: false` + `turnstile_check: false`:
```bash
# Register
curl -sk -X POST "https://TARGET/api/user/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"Test123!","email":"test@test.com"}'
# Response: {"message":"","success":true}

# Login
curl -sk -X POST "https://TARGET/api/user/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"Test123!"}'
# Response: full user object with id, role, status, quota
```

### Report Template for /api/status Disclosure
Title: `*.alayanew.com站xxx子站API接口存在未授权配置信息泄露漏洞`
Type: 信息泄露
Severity: 中危
Evidence: Full JSON response from /api/status

### Report Template for Open Registration
Title: `*.alayanew.com站xxx子站存在任意用户注册漏洞`
Type: 逻辑漏洞
Severity: 中危
Evidence: Registration + login + user object returned

## CORS Double-Header Pattern (Unusual)

Some servers return TWO Access-Control-Allow-Origin headers:
```
access-control-allow-origin: https://evil.com   (reflected)
access-control-allow-origin: *                   (wildcard)
```

This is unusual and indicates misconfigured middleware (likely Spring Boot with both a CORS filter and a gateway adding wildcard). Without `Access-Control-Allow-Credentials: true`, browsers use the wildcard `*` and the reflected origin is ignored. However:

1. The reflection behavior indicates the server processes and trusts the Origin header
2. If credentials support is added later, the reflection becomes exploitable
3. The dual-header pattern is itself a configuration error worth reporting as low-severity

### Testing
```bash
curl -sk -D- -H "Origin: https://evil.com" "https://TARGET/api/" | grep -i 'access-control'
# Look for: reflected origin + wildcard + absence of credentials header
```

## Tool Notes

### httpx Binary Conflict
System may have Python `httpx` at `/usr/bin/httpx` (pip package) conflicting with ProjectDiscovery's `httpx` at `~/go/bin/httpx`. The hexstrike `httpx_scan` MCP tool uses the Python version (wrong). 

Workaround:
```bash
# Use hexstrike_command with explicit path
~/go/bin/httpx -u https://TARGET -sc -title -td -timeout 10

# Or use curl via hexstrike_command
curl -sk -m 10 "https://TARGET/path"
```

### amass Subcommand
amass v4 requires explicit subcommand: `amass enum -passive -d domain.com`
The hexstrike amass_scan tool may not pass the correct subcommand format.
