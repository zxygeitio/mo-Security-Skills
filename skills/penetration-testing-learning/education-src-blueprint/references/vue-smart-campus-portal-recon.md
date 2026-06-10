# MDit education portal reconnaissance pattern (2026-05-21)

Use this as a reusable pattern for Vue/webpack smart-campus portals where the public landing page hides the real API map in lazy chunks.

Target class:
- Chinese education/smart-campus portals using Vue SPA + CAS/IdP + multiple micro-frontends.
- Frontend exposes `main.html`, `envConfig.js`, `remoteEntry.js`, and many lazy chunk IDs.

Case signals from mdit.edu.cn:
- `portal.mdit.edu.cn/main.html` loaded many `/js/commons~*.js` and `/js/main.*.js` chunks.
- The webpack runtime mapped chunk `7923` to `js/envConfig.js`.
- `envConfig.js` exposed business API hosts and internal/OA links, including:
  - `portal-api`, `message-service`, `authx-service`, `formflow`, `transaction`, `address-book`, `portal-data`, `admin-platform`, `evaluation-center`, `portal-center-remote`.
  - an internal OA-style link: `http://192.168.100.10:7001/defaultroot/desktop.jsp`.
- Several discovered service hosts resolved to `198.18.0.x`; treat this as an exposed routed/internal range signal, not as proof of vulnerability.
- Several APIs reflected arbitrary Origin with `Access-Control-Allow-Credentials: true`, but unauthenticated responses were only `401/403`, so this was not reportable as high-value without logged-in sensitive-data read.

Workflow:
1. Fetch landing page and force the real app page if the root only shows browser checks:
   `curl -sk https://portal.TARGET/main.html -o main.html`
2. Extract direct JS refs:
   `grep -oE 'src="[^"]+\.js"' main.html`
3. Inspect the webpack runtime for chunk name maps. Look specifically for:
   - `t.u=function(e)`
   - `envConfig.js`
   - chunk ID arrays in `Promise.all([t.e(...)])`
4. Download `envConfig.js` directly if exposed:
   `curl -sk https://portal.TARGET/js/envConfig.js`
5. Extract hosts and API bases:
   `grep -aoE 'https?://[^",\\]+' envConfig.js | sort -u`
6. Probe each newly discovered host with low-impact checks only:
   - `/`, `/robots.txt`, `/actuator/env`, `/v2/api-docs`, `/v3/api-docs`, `/swagger-ui.html`, `/.env`, `/.git/HEAD`
   - For SPA hosts, detect fallback by comparing response size/body with a random non-existent path.
7. Test CORS on API endpoints that return JSON:
   `curl -skI 'https://api.TARGET/path' -H 'Origin: https://evil.example'`
8. Only escalate/report CORS if a logged-in browser PoC can read actual sensitive data cross-origin. If no credentials/session or only `401/403`, record as a hardening note or deepening lead, not a high-value SRC report.
9. If `envConfig.js` exposes internal OA links (e.g. `defaultroot/desktop.jsp`, `seeyon`, `weaver`, `e-cology`), pivot to finding public mappings or JS-hardcoded REST token credentials. Do not submit “internal URL exposed” alone unless combined with usable access or credentials.

Reporting boundary:
- Do not submit SPA fallback 200s as exposed endpoints.
- Do not submit arbitrary-Origin CORS alone when unauthenticated responses are `401/403` and no sensitive data is readable.
- Do not submit frontend internal-host maps alone as high/medium. Use them as a lead for API auth bypass, IDOR, OA token leakage, or logged-in CORS exfiltration.

Useful evidence commands:
- `curl -sk 'https://portal.TARGET/js/envConfig.js' | grep -aoE 'https?://[^",\\]+' | sort -u`
- `curl -skI 'https://message-service.TARGET/center/api/v1/messageCenter/listMessageRecordCount' -H 'Origin: https://evil.example'`
- `curl -sk 'https://message-service.TARGET/center/api/v1/messageCenter/listMessageRecordCount' -H 'Origin: https://evil.example'`

Decision:
- If no logged-in sensitive data, final answer should say no submit-ready high-value vulnerability was verified, and list the leads separately.
