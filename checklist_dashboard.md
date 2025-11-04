# Post-Login Dashboard Security Checklist (Web App)

Scope: Run after successful login, focusing on authenticated areas (dashboard, profile, settings, admin, APIs, WebSockets).
Use Burp Proxy, Repeater, Intruder, and Comparer. Maintain a clean baseline session.

## 1) Session Management
- Test
  - Verify session rotation on login and on privilege change; logout invalidates session.
  - Check cookie flags: Secure, HttpOnly, SameSite (Lax/Strict), narrow Domain/Path.
  - Idle timeout, absolute timeout, re-auth for sensitive actions (password/MFA change).
- How
  - Observe Set-Cookie before/after login; try using pre-login token on authenticated endpoints.
  - After logout, replay an earlier authenticated request.
- Expected: New session on login; old token invalid after logout; secure flags present; timeouts enforced.
- Vulns: Session fixation, missing flags, session reuse after logout.

## 2) Authorization (Access Control)
- Test
  - VERTICAL: role-restricted endpoints (admin-only) using non-admin.
  - HORIZONTAL (IDOR/BOLA): change object IDs (userId, accountId, orderId) in URLs/JSON.
  - Mass assignment: submit extra fields (isAdmin, role, ownerId) in update calls.
- How
  - Repeater: replace IDs, remove server-generated fields, add sensitive fields.
  - For APIs, try GET/PUT/DELETE other users’ resources.
- Expected: 403 for unauthorized; ignores/strips sensitive fields.
- Vulns: IDOR, privilege escalation, mass assignment.

## 3) CSRF on state-changing endpoints
- Test
  - POST/PUT/PATCH/DELETE endpoints from another origin without CSRF token.
  - JSON and XHR endpoints; check token binding (per-session, per-request).
- How
  - Build a simple HTML form or use Burp CSRF PoC generator; strip tokens in Repeater.
- Expected: Rejected without valid CSRF token/origin; tokens rotate and are verified server-side.
- Vulns: CSRF-able actions, token not validated, missing SameSite.

## 4) Stored/Reflected/DOM XSS
- Test
  - Inputs that render on dashboard: profile name, comments, messages, search, filters, activity feeds.
  - DOM sinks (innerHTML, document.write, location.hash usage).
- Payloads
  - Basic: <img src=x onerror=alert(1)>
  - Attribute break: "><svg/onload=alert(1)>
  - Event: </script><script>alert(1)</script>
- Expected: Output encoded per context; CSP with nonces/hashes blocks inline.
- Vulns: Stored XSS in widgets, reflected in filters, DOM XSS via client-side templating.

## 5) Injection in Queries/Templates
- Test
  - SQLi/NoSQLi in search, filters, reporting; Template/EL injection in server-side templating.
- Payloads
  - SQLi: ' OR '1'='1 --, ") OR 1=1--, ' AND SLEEP(2)--
  - NoSQLi: {"$ne":""}, admin'||'1'=='1
  - SSTI (Jinja2/Twig/Velocity): {{7*7}}, ${7*7}, {{config.items()}}, #{7*7}
- Expected: Parameterized queries; templates treat payload as text; WAF not the only control.
- Vulns: Authenticated SQLi/NoSQLi, SSTI leading to RCE.

## 6) File Uploads
- Test
  - Extension filtering, magic bytes, double extensions, path traversal in filenames, SVG/HTML images, size limits, AV scanning.
- Payloads
  - Filename: avatar.php, avatar.php.jpg, ..%2f..%2fwebroot%2favatar.png
  - SVG with script, polyglot images (PNG+JS), PDF with JS.
- Expected: Validates content-type by sniffing magic bytes; stores outside webroot; random names; blocks active content.
- Vulns: RCE via upload, stored XSS via SVG, upload to webroot, traversal.

## 7) SSRF / URL Callbacks
- Test
  - Features: webhook URLs, image import, PDF fetchers, integrations.
- Payloads
  - http://127.0.0.1:80/, http://[::1]/, http://169.254.169.254/, http://metadata.google.internal/
  - http://attacker.tld:8080/ (observe egress), file:///etc/passwd, gopher://, ftp://
- Expected: Allowlist of schemes/hosts, DNS pinning, no internal access, request signing where applicable.
- Vulns: SSRF to internal services/metadata endpoints.

## 8) Open Redirects (Post-login navigation)
- Test returnUrl/next/redirect parameters on in-app links.
- Payloads: //attacker.tld, https://attacker.tld, /%2f%2fattacker.tld
- Expected: Same-origin relative-only, strict allowlist.
- Vulns: redirect to attacker with session-bearing Referer.

## 9) CORS
- Test
  - Check Access-Control-Allow-Origin and -Credentials; wildcard with credentials.
- How
  - Send Origin: https://attacker.tld in Repeater.
- Expected: Specific origins only; no * with credentials.
- Vulns: Cross-origin data exfil with cookies.

## 10) Clickjacking
- Test frameability of dashboard and sensitive forms.
- Expected: X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.
- Vulns: UI redress on money transfer/settings.

## 11) Security Headers
- Check
  - HSTS (includeSubDomains, preload), CSP (no 'unsafe-inline'), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Download-Options.
- Expected: Present and strict.
- Vulns: Missing/weak policies enabling exploit chains.

## 12) Caching and Sensitive Data
- Test
  - Cache-Control: no-store on authenticated pages and downloads with secrets.
  - Reverse proxy caches (ETag/Vary correctness); cache key poisoning.
- Expected: No caching of personalized pages; correct Vary.
- Vulns: Cache leaks of private data, cache poisoning.

## 13) API / GraphQL / WebSockets
- Test
  - Discover API endpoints from dashboard; check method auth per resource.
  - GraphQL: introspection, field-level auth, batching/aliasing DoS.
  - WebSockets: auth at connect and per message; input validation.
- Payloads
  - GraphQL introspection: {__schema{types{name}}}
  - Deep nesting query; alias abuse.
- Expected: Proper auth; introspection disabled in prod; rate-limited.
- Vulns: BOLA/IDOR, information disclosure, DoS.

## 14) JWT/OAuth/SSO Artifacts
- Test
  - JWT header alg none/HS256 with server public key, expired token acceptance, token reuse after logout, weak kid tricks.
  - OAuth redirect_uri allowlist, state/nonce/PKCE enforcement; token in URL leaked via Referer.
- Expected: Strong signature check, exp/iat/aud validated, rotation on privilege change.
- Vulns: Token forgery, replay, open redirect in OAuth.

## 15) Rate Limiting / DoS on Authenticated Actions
- Test bulk create/update/delete, export/report generation, search with heavy filters.
- Expected: 429 or async job with quotas.
- Vulns: Unbounded operations, server-side heavy queries.

## 16) Business Logic
- Test
  - Money/points transfers, discounts/coupons, order price tampering, double-submit/race conditions, approval bypass, limit circumvention.
- How
  - Modify hidden fields, repeat steps out of order, replay final step, parallel requests (race).
- Expected: Server-side state machine and invariants enforced.
- Vulns: Fraud, over-credit, coupon reuse, race success.

## 17) Data Export / CSV Injection
- Test
  - Exported CSV/Excel fields starting with =, +, -, @, and formula payloads.
- Payloads
  - =HYPERLINK("http://attacker.tld","x")
  - =cmd|' /C calc'!A0
- Expected: Sanitized (prefix apostrophe or encode), safe MIME types.
- Vulns: Spreadsheet formula injection leading to RCE/phishing.

## 18) Privacy / PII Exposure
- Test search/autocomplete endpoints for enumeration; profile endpoints for excessive data.
- Expected: Minimal necessary data; rate-limited.
- Vulns: User enumeration, PII leakage.

## 19) Client-side Storage / Source Exposure
- Test
  - localStorage/sessionStorage/IndexedDB for tokens/PII; readable source maps (*.map) for secrets; .env leakage.
- Expected: No secrets in client storage; source maps removed in prod.
- Vulns: Token theft, key exposure.

## 20) Service Workers / Caches
- Test
  - Scope of service worker; cached authenticated content; offline leakage.
- Expected: Sensitive content not cached; proper cache-busting and scoping.
- Vulns: Offline cache of private data, SW hijack scope.

## 21) Logging & Monitoring
- Test
  - Critical actions logged; tamper evident IDs; no sensitive data in logs.
- Expected: Audit trails without PII secrets.
- Vulns: Missing logs, leakage via logs.

## 22) Error Handling
- Test malformed JSON, missing fields, unexpected types on authenticated endpoints.
- Expected: 4xx with generic messages; no stack traces.
- Vulns: Error details, differential behavior.

## 23) Multi-tenant Isolation (if applicable)
- Test cross-tenant access by changing tenantId/orgId headers/fields.
- Expected: Strong tenant scoping enforced server-side.
- Vulns: Cross-tenant data access.

---
Tips
- Use Burp Comparer to normalize/compare responses for enumeration and cache testing.
- Use Intruder throttling to probe rate limits safely.
- Record every finding with: endpoint, request, response diff, expected vs actual, and impact.
