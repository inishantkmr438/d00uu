# SSRF, SSTI, LFI/RFI, and Path Traversal – How-To Steps (Burp)

This guide provides actionable steps and payloads to test SSRF, SSTI, LFI/RFI, and traversal. Pair steps with payload lists in `burp/payloads/`.

## 1) SSRF (Server-Side Request Forgery)
- Discover
  - Find features that fetch URLs: image fetch/import, webhooks, URL preview, PDF/renderers, OAuth callbacks.
- Baseline
  - Send a valid public URL; note status, time, and response size. Then send internal/edge URLs.
- Probing (use `payloads/ssrf_urls.txt`)
  - Local/internal: 127.0.0.1, [::1], 10/172/192 ranges.
  - Metadata: 169.254.169.254 (AWS), metadata.google.internal (add header `Metadata-Flavor: Google`), Azure metadata (add `Metadata: true`).
  - Out-of-band: replace `{{COLLAB}}` with a Burp Collaborator domain; watch DNS/HTTP hits.
  - Scheme tricks: file://, gopher://, ftp:// (only in safe environments).
- Header/host tricks (use `payloads/ssrf_headers.txt`)
  - Add `X-Forwarded-For: 127.0.0.1`, change `Host` to target metadata IP, try `X-Original-URL`.
- Blind SSRF indicators
  - Timeouts vs fast responses; different error messages; Collaborator interactions.
- Expected secure behavior
  - Scheme/host allowlist, DNS pinning, no internal access, metadata endpoints blocked.

## 2) SSTI (Server-Side Template Injection)
- Discover
  - Inputs reflected into server-rendered views: search, profile names, notifications, email templates.
- Detect (use `payloads/ssti_payloads.txt`)
  - Try non-intrusive arithmetic markers: `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%=7*7%>`; expect `49` only if interpreted.
  - Compare with escaped variants or literal display to avoid false positives.
- Triaging
  - Identify engine by which payload evaluates; restrict to read-only probes.
- Expected secure behavior
  - Templates treat user input as data, not code; auto-escaping or safe rendering.

## 3) LFI (Local File Inclusion) & Path Traversal
- Discover
  - Parameters likely to reference files/paths: `file`, `template`, `include`, `page`, `report`, image thumbnailers.
- Traversal payloads (use `payloads/path_traversal.txt`)
  - Unix: `../../../../etc/passwd`, encoded/double-encoded variants, mixed slashes.
  - Windows: `..\..\..\Windows\win.ini`, `%255c` encoded backslashes.
- Targets (use `payloads/lfi_targets.txt`)
  - `/etc/passwd` (look for `root:x:`), `/etc/hosts`, `/proc/self/environ`, app configs like `/.env`.
- Wrappers/tricks (use `payloads/lfi_wrappers.txt`)
  - `php://filter/convert.base64-encode/resource=index.php` to exfil source as base64.
  - `file://` URLs for absolute paths; `zip://` where zip ingestion exists.
- Techniques
  - Test null-byte terminator (`%00`) with an expected extension (legacy PHP); try stripping appended `.php` by traversal.
  - Try duplicate param (HPP) to influence which value is used.
- Expected secure behavior
  - Canonicalization and allowlist of server-side paths; ignore traversal sequences; no direct file serving.

## 4) RFI (Remote File Inclusion)
- Discover
  - Same parameters as LFI but accepting full URLs; legacy PHP settings (`allow_url_include`).
- Payloads (use `payloads/rfi_urls.txt`)
  - `http://{{COLLAB}}/rfi.txt` to detect fetch; `https://example.com/robots.txt` for harmless test.
  - `data:text/plain,OK` to test scheme acceptance.
- Steps
  - Switch local path to remote URL; observe server fetching/including response; check response body changes, headers, errors.
  - Use Collaborator to confirm outbound request.
- Expected secure behavior
  - Disallow remote schemes; fetch-on-server done via safe proxy with allowlist.

## General Burp Workflow
- Repeater
  - Keep clean session; test each param separately; toggle encodings; record timing and content-length.
- Intruder
  - Set positions around target param; load matching payload list; start slow, then throttle up; Grep-Match success markers (e.g., `root:x:`) and Grep-Extract snippets.
- Comparer
  - Compare baseline vs payload responses for small diffs.

## Evidence to capture
- Full request/response, timing, and Collaborator logs; matched payload and value; snippet proving inclusion/evaluation.
