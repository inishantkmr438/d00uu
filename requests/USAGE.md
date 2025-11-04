# Requests → Payload list mapping

- ssrf_json_example.txt, ssrf_form_example.txt, ssrf_get_proxy_example.txt
  - Position: §URL§ → load payloads/ssrf_urls.txt
  - Optional headers: payloads/ssrf_headers.txt (add in Repeater when needed)
  - Indicators: OAST/Collaborator hits, status/time deltas, metadata responses

- ssti_get_example.txt, ssti_post_json_example.txt
  - Position: §SSTI§ → load payloads/ssti_payloads.txt
  - Indicators: arithmetic evaluates (e.g., 49), template error messages

- lfi_get_example.txt, lfi_post_json_example.txt, traversal_download_get_example.txt
  - Position: §PATH§ → load payloads/path_traversal.txt (and lfi_wrappers.txt as secondary)
  - Grep-Match: `root:x:`, `127.0.0.1`, typical config keys
  - Try targets from payloads/lfi_targets.txt

- rfi_get_example.txt
  - Position: §URL§ → load payloads/rfi_urls.txt
  - Indicators: body includes remote content; OAST/Collaborator hits

Tips
- Start with Repeater for safety; then Intruder with low rate. Use Comparer on baseline vs payload.
- Record Set-Cookie and any redirects; watch for cache-control and CSP interactions.
