# Login & OTP Input Validation Checklist (Burp)

## Setup
- Proxy browser through Burp, capture baseline login and OTP requests.
- Send to Repeater and Intruder. Ensure HTTPS interception works. Keep one clean session.

## Repeater (baseline/edge cases)
- Try wrong Content-Type (toggle form/json), missing fields, and type variants from payload lists.
- Observe: status, body length/hash, headers (Set-Cookie rotation), and error text uniformity.

## Intruder: Login
- Load `burp/requests/login_form_example.txt` or JSON variant; mark §USERNAME§ and §PASSWORD§.
- Modes:
  - Sniper on USERNAME with `payloads/login_sqli.txt`, `login_nosqli.txt`, `login_ldapi.txt`, `login_xpathi.txt`, `login_xss_echo.txt`.
  - Pitchfork on USERNAME+PASSWORD: combine `encoding_tricks.txt` with safe defaults.
  - Cluster Bomb for credential spraying (if allowed).
- Grep-Match: Invalid, does not exist, locked, success tokens (e.g., "Welcome", JWT regex), 500, trace.
- Grep-Extract: Set-Cookie, auth tokens. Check session rotation post-login.
- Rate limit: throttle 1–3 rps; then burst to trigger 429/lockout; observe consistency.

## Intruder: OTP
- Load `burp/requests/otp_form_example.txt` or JSON variant; mark §OTP§ (+ binders like §USERNAME§/§TXID§ if needed).
- Modes:
  - Sniper on OTP with `payloads/otp_formats.txt`.
  - Cluster Bomb for HPP or tampering when multiple params are positions.
  - Quick brute: `payloads/otp_bruteforce_common.txt` (respect scope/authorization).
- Check replay: resend last valid code twice; attempt cross-session/device if permitted.
- Rate limit: 2–5 attempts -> expect block/step-up.

## Comparer / Decoder / Sequencer
- Comparer: diff valid vs invalid user responses and OTP wrong-length vs wrong-value.
- Decoder: check single vs double decoding acceptance (`encoding_tricks.txt`).
- Sequencer: analyze session IDs pre/post login; confirm rotation.

## Findings to record
- Any auth success with malformed/encoded/injection input.
- Distinct messages/status/length/timing (username/OTP enumeration).
- Acceptance of arrays/objects/booleans; missing rate limits; weak cookie flags; open redirects.
- OTP not one-time/short-lived/session-bound; accepts Unicode/whitespace; HPP/race acceptance.

## Notes
- Use `payloads/whitespace_unicode.txt` for trimming/normalization checks.
- Use `payloads/returnurl_open_redirects.txt` to probe redirect params.
- Use `payloads/type_juggling.txt` with JSON bodies to test loose comparisons.