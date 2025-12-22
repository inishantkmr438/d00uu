# 🔍 **Login \& OTP Input Validation Test Plan**

**Target Audience:** Application security testers validating authentication flows
**Scope:** Comprehensive black-box testing of username/password + OTP verification
**Tools:** Burp Suite (Repeater, Intruder, Sequencer, Comparer, Decoder)[^1]

***

## Table of Contents

- [Test Scope \& Methodology](#test-scope--methodology)
- [Login Page Testing](#login-page-testing)
- [OTP Verification Testing](#otp-verification-testing)
- [Burp Suite Usage Patterns](#burp-suite-usage-patterns)
- [Expected Vulnerabilities](#expected-vulnerabilities)

***

## Test Scope \& Methodology

**Objective:** Identify input validation flaws enabling authentication bypass, enumeration, DoS, and injection attacks

### Attack Surface Coverage

```
Login Form → Password Reset → Session Issuance → OTP Verification → Dashboard
     ↓
Input Vectors: username, password, otp, txId, returnUrl, session cookies
```


### Success Criteria

| **Validation** | **Secure Response** | **Vulnerable Indicators** |
| :-- | :-- | :-- |
| **Generic Errors** | 400/422 uniform message | User-specific errors, 200 OK |
| **Rate Limiting** | 429 after 3-5 attempts | Unlimited attempts |
| **Timing** | <200ms uniform | Valid/invalid timing differences |


***

## Login Page Testing

### 1. Empty/Missing/Wrong Type Inputs

**Test Vectors:**

```http
# Form-URL-Encoded (Content-Type: application/x-www-form-urlencoded)
POST /login
username=&password=
---
username=admin&password=
---
username=&password=Passw0rd!
---
username=admin          # Missing password entirely
---
username=admin&password[]=Passw0rd!     # Array coercion
---
username=admin&password[foo]=bar        # Object coercion

# JSON (Content-Type: application/json)
POST /login
{}
---
{"username":"","password":""}
---
{"username":"admin"}                    # Missing password
---
{"username":["admin"],"password":"Passw0rd!"}
---
{"username":{"$ne":""},"password":"x"}    # NoSQLi probe
```

**Expected:** Uniform 400/422 "Invalid credentials"
**Vulns:** Missing param acceptance, array/object coercion, type juggling

### 2. Length Boundaries \& DoS

**Test Vectors:**

```http
username=a&password=a              # Minimum length
username=$(python -c 'print("a"*256)')  # Buffer overflow
username=$(python -c 'print("a"*10000)') # Memory exhaustion
password=$(python -c 'print("a"*100000)') # CPU timeout
```

**Expected:** Enforced min/max length, fast 4xx rejection
**Vulns:** Truncation bypass (`admin `≠`admin`), memory exhaustion

### 3. Whitespace \& Normalization

**Test Vectors:**

```http
username=" admin"                   # Leading space
username="admin "                   # Trailing space
username="\tadmin\t"                # Tab characters
username="admin\n"                  # Newline
username="admin\u00A0"              # Non-breaking space (NBSP)
username="adm\u0069n"               # Unicode homoglyph (i)
username="adm\u202Eni"              # Right-to-Left Override (RLO)
```

**Expected:** Consistent trimming + normalization policy
**Vulns:** Login bypass via collation mismatch

### 4. Encoding/Decoding Quirks

**Test Vectors:**

```http
username=admin%00&password=pass%00  # Null byte termination
username=admin%2527                 # Double URL encoding (%27)
username=%C0%AA                     # Overlong UTF-8
username=YWRtaW4=                   # Base64 (should reject)
```

**Expected:** Single decode only, reject control characters
**Vulns:** Double-decode bypass, parser differentials

### 5. Injection Probes

**Test Vectors:**

```http
# SQL Injection
' OR '1'='1
admin' --
") OR ("1"="1
%27%20OR%201=1--

# NoSQL Injection (MongoDB)
{"username":{"$ne":null},"password":"x"}
{"username":"admin","password":{"$gt":""}}

# LDAP Injection
*)(uid=*))(|(uid=*

# XPath Injection
' or '1'='1
" or count(/*)=1 or "
```

**Expected:** Generic failure, no stack traces
**Vulns:** Authentication bypass, error-based info disclosure

***

## OTP Verification Testing

### 1. Presence/Type/Structure

**Test Vectors:**

```http
# Form-URL-Encoded
otp=                           # Empty
otp[]=123456                   # Array
otp[code]=123456               # Nested

# JSON
{}
{"otp":[]}
{"otp":{"$ne":""}}
```

**Expected:** 400/422 generic rejection
**Vulns:** Implicit defaults, array coercion

### 2. Length/Charset/Normalization

**Test Vectors:**

```http
otp=0                           # Single digit
otp=12345                       # Short
otp=1234567                     # Long
otp=１２３４５６                   # Full-width Unicode
otp=۱۲۳۴۵۶                     # Persian digits
otp=" 123456 "                 # Whitespace
otp=123\u200b456               # Zero-width space
otp=123-456                     # Separators
```

**Expected:** Strict 6-digit ASCII validation
**Vulns:** Non-digit acceptance, normalization bypass

### 3. Brute Force Viability

**Intruder Payloads (000000-999999):**

```http
000000, 000001, 123456, 111111, 121212, 654321, 222222
```

**Expected:** 3-5 attempts → 429/captcha/lockout
**Vulns:** Unlimited attempts, shared code space

### 4. Replay/Reuse/Expiry

**Test Sequence:**

```
1. Request OTP → Receive: 123456 (TTL: 180s)
2. Submit valid OTP → Success
3. Resubmit same OTP → Should FAIL
4. Wait 300s → Resubmit → Should FAIL
```

**Expected:** One-time use, strict TTL
**Vulns:** Replay acceptance, long-lived codes

### 5. Binding \& Tampering

**Test Vectors:**

```json
{"username":"victim","otp":"123456","txId":"A"}  # Original
{"username":"attacker","otp":"123456","txId":"B"} # Same OTP, different user
```

**Expected:** OTP bound to original user/transaction
**Vulns:** Cross-user verification (confused deputy)

***

## Burp Suite Usage Patterns

### Repeater Workflow

```
1. Intercept login → Toggle Content-Type (form/JSON)
2. Inject payloads → Observe status/body/length/headers
3. Check Set-Cookie rotation after successful login
4. Decoder → Verify double-encoding acceptance
```


### Intruder Configurations

**Sniper (Username Enumeration):**

```
§username§=admin&password=wrong
Payloads: users.txt
Grep-Match: "Invalid username", "User does not exist"
```

**Pitchfork (OTP Brute Force):**

```
otp=§otp§
Payloads: 000000-999999
Grep-Extract: session token
Throttle: 1 req/sec
```

**Comparer Analysis:**

```
Valid vs Invalid username responses
Pre-login vs Post-login cookies
OTP wrong-length vs wrong-value
```


***

## Expected Vulnerabilities \& CVSS Scoring

| **Finding** | **CVSS v3.1** | **Impact** | **Detection Method** |
| :-- | :-- | :-- | :-- |
| Username Enumeration | **5.3** | Account discovery | Response diff (text/size/timing) |
| SQLi Auth Bypass | **9.8** | Full compromise | `' OR '1'='1` → 200 OK |
| Type Juggling | **7.5** | Auth bypass | `{"password":true}` → Login |
| Missing Rate Limit | **7.5** | Brute force viable | 100+ attempts → No 429 |
| OTP Replay | **8.1** | Account takeover | Same OTP → Multiple success |
| Normalization Bypass | **7.1** | Auth bypass | `admin\u00A0` → Login success |


***

## Success Metrics

```
✅ 100% input validation coverage
✅ Zero information disclosure (generic errors only)
✅ Rate limiting: 3-5 attempts → Lockout/Captcha
✅ Session rotation on successful login
✅ Secure cookie flags: Secure/HttpOnly/SameSite=Strict
✅ OTP: One-time, user-bound, 6-digit ASCII only
```

**Report Template:** Screenshots + Burp requests + CVSS scores + Remediation steps

**Production-ready validation methodology** - Deploy → Test → Report → Secure 🔒

<div align="center">⁂</div>

[^1]: https://portswigger.net/web-security/all-labs

