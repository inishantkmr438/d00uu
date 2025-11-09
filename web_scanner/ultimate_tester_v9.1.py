#!/usr/bin/env python3
"""Ultimate Tester v9.1 - Data Validation Module"""
import requests, re, time, json, argparse, warnings, hashlib
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote
from bs4 import BeautifulSoup
from datetime import datetime
warnings.filterwarnings('ignore')

class Colors:
    OKBLUE='\033[94m';OKGREEN='\033[92m';WARNING='\033[93m';FAIL='\033[91m'
    ENDC='\033[0m';BOLD='\033[1m';OKCYAN='\033[96m';PURPLE='\033[95m'

class SecurityHeaders:
    HEADERS = {
        'Strict-Transport-Security': {'severity': 'HIGH', 'description': 'Forces HTTPS', 'recommended': 'max-age=31536000', 'attack': 'SSL stripping'},
        'Content-Security-Policy': {'severity': 'HIGH', 'description': 'Prevents XSS', 'recommended': "default-src 'self'", 'attack': 'XSS attacks'},
        'X-Frame-Options': {'severity': 'MEDIUM', 'description': 'Prevents clickjacking', 'recommended': 'DENY', 'attack': 'Clickjacking'},
        'X-Content-Type-Options': {'severity': 'MEDIUM', 'description': 'Prevents MIME-sniffing', 'recommended': 'nosniff', 'attack': 'MIME confusion'},
        'Referrer-Policy': {'severity': 'MEDIUM', 'description': 'Controls referrer', 'recommended': 'no-referrer', 'attack': 'Info leakage'},
        'Permissions-Policy': {'severity': 'MEDIUM', 'description': 'Browser features', 'recommended': 'geolocation=()', 'attack': 'Unauthorized access'},
        'Cross-Origin-Embedder-Policy': {'severity': 'MEDIUM', 'description': 'Cross-origin isolation', 'recommended': 'require-corp', 'attack': 'Info leaks'},
        'Cross-Origin-Opener-Policy': {'severity': 'MEDIUM', 'description': 'Context isolation', 'recommended': 'same-origin', 'attack': 'Spectre attacks'},
        'Cross-Origin-Resource-Policy': {'severity': 'MEDIUM', 'description': 'Prevents cross-domain reads', 'recommended': 'same-origin', 'attack': 'Data theft'},
        'X-XSS-Protection': {'severity': 'LOW', 'description': 'XSS filter', 'recommended': '1; mode=block', 'attack': 'XSS (legacy)'},
        'Cache-Control': {'severity': 'MEDIUM', 'description': 'Cache control', 'recommended': 'no-store, no-cache', 'attack': 'Data cached'},
        'Pragma': {'severity': 'MEDIUM', 'description': 'HTTP/1.0 cache', 'recommended': 'no-cache', 'attack': 'Cache exposure'}
    }

class DataValidationScanner:
    """OWASP Data Validation Testing - 15 Tests"""

    @staticmethod
    def test_reflected_xss(session, urls):
        """DV-01: Reflected XSS - Tests for reflected cross-site scripting"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-01] Reflected XSS{Colors.ENDC}")
        issues = []
        payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg/onload=alert(1)>']
        for url in urls[:3]:
            if '=' in url:
                for payload in payloads:
                    try:
                        test_url = url + quote(payload)
                        r = session.get(test_url, timeout=5)
                        if payload in r.text or unquote(payload) in r.text:
                            print(f"  {Colors.FAIL}[!] Reflected XSS{Colors.ENDC}")
                            issues.append({'type': 'Reflected XSS', 'severity': 'HIGH', 'owasp': 'Data Validation', 'url': url, 'description': 'XSS vulnerability', 'recommended': 'Sanitize input, encode output'})
                            return issues
                    except: pass
        print(f"  {Colors.OKGREEN}[+] No reflected XSS{Colors.ENDC}")
        return issues

    @staticmethod
    def test_sql_injection(session, urls):
        """DV-02: SQL Injection - Tests for SQL injection vulnerabilities"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-02] SQL Injection{Colors.ENDC}")
        issues = []
        payloads = ["'", "' OR '1'='1", "'; DROP TABLE--"]
        sql_errors = ['sql', 'mysql', 'sqlite', 'postgresql', 'syntax', 'database']
        for url in urls[:3]:
            if '=' in url:
                for payload in payloads:
                    try:
                        test_url = url + quote(payload)
                        r = session.get(test_url, timeout=5)
                        if any(err in r.text.lower() for err in sql_errors):
                            print(f"  {Colors.FAIL}[!] SQL Injection{Colors.ENDC}")
                            issues.append({'type': 'SQL Injection', 'severity': 'CRITICAL', 'owasp': 'Data Validation', 'url': url, 'description': 'SQL injection', 'recommended': 'Use parameterized queries'})
                            return issues
                    except: pass
        print(f"  {Colors.OKGREEN}[+] No SQL injection{Colors.ENDC}")
        return issues

    @staticmethod
    def test_nosql_injection(session, urls):
        """DV-03: NoSQL Injection - Tests for MongoDB/NoSQL injection"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-03] NoSQL Injection{Colors.ENDC}")
        issues = []
        payloads = ['{"$gt":""}', '{"$ne":null}', '[$ne]=1']
        for url in urls[:3]:
            if '=' in url:
                for payload in payloads:
                    try:
                        test_url = url + quote(payload)
                        r = session.get(test_url, timeout=5)
                        if len(r.text) > 100 and r.status_code == 200:
                            print(f"  {Colors.WARNING}[!] Potential NoSQL{Colors.ENDC}")
                            issues.append({'type': 'NoSQL Injection', 'severity': 'HIGH', 'owasp': 'Data Validation', 'url': url, 'description': 'NoSQL injection', 'recommended': 'Validate input'})
                            return issues
                    except: pass
        print(f"  {Colors.OKGREEN}[+] No NoSQL injection{Colors.ENDC}")
        return issues

    @staticmethod
    def test_ldap_injection(session, urls):
        """DV-04: LDAP Injection - Tests for LDAP query injection"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-04] LDAP Injection{Colors.ENDC}")
        issues = []
        payloads = ['*', '*)(uid=*))(|(uid=*']
        for url in urls[:3]:
            if '=' in url and any(t in url.lower() for t in ['user', 'name']):
                for payload in payloads:
                    try:
                        test_url = url + quote(payload)
                        r = session.get(test_url, timeout=5)
                        if 'ldap' in r.text.lower():
                            print(f"  {Colors.WARNING}[!] Potential LDAP{Colors.ENDC}")
                            issues.append({'type': 'LDAP Injection', 'severity': 'HIGH', 'owasp': 'Data Validation', 'url': url, 'description': 'LDAP injection', 'recommended': 'Escape LDAP chars'})
                            return issues
                    except: pass
        print(f"  {Colors.OKGREEN}[+] No LDAP injection{Colors.ENDC}")
        return issues

    @staticmethod
    def test_xml_xxe(session, urls):
        """DV-05: XXE Injection - Tests for XML External Entity injection"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-05] XXE Injection{Colors.ENDC}")
        issues = []
        xxe = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
        for url in urls[:3]:
            try:
                r = session.post(url, data=xxe, headers={'Content-Type': 'application/xml'}, timeout=5)
                if 'root:' in r.text:
                    print(f"  {Colors.FAIL}[!] XXE{Colors.ENDC}")
                    issues.append({'type': 'XXE Injection', 'severity': 'CRITICAL', 'owasp': 'Data Validation', 'url': url, 'description': 'XXE', 'recommended': 'Disable external entities'})
                    return issues
            except: pass
        print(f"  {Colors.OKGREEN}[+] No XXE{Colors.ENDC}")
        return issues

    @staticmethod
    def test_command_injection(session, urls):
        """DV-06: Command Injection - Tests for OS command injection"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-06] Command Injection{Colors.ENDC}")
        issues = []
        payloads = ['; ls', '| whoami', '`id`', '$(whoami)']
        for url in urls[:3]:
            if '=' in url:
                for payload in payloads:
                    try:
                        test_url = url + quote(payload)
                        r = session.get(test_url, timeout=5)
                        if any(i in r.text.lower() for i in ['root:', 'uid=', 'bin/']):
                            print(f"  {Colors.FAIL}[!] Command injection{Colors.ENDC}")
                            issues.append({'type': 'Command Injection', 'severity': 'CRITICAL', 'owasp': 'Data Validation', 'url': url, 'description': 'OS command injection', 'recommended': 'Avoid shell commands'})
                            return issues
                    except: pass
        print(f"  {Colors.OKGREEN}[+] No command injection{Colors.ENDC}")
        return issues

    @staticmethod
    def test_lfi(session, urls):
        """DV-07: LFI - Tests for Local File Inclusion"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-07] Local File Inclusion{Colors.ENDC}")
        issues = []
        payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini']
        for url in urls[:3]:
            if '=' in url:
                for payload in payloads:
                    try:
                        test_url = url.split('=')[0] + '=' + quote(payload)
                        r = session.get(test_url, timeout=5)
                        if 'root:' in r.text or '[fonts]' in r.text:
                            print(f"  {Colors.FAIL}[!] LFI{Colors.ENDC}")
                            issues.append({'type': 'LFI', 'severity': 'HIGH', 'owasp': 'Data Validation', 'url': url, 'description': 'Local file inclusion', 'recommended': 'Validate paths'})
                            return issues
                    except: pass
        print(f"  {Colors.OKGREEN}[+] No LFI{Colors.ENDC}")
        return issues

    @staticmethod
    def test_rfi(session, urls):
        """DV-08: RFI - Tests for Remote File Inclusion"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-08] Remote File Inclusion{Colors.ENDC}")
        issues = []
        for url in urls[:3]:
            if '=' in url:
                try:
                    test_url = url.split('=')[0] + '=http://example.com/test.txt'
                    r = session.get(test_url, timeout=5)
                    if r.status_code == 200:
                        print(f"  {Colors.WARNING}[!] Potential RFI{Colors.ENDC}")
                        issues.append({'type': 'RFI', 'severity': 'CRITICAL', 'owasp': 'Data Validation', 'url': url, 'description': 'Remote file inclusion', 'recommended': 'Disable remote includes'})
                        return issues
                except: pass
        print(f"  {Colors.OKGREEN}[+] No RFI{Colors.ENDC}")
        return issues

    @staticmethod
    def test_http_verb(session, url):
        """DV-09: HTTP Verb Tampering - Tests for unsafe HTTP methods"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-09] HTTP Verb Tampering{Colors.ENDC}")
        issues = []
        for method in ['PUT', 'DELETE', 'TRACE', 'OPTIONS']:
            try:
                r = session.request(method, url, timeout=5)
                if r.status_code in [200, 204]:
                    print(f"  {Colors.WARNING}[!] {method} allowed{Colors.ENDC}")
                    issues.append({'type': f'HTTP Verb - {method}', 'severity': 'MEDIUM', 'owasp': 'Data Validation', 'url': url, 'description': f'{method} enabled', 'recommended': 'Disable methods'})
            except: pass
        if not issues: print(f"  {Colors.OKGREEN}[+] No verb tampering{Colors.ENDC}")
        return issues

    @staticmethod
    def test_http_splitting(session, urls):
        """DV-10: HTTP Response Splitting - Tests for CRLF injection"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-10] HTTP Response Splitting{Colors.ENDC}")
        issues = []
        payload = '%0d%0aContent-Length:%200'
        for url in urls[:3]:
            if '=' in url:
                try:
                    r = session.get(url + payload, timeout=5)
                    if 'Content-Length: 0' in r.text:
                        print(f"  {Colors.FAIL}[!] HTTP splitting{Colors.ENDC}")
                        issues.append({'type': 'HTTP Splitting', 'severity': 'HIGH', 'owasp': 'Data Validation', 'url': url, 'description': 'Response splitting', 'recommended': 'Reject CRLF'})
                        return issues
                except: pass
        print(f"  {Colors.OKGREEN}[+] No HTTP splitting{Colors.ENDC}")
        return issues

    @staticmethod
    def test_html_injection(session, urls):
        """DV-11: HTML Injection - Tests for HTML injection"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-11] HTML Injection{Colors.ENDC}")
        issues = []
        payloads = ['<h1>test</h1>', '<b>bold</b>']
        for url in urls[:3]:
            if '=' in url:
                for payload in payloads:
                    try:
                        r = session.get(url + quote(payload), timeout=5)
                        if payload in r.text:
                            print(f"  {Colors.FAIL}[!] HTML injection{Colors.ENDC}")
                            issues.append({'type': 'HTML Injection', 'severity': 'MEDIUM', 'owasp': 'Data Validation', 'url': url, 'description': 'HTML injection', 'recommended': 'Encode HTML'})
                            return issues
                    except: pass
        print(f"  {Colors.OKGREEN}[+] No HTML injection{Colors.ENDC}")
        return issues

    @staticmethod
    def test_ssi_injection(session, urls):
        """DV-12: SSI Injection - Tests for Server Side Includes injection"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-12] SSI Injection{Colors.ENDC}")
        issues = []
        payload = '<!--#exec cmd="ls"-->'
        for url in urls[:3]:
            if '=' in url:
                try:
                    r = session.get(url + quote(payload), timeout=5)
                    if 'exec' not in r.text and r.status_code == 200:
                        print(f"  {Colors.WARNING}[!] Potential SSI{Colors.ENDC}")
                        issues.append({'type': 'SSI Injection', 'severity': 'HIGH', 'owasp': 'Data Validation', 'url': url, 'description': 'SSI injection', 'recommended': 'Disable SSI'})
                        return issues
                except: pass
        print(f"  {Colors.OKGREEN}[+] No SSI{Colors.ENDC}")
        return issues

    @staticmethod
    def test_xpath_injection(session, urls):
        """DV-13: XPath Injection - Tests for XPath injection"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-13] XPath Injection{Colors.ENDC}")
        issues = []
        payloads = ["' or '1'='1", "x' or 1=1 or 'x'='y"]
        for url in urls[:3]:
            if '=' in url:
                for payload in payloads:
                    try:
                        r = session.get(url + quote(payload), timeout=5)
                        if 'xpath' in r.text.lower():
                            print(f"  {Colors.WARNING}[!] Potential XPath{Colors.ENDC}")
                            issues.append({'type': 'XPath Injection', 'severity': 'HIGH', 'owasp': 'Data Validation', 'url': url, 'description': 'XPath injection', 'recommended': 'Parameterized queries'})
                            return issues
                    except: pass
        print(f"  {Colors.OKGREEN}[+] No XPath{Colors.ENDC}")
        return issues

    @staticmethod
    def test_http_param_pollution(session, urls):
        """DV-14: HTTP Parameter Pollution - Tests for HPP"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-14] HTTP Parameter Pollution{Colors.ENDC}")
        issues = []
        for url in urls[:3]:
            if '=' in url:
                try:
                    param = url.split('=')[0].split('?')[-1]
                    test_url = url + f'&{param}=test2'
                    r = session.get(test_url, timeout=5)
                    if r.status_code == 200:
                        print(f"  {Colors.OKCYAN}[*] HPP test{Colors.ENDC}")
                        issues.append({'type': 'HPP', 'severity': 'INFO', 'owasp': 'Data Validation', 'url': url, 'description': 'Manual verification needed', 'recommended': 'Validate handling'})
                        return issues
                except: pass
        print(f"  {Colors.OKGREEN}[+] No HPP{Colors.ENDC}")
        return issues

    @staticmethod
    def test_mass_assignment(soup, url):
        """DV-15: Mass Assignment - Tests for mass assignment vulnerabilities"""
        print(f"\n{Colors.PURPLE}[DATA-VAL-15] Mass Assignment{Colors.ENDC}")
        issues = []
        for form in soup.find_all('form'):
            for field in form.find_all('input', type='hidden'):
                if any(term in field.get('name','').lower() for term in ['role', 'admin', 'privilege']):
                    print(f"  {Colors.WARNING}[!] Potential mass assignment{Colors.ENDC}")
                    issues.append({'type': 'Mass Assignment', 'severity': 'HIGH', 'owasp': 'Data Validation', 'url': url, 'description': 'Sensitive fields', 'recommended': 'Use whitelist'})
                    return issues
        print(f"  {Colors.OKGREEN}[+] No mass assignment{Colors.ENDC}")
        return issues

class OWASP2021Scanner:
    @staticmethod
    def test_a01(session, urls):
        print(f"\n{Colors.PURPLE}[OWASP-2021-A01] Access Control{Colors.ENDC}")
        issues = []
        for url in urls[:5]:
            if 'id=' in url.lower():
                try:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    for param in ['id', 'user']:
                        if param in params and params[param][0].isdigit():
                            orig = params[param][0]
                            test_url = url.replace(f"{param}={orig}", f"{param}={int(orig)+1}")
                            r = session.get(test_url, timeout=5)
                            if r.status_code == 200 and len(r.text) > 100:
                                print(f"  {Colors.FAIL}[!] IDOR{Colors.ENDC}")
                                issues.append({'type': 'IDOR', 'severity': 'HIGH', 'owasp': 'A01:2021', 'url': url, 'description': 'IDOR', 'recommended': 'Authorization checks'})
                                return issues
                except: pass
        print(f"  {Colors.OKGREEN}[+] No IDOR{Colors.ENDC}")
        return issues

    @staticmethod
    def test_a06(soup, url):
        print(f"\n{Colors.PURPLE}[OWASP-2021-A06] Vulnerable Components{Colors.ENDC}")
        issues = []
        libs = {'jQuery': {'pattern': r'jquery[.-]?([0-9.]+)', 'vuln': ['1.', '2.'], 'cves': 'CVE-2020-11022'}}
        for script in soup.find_all('script', src=True):
            src = script.get('src', '').lower()
            for name, info in libs.items():
                matches = re.findall(info['pattern'], src)
                if matches and any(matches[0].startswith(v) for v in info['vuln']):
                    print(f"  {Colors.FAIL}[!] Vulnerable {name}{Colors.ENDC}")
                    issues.append({'type': f'Vulnerable {name}', 'severity': 'HIGH', 'owasp': 'A06:2021', 'url': url, 'description': info["cves"], 'recommended': f'Update {name}'})
        if not issues: print(f"  {Colors.OKGREEN}[+] No vulnerable components{Colors.ENDC}")
        return issues

class OWASP2025Scanner:
    @staticmethod
    def test_a01(session, urls):
        print(f"\n{Colors.PURPLE}[OWASP-2025-A01] Access Control{Colors.ENDC}")
        return OWASP2021Scanner.test_a01(session, urls)

    @staticmethod
    def test_a03(soup, url):
        print(f"\n{Colors.PURPLE}[OWASP-2025-A03] Supply Chain{Colors.ENDC}")
        return OWASP2021Scanner.test_a06(soup, url)

    @staticmethod
    def test_a05(session, urls):
        print(f"\n{Colors.PURPLE}[OWASP-2025-A05] Injection{Colors.ENDC}")
        return DataValidationScanner.test_sql_injection(session, urls)

class BurpProScanner:
    @staticmethod
    def test_csrf(soup, url):
        print(f"\n{Colors.PURPLE}[BURP-PRO] CSRF{Colors.ENDC}")
        issues = []
        for form in soup.find_all('form', method=re.compile('post', re.I)):
            if not any(inp.get('name','').lower() in ['csrf', 'token'] for inp in form.find_all('input')):
                print(f"  {Colors.FAIL}[!] Missing CSRF{Colors.ENDC}")
                issues.append({'type': 'Missing CSRF', 'severity': 'HIGH', 'owasp': 'Burp Pro', 'url': url, 'description': 'No CSRF token', 'recommended': 'Implement CSRF'})
                break
        if not issues: print(f"  {Colors.OKGREEN}[+] CSRF protection{Colors.ENDC}")
        return issues

    @staticmethod
    def test_path_traversal(session, url):
        print(f"\n{Colors.PURPLE}[BURP-PRO] Path Traversal{Colors.ENDC}")
        return DataValidationScanner.test_lfi(session, [url])

    @staticmethod
    def test_open_redirect(session, urls):
        print(f"\n{Colors.PURPLE}[BURP-PRO] Open Redirect{Colors.ENDC}")
        issues = []
        for url in urls[:5]:
            if any(p in url.lower() for p in ['redirect', 'url']):
                try:
                    r = session.get(url.split('=')[0] + '=https://evil.com', timeout=5, allow_redirects=False)
                    if r.status_code in [301, 302] and 'evil.com' in r.headers.get('Location', ''):
                        print(f"  {Colors.FAIL}[!] Open redirect{Colors.ENDC}")
                        issues.append({'type': 'Open Redirect', 'severity': 'MEDIUM', 'owasp': 'Burp Pro', 'url': url, 'description': 'Unvalidated redirect', 'recommended': 'Validate URLs'})
                        return issues
                except: pass
        if not issues: print(f"  {Colors.OKGREEN}[+] No open redirect{Colors.ENDC}")
        return issues

class AuthenticationScanner:
    @staticmethod
    def test_user_enumeration(session, soup, url):
        print(f"\n{Colors.PURPLE}[AUTH-01] User Enumeration{Colors.ENDC}")
        if soup.find_all('form', action=re.compile('login', re.I)):
            print(f"  {Colors.OKCYAN}[*] Login forms{Colors.ENDC}")
            return [{'type': 'User Enumeration', 'severity': 'INFO', 'owasp': 'Authentication', 'url': url, 'description': 'Manual test', 'recommended': 'Generic errors'}]
        return []

    @staticmethod
    def test_autocomplete(soup, url):
        print(f"\n{Colors.PURPLE}[AUTH-02] Password Autocomplete{Colors.ENDC}")
        for field in soup.find_all('input', type='password'):
            if field.get('autocomplete', '').lower() not in ['off', 'new-password']:
                print(f"  {Colors.FAIL}[!] Autocomplete{Colors.ENDC}")
                return [{'type': 'Password Autocomplete', 'severity': 'LOW', 'owasp': 'Authentication', 'url': url, 'description': 'Autocomplete', 'recommended': 'autocomplete=off'}]
        print(f"  {Colors.OKGREEN}[+] Configured{Colors.ENDC}")
        return []

class SessionManagementScanner:
    @staticmethod
    def test_session_storage(response, soup, url):
        print(f"\n{Colors.PURPLE}[SESSION-01] Session Storage{Colors.ENDC}")
        issues = []
        if response.cookies:
            print(f"  {Colors.OKCYAN}[*] Cookies{Colors.ENDC}")
            issues.append({'type': 'Session Storage', 'severity': 'INFO', 'owasp': 'Session', 'url': url, 'description': 'Using cookies', 'recommended': 'Ensure flags'})
        if any(t in url.lower() for t in ['session', 'sid']):
            print(f"  {Colors.FAIL}[!] Session in URL{Colors.ENDC}")
            issues.append({'type': 'Session in URL', 'severity': 'HIGH', 'owasp': 'Session', 'url': url, 'description': 'Session ID in URL', 'recommended': 'Use cookies'})
        return issues

    @staticmethod
    def test_cookie_flags(response, url):
        print(f"\n{Colors.PURPLE}[SESSION-02] Cookie Flags{Colors.ENDC}")
        issues = []
        for cookie in response.cookies:
            print(f"  {Colors.OKCYAN}[*] {cookie.name}{Colors.ENDC}")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                print(f"    {Colors.FAIL}[!] Missing HttpOnly{Colors.ENDC}")
                issues.append({'type': f'Missing HttpOnly ({cookie.name})', 'severity': 'HIGH', 'owasp': 'Session', 'url': url, 'description': 'XSS risk', 'recommended': 'Add HttpOnly'})
            if not cookie.secure:
                print(f"    {Colors.FAIL}[!] Missing Secure{Colors.ENDC}")
                issues.append({'type': f'Missing Secure ({cookie.name})', 'severity': 'HIGH', 'owasp': 'Session', 'url': url, 'description': 'HTTP risk', 'recommended': 'Add Secure'})
        return issues

    @staticmethod
    def test_session_randomness(response, url):
        print(f"\n{Colors.PURPLE}[SESSION-06] Session Randomness{Colors.ENDC}")
        issues = []
        for cookie in response.cookies:
            if any(t in cookie.name.lower() for t in ['session', 'sid', 'token']):
                print(f"  {Colors.OKCYAN}[*] {cookie.name}{Colors.ENDC}")
                if len(cookie.value) < 16:
                    print(f"    {Colors.FAIL}[!] Too short{Colors.ENDC}")
                    issues.append({'type': f'Short Session ID', 'severity': 'HIGH', 'owasp': 'Session', 'url': url, 'description': 'Brute force risk', 'recommended': '128+ bit IDs'})
                if re.match(r'^[0-9]+$', cookie.value):
                    print(f"    {Colors.FAIL}[!] Numeric{Colors.ENDC}")
                    issues.append({'type': f'Weak Pattern', 'severity': 'CRITICAL', 'owasp': 'Session', 'url': url, 'description': 'Predictable', 'recommended': 'Crypto random'})
        return issues

class UltimateSecurityTester:
    def __init__(self, target_url, verbose=False, burp_pro=False, owasp_2025=False, auth_tests=False, session_tests=False, data_validation=False, output_file=None):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.verbose = verbose
        self.burp_pro = burp_pro
        self.owasp_2025 = owasp_2025
        self.auth_tests = auth_tests
        self.session_tests = session_tests
        self.data_validation = data_validation
        self.output_file = output_file
        self.vulnerabilities = []
        self.finding_counter = 0
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def scan(self):
        start = time.time()
        edition = "OWASP 2025" if self.owasp_2025 else "OWASP 2021"
        if self.burp_pro: edition += " + Burp"
        if self.auth_tests: edition += " + Auth"
        if self.session_tests: edition += " + Session"
        if self.data_validation: edition += " + Data Val"

        print(f"\n{'='*70}")
        print(f"  ULTIMATE TESTER v9.1")
        print(f"  {edition}")
        print(f"  Target: {self.target_url}")
        print(f"{'='*70}")

        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            print(f"\nPHASE 1: SECURITY HEADERS")
            print(f"{'='*70}")
            self.check_headers(response.headers)

            print(f"\nPHASE 2: OWASP TESTING")
            print(f"{'='*70}")
            urls = self.crawl()

            if self.owasp_2025:
                for i in OWASP2025Scanner.test_a01(self.session, urls): self.add_vuln(i)
                for i in OWASP2025Scanner.test_a03(soup, self.target_url): self.add_vuln(i)
                for i in OWASP2025Scanner.test_a05(self.session, urls): self.add_vuln(i)
            else:
                for i in OWASP2021Scanner.test_a01(self.session, urls): self.add_vuln(i)
                for i in OWASP2021Scanner.test_a06(soup, self.target_url): self.add_vuln(i)

            phase = 3
            if self.burp_pro:
                print(f"\nPHASE {phase}: BURP PRO")
                print(f"{'='*70}")
                for i in BurpProScanner.test_csrf(soup, self.target_url): self.add_vuln(i)
                for i in BurpProScanner.test_path_traversal(self.session, self.target_url): self.add_vuln(i)
                for i in BurpProScanner.test_open_redirect(self.session, urls): self.add_vuln(i)
                phase += 1

            if self.auth_tests:
                print(f"\nPHASE {phase}: AUTHENTICATION")
                print(f"{'='*70}")
                for i in AuthenticationScanner.test_user_enumeration(self.session, soup, self.target_url): self.add_vuln(i)
                for i in AuthenticationScanner.test_autocomplete(soup, self.target_url): self.add_vuln(i)
                phase += 1

            if self.session_tests:
                print(f"\nPHASE {phase}: SESSION MANAGEMENT")
                print(f"{'='*70}")
                for i in SessionManagementScanner.test_session_storage(response, soup, self.target_url): self.add_vuln(i)
                for i in SessionManagementScanner.test_cookie_flags(response, self.target_url): self.add_vuln(i)
                for i in SessionManagementScanner.test_session_randomness(response, self.target_url): self.add_vuln(i)
                phase += 1

            if self.data_validation:
                print(f"\nPHASE {phase}: DATA VALIDATION (15 tests)")
                print(f"{'='*70}")
                for i in DataValidationScanner.test_reflected_xss(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_sql_injection(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_nosql_injection(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_ldap_injection(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_xml_xxe(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_command_injection(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_lfi(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_rfi(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_http_verb(self.session, self.target_url): self.add_vuln(i)
                for i in DataValidationScanner.test_http_splitting(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_html_injection(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_ssi_injection(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_xpath_injection(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_http_param_pollution(self.session, urls): self.add_vuln(i)
                for i in DataValidationScanner.test_mass_assignment(soup, self.target_url): self.add_vuln(i)

            print(f"\n{'='*70}")
            print(f"Completed in {time.time()-start:.2f}s")
            print(f"{'='*70}\n")
            self.generate_report()
        except Exception as e:
            print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

    def add_vuln(self, vuln):
        self.finding_counter += 1
        vuln['number'] = self.finding_counter
        self.vulnerabilities.append(vuln)

    def check_headers(self, headers):
        print(f"\n{Colors.OKCYAN}Analyzing headers...{Colors.ENDC}\n")
        missing = 0
        for header, info in SecurityHeaders.HEADERS.items():
            if header not in headers:
                missing += 1
                sev_color = Colors.FAIL + Colors.BOLD if info['severity'] == 'HIGH' else Colors.WARNING if info['severity'] == 'MEDIUM' else Colors.OKCYAN
                print(f"{Colors.FAIL}[!] Missing: {header}{Colors.ENDC}")
                print(f"    {Colors.OKBLUE}What:{Colors.ENDC} {info['description']}")
                print(f"    {Colors.WARNING}Risk:{Colors.ENDC} {info['attack']}")
                print(f"    {Colors.OKGREEN}Fix:{Colors.ENDC} {info['recommended']}")
                print(f"    {sev_color}Severity: {info['severity']}{Colors.ENDC}\n")
                self.add_vuln({'type': f"Missing Header - {header}", 'severity': info['severity'], 'owasp': 'Security', 'url': self.target_url, 'description': info['description'], 'recommended': info['recommended']})
            else:
                print(f"{Colors.OKGREEN}[+] Present: {header}{Colors.ENDC}")
        print(f"\n{Colors.OKBLUE}Summary: {missing}/{len(SecurityHeaders.HEADERS)} missing{Colors.ENDC}")

    def crawl(self):
        print(f"\n{Colors.OKCYAN}[*] Crawling{Colors.ENDC}")
        urls = set([self.target_url])
        try:
            r = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            for link in soup.find_all('a', href=True)[:10]:
                url = urljoin(self.target_url, link['href'])
                if urlparse(url).netloc == self.base_domain: urls.add(url)
        except: pass
        print(f"  {Colors.OKBLUE}[*] Found {len(urls)} URLs{Colors.ENDC}")
        return list(urls)

    def generate_report(self):
        print(f"\n{'='*70}")
        print("SCAN REPORT")
        print(f"{'='*70}")
        groups = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': []}
        for v in self.vulnerabilities:
            if v['severity'] in groups: groups[v['severity']].append(v)
        total = len(self.vulnerabilities)
        edition = "OWASP 2025" if self.owasp_2025 else "OWASP 2021"
        if self.burp_pro: edition += " + Burp"
        if self.auth_tests: edition += " + Auth"
        if self.session_tests: edition += " + Session"
        if self.data_validation: edition += " + Data Val"
        print(f"\nTarget: {self.target_url}")
        print(f"Edition: {edition}")
        print(f"Total: {total}")
        print(f"{'-'*70}\n")
        print("SEVERITY BREAKDOWN:\n")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = len(groups[sev])
            if count > 0:
                color = Colors.FAIL + Colors.BOLD if sev == 'CRITICAL' else Colors.FAIL if sev == 'HIGH' else Colors.WARNING if sev == 'MEDIUM' else Colors.OKCYAN if sev == 'LOW' else Colors.OKBLUE
                print(f"  {color}[{sev}] {count}{Colors.ENDC}")
        print(f"\n{'-'*70}\n")
        print("DETAILED FINDINGS:\n")
        for vuln in self.vulnerabilities:
            color = Colors.FAIL + Colors.BOLD if vuln['severity'] == 'CRITICAL' else Colors.FAIL if vuln['severity'] == 'HIGH' else Colors.WARNING if vuln['severity'] == 'MEDIUM' else Colors.OKCYAN if vuln['severity'] == 'LOW' else Colors.OKBLUE
            owasp_tag = f" [{vuln.get('owasp', 'N/A')}]" if 'owasp' in vuln else ""
            print(f"[{vuln['number']}] {vuln['type']}{owasp_tag}")
            print(f"    {color}Severity: {vuln['severity']}{Colors.ENDC}")
            print(f"    URL: {vuln['url']}")
            if vuln.get('description'): print(f"    Description: {vuln['description']}")
            if vuln.get('recommended'): print(f"    Recommended: {vuln['recommended']}")
            print()
        if self.output_file:
            with open(self.output_file, 'w') as f:
                json.dump({'target': self.target_url, 'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'edition': edition, 'total': total, 'severity_breakdown': {k: len(v) for k, v in groups.items()}, 'vulnerabilities': self.vulnerabilities}, f, indent=2)
            print(f"{Colors.OKGREEN}[+] JSON: {self.output_file}{Colors.ENDC}\n")
        print(f"{'='*70}\n")

def main():
    parser = argparse.ArgumentParser(description='Ultimate Tester v9.1 - Data Validation Module')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose')
    parser.add_argument('--burp-pro', action='store_true', help='Burp Pro')
    parser.add_argument('--owasp-2025', action='store_true', help='OWASP 2025')
    parser.add_argument('--auth-tests', action='store_true', help='Auth tests')
    parser.add_argument('--session-tests', action='store_true', help='Session tests')
    parser.add_argument('--data-validation', action='store_true', help='Data validation (15 tests)')
    parser.add_argument('-O', '--output', type=str, help='JSON output')
    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        return print(f"{Colors.FAIL}Error: URL must start with http:// or https://{Colors.ENDC}")

    scanner = UltimateSecurityTester(args.url, args.verbose, args.burp_pro, args.owasp_2025, args.auth_tests, args.session_tests, args.data_validation, args.output)
    scanner.scan()

if __name__ == "__main__":
    main()
