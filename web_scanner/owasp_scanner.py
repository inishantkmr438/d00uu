#!/usr/bin/env python3
"""
OWASP Top 10 Vulnerability Scanner
Author: Penetration Testing Tool
Description: Automated scanner for detecting OWASP Top 10 vulnerabilities
"""

import requests
import re
import time
import json
import argparse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class VulnerabilityScanner:
    """Main vulnerability scanner class"""

    def __init__(self, target_url: str, threads: int = 10, verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.threads = threads
        self.verbose = verbose
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def print_banner(self):
        """Print scanner banner"""
        banner = f"""
{Colors.OKBLUE}{'='*70}
   ____  _       _____    _____ ____    _____              _   ___  
  / __ \| |     / /   |  / ___// __ \  /_  _/ ___  ____  / | / _ \ 
 / / / /| | /| / / /| |  \__ \/ /_/ /   / /  / _ \/ __ \/  |/ / / |
/ /_/ / | |/ |/ / ___ | ___/ / ____/   / /  /  __/ /_/ / /|  / /_/ |
\____/  |__/|__/_/  |_|/____/_/       /_/   \___/ .___/_/ |_/\____/ 
                                               /_/                   
{Colors.ENDC}
{Colors.OKGREEN}Automated OWASP Top 10 Vulnerability Scanner{Colors.ENDC}
{Colors.WARNING}Target: {self.target_url}{Colors.ENDC}
{Colors.OKBLUE}{'='*70}{Colors.ENDC}
        """
        print(banner)

    def log(self, message: str, level: str = "INFO"):
        """Logging function with color coding"""
        timestamp = time.strftime("%H:%M:%S")
        colors = {
            "INFO": Colors.OKBLUE,
            "SUCCESS": Colors.OKGREEN,
            "WARNING": Colors.WARNING,
            "ERROR": Colors.FAIL,
            "VULN": Colors.FAIL + Colors.BOLD
        }
        color = colors.get(level, Colors.ENDC)
        print(f"[{timestamp}] {color}[{level}]{Colors.ENDC} {message}")

    def crawl_site(self, url: str, depth: int = 2) -> List[str]:
        """Crawl the website to discover URLs"""
        self.log(f"Crawling site (depth: {depth})...", "INFO")
        discovered_urls = set([url])

        def crawl_recursive(current_url: str, current_depth: int):
            if current_depth > depth or current_url in self.visited_urls:
                return

            self.visited_urls.add(current_url)

            try:
                response = self.session.get(current_url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')

                # Extract all links
                for link in soup.find_all(['a', 'form'], href=True):
                    href = link.get('href') or link.get('action')
                    if href:
                        full_url = urljoin(current_url, href)
                        if urlparse(full_url).netloc == self.base_domain:
                            discovered_urls.add(full_url)
                            if current_depth < depth:
                                crawl_recursive(full_url, current_depth + 1)
            except Exception as e:
                if self.verbose:
                    self.log(f"Crawl error for {current_url}: {str(e)}", "ERROR")

        crawl_recursive(url, 0)
        self.log(f"Discovered {len(discovered_urls)} URLs", "SUCCESS")
        return list(discovered_urls)

    # ==================== OWASP #1: Broken Access Control ====================
    def test_broken_access_control(self, urls: List[str]):
        """Test for broken access control vulnerabilities"""
        self.log("Testing for Broken Access Control (OWASP #1)...", "INFO")

        # Test for IDOR
        for url in urls:
            if any(param in url.lower() for param in ['id=', 'user=', 'account=']):
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                for param, value in params.items():
                    if value[0].isdigit():
                        # Test sequential IDs
                        test_values = [str(int(value[0]) + 1), str(int(value[0]) - 1), '999999']
                        for test_val in test_values:
                            test_params = params.copy()
                            test_params[param] = [test_val]
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                            try:
                                response = self.session.get(test_url, timeout=5)
                                if response.status_code == 200 and len(response.text) > 100:
                                    self.add_vulnerability(
                                        "Broken Access Control - Potential IDOR",
                                        test_url,
                                        f"Parameter '{param}' may be vulnerable to IDOR. Changed value from {value[0]} to {test_val}",
                                        "HIGH"
                                    )
                                    break
                            except:
                                pass

    # ==================== OWASP #2: Cryptographic Failures ====================
    def test_cryptographic_failures(self, urls: List[str]):
        """Test for cryptographic failures"""
        self.log("Testing for Cryptographic Failures (OWASP #2)...", "INFO")

        # Check if HTTPS is enforced
        if self.target_url.startswith('http://'):
            self.add_vulnerability(
                "Cryptographic Failure - No HTTPS",
                self.target_url,
                "Site is not using HTTPS encryption",
                "HIGH"
            )

        # Check for sensitive data exposure
        sensitive_patterns = [
            (r'password\s*[:=]\s*["']?[^"'\s]+', 'Hardcoded Password'),
            (r'api[_-]?key\s*[:=]\s*["']?[^"'\s]+', 'Exposed API Key'),
            (r'secret\s*[:=]\s*["']?[^"'\s]+', 'Exposed Secret'),
            (r'[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}', 'Credit Card Number'),
        ]

        for url in urls[:10]:  # Check first 10 URLs
            try:
                response = self.session.get(url, timeout=5)
                for pattern, vuln_name in sensitive_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        self.add_vulnerability(
                            f"Cryptographic Failure - {vuln_name}",
                            url,
                            f"Found potential {vuln_name} in page content",
                            "CRITICAL"
                        )
            except:
                pass

    # ==================== OWASP #3: Injection ====================
    def test_sql_injection(self, urls: List[str]):
        """Test for SQL injection vulnerabilities"""
        self.log("Testing for SQL Injection (OWASP #3)...", "INFO")

        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' AND '1'='2",
            "' UNION SELECT NULL--",
            "admin'--",
            "' OR 1=1--",
        ]

        error_patterns = [
            "SQL syntax",
            "mysql_fetch",
            "mysqli",
            "SQLite",
            "PostgreSQL",
            "ORA-01",
            "Microsoft SQL Server",
            "ODBC",
            "syntax error",
        ]

        for url in urls:
            if '=' in url:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                for param in params.keys():
                    for payload in sqli_payloads:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                        try:
                            response = self.session.get(test_url, timeout=5)

                            # Check for SQL errors
                            for error in error_patterns:
                                if error.lower() in response.text.lower():
                                    self.add_vulnerability(
                                        "SQL Injection",
                                        test_url,
                                        f"Parameter '{param}' appears vulnerable. Payload: {payload}",
                                        "CRITICAL"
                                    )
                                    return  # Stop after first finding
                        except:
                            pass

    def test_xss(self, urls: List[str]):
        """Test for Cross-Site Scripting (XSS)"""
        self.log("Testing for XSS (OWASP #3)...", "INFO")

        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "'><script>alert(1)</script>",
        ]

        for url in urls:
            if '=' in url:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                for param in params.keys():
                    for payload in xss_payloads:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                        try:
                            response = self.session.get(test_url, timeout=5)

                            # Check if payload is reflected
                            if payload in response.text:
                                self.add_vulnerability(
                                    "Cross-Site Scripting (XSS)",
                                    test_url,
                                    f"Parameter '{param}' is vulnerable to reflected XSS. Payload: {payload}",
                                    "HIGH"
                                )
                                return
                        except:
                            pass

    # ==================== OWASP #4: Insecure Design ====================
    def test_insecure_design(self, urls: List[str]):
        """Test for insecure design patterns"""
        self.log("Testing for Insecure Design (OWASP #4)...", "INFO")

        # Check for common insecure endpoints
        insecure_paths = [
            '/admin', '/administrator', '/admin.php', '/admin/',
            '/phpmyadmin', '/phpMyAdmin', '/pma',
            '/backup', '/backups', '/backup.zip', '/backup.sql',
            '/.git', '/.env', '/config.php', '/config/',
            '/api/v1/users', '/api/users', '/api/admin',
        ]

        for path in insecure_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    self.add_vulnerability(
                        "Insecure Design - Exposed Endpoint",
                        test_url,
                        f"Sensitive endpoint '{path}' is accessible without authentication",
                        "HIGH"
                    )
            except:
                pass

    # ==================== OWASP #5: Security Misconfiguration ====================
    def test_security_misconfiguration(self, urls: List[str]):
        """Test for security misconfigurations"""
        self.log("Testing for Security Misconfiguration (OWASP #5)...", "INFO")

        try:
            response = self.session.get(self.target_url, timeout=10)

            # Check security headers
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header (Clickjacking protection)',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing CSP header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
            }

            for header, description in security_headers.items():
                if header not in response.headers:
                    self.add_vulnerability(
                        "Security Misconfiguration",
                        self.target_url,
                        description,
                        "MEDIUM"
                    )

            # Check for verbose error messages
            if 'Server' in response.headers:
                server = response.headers['Server']
                if any(s in server.lower() for s in ['apache/', 'nginx/', 'microsoft-iis/']):
                    self.add_vulnerability(
                        "Security Misconfiguration - Server Version Disclosure",
                        self.target_url,
                        f"Server header reveals version: {server}",
                        "LOW"
                    )

            # Check for directory listing
            dir_listing_patterns = ['Index of /', 'Directory Listing', 'Parent Directory']
            for pattern in dir_listing_patterns:
                if pattern in response.text:
                    self.add_vulnerability(
                        "Security Misconfiguration - Directory Listing",
                        self.target_url,
                        "Directory listing is enabled",
                        "MEDIUM"
                    )
                    break
        except:
            pass

    # ==================== OWASP #6: Vulnerable Components ====================
    def test_vulnerable_components(self, urls: List[str]):
        """Test for vulnerable and outdated components"""
        self.log("Testing for Vulnerable Components (OWASP #6)...", "INFO")

        # Check for common vulnerable paths
        vulnerable_paths = [
            '/wp-admin',  # WordPress
            '/wp-login.php',
            '/administrator',  # Joomla
            '/admin/login.php',  # Various CMS
            '/phpmyadmin/index.php',
        ]

        for path in vulnerable_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    cms_name = "Unknown CMS"
                    if 'wp-' in path:
                        cms_name = "WordPress"
                    elif 'joomla' in response.text.lower():
                        cms_name = "Joomla"

                    self.add_vulnerability(
                        "Vulnerable Components - CMS Detected",
                        test_url,
                        f"Detected {cms_name}. Ensure it's up to date.",
                        "MEDIUM"
                    )
            except:
                pass

        # Check JavaScript libraries
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script', src=True)

            vulnerable_libs = {
                'jquery-1.': 'jQuery < 3.0',
                'jquery-2.': 'jQuery < 3.0',
                'angular.min.js': 'AngularJS',
                'bootstrap-3': 'Bootstrap 3.x',
            }

            for script in scripts:
                src = script.get('src', '')
                for lib, name in vulnerable_libs.items():
                    if lib in src.lower():
                        self.add_vulnerability(
                            "Vulnerable Components - Outdated Library",
                            self.target_url,
                            f"Potentially outdated library detected: {name}",
                            "MEDIUM"
                        )
        except:
            pass

    # ==================== OWASP #7: Authentication Failures ====================
    def test_authentication_failures(self, urls: List[str]):
        """Test for authentication and session management failures"""
        self.log("Testing for Authentication Failures (OWASP #7)...", "INFO")

        # Look for login pages
        login_keywords = ['login', 'signin', 'auth', 'user']
        login_urls = [url for url in urls if any(kw in url.lower() for kw in login_keywords)]

        for url in login_urls[:5]:  # Test first 5 login URLs
            try:
                response = self.session.get(url, timeout=5)

                # Check for weak password policy indicators
                if 'password' in response.text.lower():
                    # Try common credentials
                    common_creds = [
                        ('admin', 'admin'),
                        ('admin', 'password'),
                        ('admin', '123456'),
                        ('test', 'test'),
                    ]

                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')

                    for form in forms:
                        action = form.get('action', url)
                        method = form.get('method', 'get').lower()

                        # Extract form fields
                        inputs = form.find_all(['input', 'textarea'])
                        form_data = {}

                        for input_field in inputs:
                            name = input_field.get('name')
                            if name:
                                form_data[name] = 'test'

                        # Try one common credential
                        if form_data:
                            username_field = next((k for k in form_data.keys() if 'user' in k.lower() or 'email' in k.lower()), None)
                            password_field = next((k for k in form_data.keys() if 'pass' in k.lower()), None)

                            if username_field and password_field:
                                form_data[username_field] = 'admin'
                                form_data[password_field] = 'admin'

                                test_url = urljoin(url, action)

                                if method == 'post':
                                    test_response = self.session.post(test_url, data=form_data, timeout=5, allow_redirects=False)
                                else:
                                    test_response = self.session.get(test_url, params=form_data, timeout=5, allow_redirects=False)

                                # Check if login succeeded (redirect or success message)
                                if test_response.status_code in [200, 302, 303] and 'error' not in test_response.text.lower():
                                    self.add_vulnerability(
                                        "Authentication Failure - Weak Credentials",
                                        test_url,
                                        "Login form may accept weak credentials (admin/admin)",
                                        "CRITICAL"
                                    )
            except:
                pass

    # ==================== OWASP #8: Software and Data Integrity Failures ====================
    def test_integrity_failures(self, urls: List[str]):
        """Test for software and data integrity failures"""
        self.log("Testing for Integrity Failures (OWASP #8)...", "INFO")

        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Check for external scripts without integrity checks
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script.get('src', '')
                if src.startswith(('http://', 'https://', '//')):
                    if not script.get('integrity'):
                        self.add_vulnerability(
                            "Integrity Failure - Missing SRI",
                            self.target_url,
                            f"External script loaded without Subresource Integrity (SRI): {src}",
                            "MEDIUM"
                        )
                        break  # Report once
        except:
            pass

    # ==================== OWASP #9: Logging and Monitoring Failures ====================
    def test_logging_failures(self, urls: List[str]):
        """Test for insufficient logging and monitoring"""
        self.log("Testing for Logging Failures (OWASP #9)...", "INFO")

        # Check for verbose error messages that indicate logging issues
        test_urls = [
            urljoin(self.target_url, '/nonexistent-page-12345'),
            urljoin(self.target_url, '/test?id=\'\'\"'),
        ]

        for url in test_urls:
            try:
                response = self.session.get(url, timeout=5)

                # Look for stack traces or detailed error messages
                error_indicators = [
                    'Traceback',
                    'Exception',
                    'Stack trace',
                    'Error in',
                    'Warning:',
                    'Fatal error',
                    'on line',
                ]

                for indicator in error_indicators:
                    if indicator in response.text:
                        self.add_vulnerability(
                            "Logging Failure - Verbose Error Messages",
                            url,
                            "Application reveals detailed error information that could aid attackers",
                            "LOW"
                        )
                        return
            except:
                pass

    # ==================== OWASP #10: SSRF ====================
    def test_ssrf(self, urls: List[str]):
        """Test for Server-Side Request Forgery"""
        self.log("Testing for SSRF (OWASP #10)...", "INFO")

        ssrf_params = ['url', 'uri', 'path', 'file', 'page', 'doc', 'document']

        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in params.keys():
                if any(ssrf_param in param.lower() for ssrf_param in ssrf_params):
                    # Test internal IP access
                    test_payloads = [
                        'http://localhost',
                        'http://127.0.0.1',
                        'http://169.254.169.254',  # AWS metadata
                        'file:///etc/passwd',
                    ]

                    for payload in test_payloads:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                        try:
                            response = self.session.get(test_url, timeout=5)

                            # Check for indicators of successful SSRF
                            if response.status_code == 200 and len(response.text) > 0:
                                ssrf_indicators = ['root:', 'localhost', '127.0.0.1']
                                if any(indicator in response.text.lower() for indicator in ssrf_indicators):
                                    self.add_vulnerability(
                                        "Server-Side Request Forgery (SSRF)",
                                        test_url,
                                        f"Parameter '{param}' may be vulnerable to SSRF. Payload: {payload}",
                                        "CRITICAL"
                                    )
                                    return
                        except:
                            pass

    def add_vulnerability(self, title: str, url: str, description: str, severity: str):
        """Add a vulnerability to the results"""
        vuln = {
            'title': title,
            'url': url,
            'description': description,
            'severity': severity,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.vulnerabilities.append(vuln)
        self.log(f"Found: {title} - {severity}", "VULN")

    def generate_report(self):
        """Generate scan report"""
        print(f"\n{Colors.OKBLUE}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}SCAN REPORT{Colors.ENDC}")
        print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}\n")

        if not self.vulnerabilities:
            print(f"{Colors.OKGREEN}No vulnerabilities found!{Colors.ENDC}\n")
            return

        # Group by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in self.vulnerabilities:
            severity_counts[vuln['severity']] += 1

        print(f"{Colors.BOLD}Summary:{Colors.ENDC}")
        print(f"  {Colors.FAIL}CRITICAL: {severity_counts['CRITICAL']}{Colors.ENDC}")
        print(f"  {Colors.WARNING}HIGH: {severity_counts['HIGH']}{Colors.ENDC}")
        print(f"  {Colors.OKCYAN}MEDIUM: {severity_counts['MEDIUM']}{Colors.ENDC}")
        print(f"  {Colors.OKGREEN}LOW: {severity_counts['LOW']}{Colors.ENDC}")
        print(f"\n{Colors.OKBLUE}{'-'*70}{Colors.ENDC}\n")

        # Print detailed findings
        for i, vuln in enumerate(self.vulnerabilities, 1):
            severity_color = {
                'CRITICAL': Colors.FAIL,
                'HIGH': Colors.WARNING,
                'MEDIUM': Colors.OKCYAN,
                'LOW': Colors.OKGREEN
            }.get(vuln['severity'], Colors.ENDC)

            print(f"{Colors.BOLD}[{i}] {vuln['title']}{Colors.ENDC}")
            print(f"    {severity_color}Severity: {vuln['severity']}{Colors.ENDC}")
            print(f"    URL: {vuln['url']}")
            print(f"    Description: {vuln['description']}")
            print(f"    Found at: {vuln['timestamp']}")
            print()

        print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}\n")

        # Save to JSON
        report_file = f"scan_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'target': self.target_url,
                'scan_time': time.strftime("%Y-%m-%d %H:%M:%S"),
                'summary': severity_counts,
                'vulnerabilities': self.vulnerabilities
            }, f, indent=4)

        self.log(f"Report saved to {report_file}", "SUCCESS")

    def scan(self):
        """Main scanning function"""
        start_time = time.time()
        self.print_banner()

        try:
            # Step 1: Crawl
            urls = self.crawl_site(self.target_url, depth=2)

            # Step 2: Run all OWASP Top 10 tests
            self.test_broken_access_control(urls)
            self.test_cryptographic_failures(urls)
            self.test_sql_injection(urls)
            self.test_xss(urls)
            self.test_insecure_design(urls)
            self.test_security_misconfiguration(urls)
            self.test_vulnerable_components(urls)
            self.test_authentication_failures(urls)
            self.test_integrity_failures(urls)
            self.test_logging_failures(urls)
            self.test_ssrf(urls)

            # Step 3: Generate report
            elapsed_time = time.time() - start_time
            self.log(f"Scan completed in {elapsed_time:.2f} seconds", "SUCCESS")
            self.generate_report()

        except KeyboardInterrupt:
            self.log("Scan interrupted by user", "WARNING")
        except Exception as e:
            self.log(f"Scan error: {str(e)}", "ERROR")

def main():
    parser = argparse.ArgumentParser(
        description='OWASP Top 10 Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.FAIL}Error: URL must start with http:// or https://{Colors.ENDC}")
        return

    scanner = VulnerabilityScanner(args.url, threads=args.threads, verbose=args.verbose)
    scanner.scan()

if __name__ == "__main__":
    main()
