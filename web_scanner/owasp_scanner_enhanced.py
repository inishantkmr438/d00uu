#!/usr/bin/env python3
"""
Enhanced OWASP Top 10 Vulnerability Scanner with Security Headers Analysis
Author: Advanced Penetration Testing Tool
Description: Automated scanner with comprehensive security header validation
"""

import requests
import re
import time
import json
import argparse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Tuple
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

class SecurityHeadersChecker:
    """Comprehensive security headers validation"""

    # Complete list of security headers with descriptions and recommendations
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'HTTP Strict Transport Security (HSTS)',
            'purpose': 'Forces browsers to use HTTPS connections only',
            'recommended_value': 'max-age=31536000; includeSubDomains; preload',
            'risk_level': 'HIGH',
            'references': 'https://owasp.org/www-project-secure-headers/#http-strict-transport-security',
        },
        'Content-Security-Policy': {
            'description': 'Content Security Policy (CSP)',
            'purpose': 'Prevents XSS, clickjacking, and code injection attacks',
            'recommended_value': "default-src 'self'; script-src 'self'; object-src 'none'",
            'risk_level': 'HIGH',
            'references': 'https://owasp.org/www-project-secure-headers/#content-security-policy',
        },
        'X-Frame-Options': {
            'description': 'X-Frame-Options',
            'purpose': 'Prevents clickjacking attacks by controlling iframe embedding',
            'recommended_value': 'DENY or SAMEORIGIN',
            'risk_level': 'MEDIUM',
            'references': 'https://owasp.org/www-project-secure-headers/#x-frame-options',
        },
        'X-Content-Type-Options': {
            'description': 'X-Content-Type-Options',
            'purpose': 'Prevents MIME-sniffing attacks',
            'recommended_value': 'nosniff',
            'risk_level': 'MEDIUM',
            'references': 'https://owasp.org/www-project-secure-headers/#x-content-type-options',
        },
        'X-XSS-Protection': {
            'description': 'X-XSS-Protection (Legacy)',
            'purpose': 'Enables browser XSS filters (deprecated, use CSP instead)',
            'recommended_value': '1; mode=block',
            'risk_level': 'LOW',
            'references': 'https://owasp.org/www-project-secure-headers/#x-xss-protection',
        },
        'Referrer-Policy': {
            'description': 'Referrer Policy',
            'purpose': 'Controls how much referrer information is shared',
            'recommended_value': 'no-referrer or strict-origin-when-cross-origin',
            'risk_level': 'MEDIUM',
            'references': 'https://owasp.org/www-project-secure-headers/#referrer-policy',
        },
        'Permissions-Policy': {
            'description': 'Permissions Policy (formerly Feature-Policy)',
            'purpose': 'Controls which browser features can be used',
            'recommended_value': 'geolocation=(), microphone=(), camera=()',
            'risk_level': 'MEDIUM',
            'references': 'https://owasp.org/www-project-secure-headers/#permissions-policy',
        },
        'X-Permitted-Cross-Domain-Policies': {
            'description': 'X-Permitted-Cross-Domain-Policies',
            'purpose': 'Controls cross-domain policies for Adobe Flash and PDF',
            'recommended_value': 'none',
            'risk_level': 'LOW',
            'references': 'https://owasp.org/www-project-secure-headers/',
        },
        'Cross-Origin-Embedder-Policy': {
            'description': 'Cross-Origin-Embedder-Policy (COEP)',
            'purpose': 'Prevents loading cross-origin resources without explicit permission',
            'recommended_value': 'require-corp',
            'risk_level': 'MEDIUM',
            'references': 'https://web.dev/coop-coep/',
        },
        'Cross-Origin-Opener-Policy': {
            'description': 'Cross-Origin-Opener-Policy (COOP)',
            'purpose': 'Isolates browsing context from cross-origin windows',
            'recommended_value': 'same-origin',
            'risk_level': 'MEDIUM',
            'references': 'https://web.dev/coop-coep/',
        },
        'Cross-Origin-Resource-Policy': {
            'description': 'Cross-Origin-Resource-Policy (CORP)',
            'purpose': 'Prevents other domains from reading responses',
            'recommended_value': 'same-origin',
            'risk_level': 'MEDIUM',
            'references': 'https://resourcepolicy.fyi/',
        },
        'Cache-Control': {
            'description': 'Cache Control',
            'purpose': 'Controls caching behavior for sensitive pages',
            'recommended_value': 'no-store, no-cache, must-revalidate (for sensitive pages)',
            'risk_level': 'MEDIUM',
            'references': 'https://owasp.org/www-project-secure-headers/',
        },
        'Expect-CT': {
            'description': 'Expect-CT (Deprecated)',
            'purpose': 'Certificate Transparency enforcement (deprecated)',
            'recommended_value': 'max-age=86400, enforce',
            'risk_level': 'LOW',
            'references': 'https://owasp.org/www-project-secure-headers/',
        },
    }

    @staticmethod
    def check_hsts(value: str) -> Tuple[bool, str]:
        """Validate HSTS header"""
        if not value:
            return False, "HSTS header is missing"

        issues = []

        # Check max-age
        max_age_match = re.search(r'max-age=(\d+)', value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                issues.append(f"max-age is {max_age} seconds (recommended: 31536000 or more)")
        else:
            issues.append("max-age directive is missing")

        # Check includeSubDomains
        if 'includesubdomains' not in value.lower():
            issues.append("includeSubDomains directive is missing")

        # Check preload
        if 'preload' not in value.lower():
            issues.append("preload directive is missing (optional but recommended)")

        if issues:
            return False, "; ".join(issues)
        return True, "HSTS properly configured"

    @staticmethod
    def check_csp(value: str) -> Tuple[bool, str]:
        """Validate Content Security Policy"""
        if not value:
            return False, "CSP header is missing"

        issues = []
        weak_patterns = [
            ('unsafe-inline', "Contains 'unsafe-inline' which weakens XSS protection"),
            ('unsafe-eval', "Contains 'unsafe-eval' which allows eval() execution"),
            ('*', "Contains wildcard '*' which allows any source"),
        ]

        value_lower = value.lower()
        for pattern, message in weak_patterns:
            if pattern in value_lower:
                issues.append(message)

        # Check for default-src
        if 'default-src' not in value_lower:
            issues.append("Missing 'default-src' directive")

        if issues:
            return False, "; ".join(issues)
        return True, "CSP is properly configured"

    @staticmethod
    def check_x_frame_options(value: str) -> Tuple[bool, str]:
        """Validate X-Frame-Options"""
        if not value:
            return False, "X-Frame-Options header is missing"

        value_upper = value.upper()
        if value_upper not in ['DENY', 'SAMEORIGIN']:
            return False, f"Value '{value}' is not recommended (use DENY or SAMEORIGIN)"

        return True, f"X-Frame-Options properly set to {value_upper}"

    @staticmethod
    def check_x_content_type_options(value: str) -> Tuple[bool, str]:
        """Validate X-Content-Type-Options"""
        if not value:
            return False, "X-Content-Type-Options header is missing"

        if value.lower() != 'nosniff':
            return False, f"Value '{value}' is incorrect (should be 'nosniff')"

        return True, "X-Content-Type-Options properly set"

    @staticmethod
    def check_referrer_policy(value: str) -> Tuple[bool, str]:
        """Validate Referrer-Policy"""
        if not value:
            return False, "Referrer-Policy header is missing"

        safe_values = [
            'no-referrer',
            'no-referrer-when-downgrade',
            'origin',
            'origin-when-cross-origin',
            'same-origin',
            'strict-origin',
            'strict-origin-when-cross-origin',
        ]

        if value.lower() not in safe_values:
            return False, f"Value '{value}' may not provide adequate protection"

        return True, f"Referrer-Policy properly set to {value}"

    @staticmethod
    def check_permissions_policy(value: str) -> Tuple[bool, str]:
        """Validate Permissions-Policy"""
        if not value:
            return False, "Permissions-Policy header is missing"

        # Check if dangerous features are disabled
        dangerous_features = ['geolocation', 'microphone', 'camera', 'payment']
        issues = []

        for feature in dangerous_features:
            if feature in value and '()' not in value[value.index(feature):value.index(feature)+20]:
                issues.append(f"{feature} is not explicitly disabled")

        if issues:
            return False, "; ".join(issues)

        return True, "Permissions-Policy is properly configured"

class VulnerabilityScanner:
    """Main vulnerability scanner class with enhanced security header checks"""

    def __init__(self, target_url: str, threads: int = 10, verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.threads = threads
        self.verbose = verbose
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.security_headers_result: Dict = {}
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        self.headers_checker = SecurityHeadersChecker()

    def print_banner(self):
        """Print scanner banner"""
        banner = f"""
{Colors.OKBLUE}{'='*70}
   ____  _       _____    _____ ____    _____              _   ___  
  / __ \\| |     / /   |  / ___// __ \\  /_  _/ ___  ____  / | / _ \\ 
 / / / /| | /| / / /| |  \\__ \\/ /_/ /   / /  / _ \\/ __ \\/  |/ / / |
/ /_/ / | |/ |/ / ___ | ___/ / ____/   / /  /  __/ /_/ / /|  / /_/ |
\\____/  |__/|__/_/  |_|/____/_/       /_/   \\___/ .___/_/ |_/\\____/ 
                                               /_/                   
{Colors.ENDC}
{Colors.OKGREEN}Enhanced OWASP Top 10 + Security Headers Scanner{Colors.ENDC}
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

    # ==================== ENHANCED SECURITY HEADERS CHECK ====================
    def test_security_headers(self):
        """Comprehensive security headers analysis"""
        self.log("Analyzing Security Headers (13 headers)...", "INFO")

        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers

            self.security_headers_result = {
                'present': [],
                'missing': [],
                'misconfigured': [],
                'score': 0,
                'max_score': 0
            }

            print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}SECURITY HEADERS ANALYSIS{Colors.ENDC}")
            print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")

            for header_name, header_info in self.headers_checker.SECURITY_HEADERS.items():
                header_value = headers.get(header_name, '')
                self.security_headers_result['max_score'] += 10

                # Check if header is present
                if not header_value:
                    self.security_headers_result['missing'].append(header_name)
                    self.add_vulnerability(
                        f"Missing Security Header - {header_info['description']}",
                        self.target_url,
                        f"{header_info['purpose']}. Recommended: {header_info['recommended_value']}",
                        header_info['risk_level']
                    )

                    print(f"{Colors.FAIL}✗ {header_name}{Colors.ENDC}")
                    print(f"  Status: {Colors.FAIL}MISSING{Colors.ENDC}")
                    print(f"  Risk Level: {self._get_risk_color(header_info['risk_level'])}{header_info['risk_level']}{Colors.ENDC}")
                    print(f"  Purpose: {header_info['purpose']}")
                    print(f"  Recommended: {Colors.OKGREEN}{header_info['recommended_value']}{Colors.ENDC}")
                    print(f"  Reference: {header_info['references']}")
                    print()

                else:
                    # Validate header value
                    is_valid, message = self._validate_header(header_name, header_value)

                    if is_valid:
                        self.security_headers_result['present'].append(header_name)
                        self.security_headers_result['score'] += 10

                        print(f"{Colors.OKGREEN}✓ {header_name}{Colors.ENDC}")
                        print(f"  Status: {Colors.OKGREEN}PRESENT & VALID{Colors.ENDC}")
                        print(f"  Current Value: {Colors.OKCYAN}{header_value}{Colors.ENDC}")
                        print(f"  Validation: {Colors.OKGREEN}{message}{Colors.ENDC}")
                        print()
                    else:
                        self.security_headers_result['misconfigured'].append(header_name)
                        self.security_headers_result['score'] += 5  # Partial credit

                        self.add_vulnerability(
                            f"Misconfigured Security Header - {header_info['description']}",
                            self.target_url,
                            f"Current: {header_value}. Issue: {message}",
                            "MEDIUM"
                        )

                        print(f"{Colors.WARNING}⚠ {header_name}{Colors.ENDC}")
                        print(f"  Status: {Colors.WARNING}PRESENT BUT WEAK{Colors.ENDC}")
                        print(f"  Current Value: {Colors.WARNING}{header_value}{Colors.ENDC}")
                        print(f"  Issue: {Colors.FAIL}{message}{Colors.ENDC}")
                        print(f"  Recommended: {Colors.OKGREEN}{header_info['recommended_value']}{Colors.ENDC}")
                        print()

            # Calculate and display score
            score_percentage = (self.security_headers_result['score'] / self.security_headers_result['max_score']) * 100
            self.security_headers_result['percentage'] = score_percentage

            print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}SECURITY HEADERS SCORE{Colors.ENDC}")
            print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
            print(f"  Score: {self._get_score_color(score_percentage)}{self.security_headers_result['score']}/{self.security_headers_result['max_score']} ({score_percentage:.1f}%){Colors.ENDC}")
            print(f"  {Colors.OKGREEN}✓ Present & Valid: {len(self.security_headers_result['present'])}{Colors.ENDC}")
            print(f"  {Colors.WARNING}⚠ Misconfigured: {len(self.security_headers_result['misconfigured'])}{Colors.ENDC}")
            print(f"  {Colors.FAIL}✗ Missing: {len(self.security_headers_result['missing'])}{Colors.ENDC}")
            print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}\n")

            # Grade based on score
            grade = self._calculate_grade(score_percentage)
            grade_color = self._get_grade_color(grade)
            print(f"  Overall Grade: {grade_color}{grade}{Colors.ENDC}")
            print(f"  {self._get_grade_description(grade)}")
            print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}\n")

        except Exception as e:
            self.log(f"Error analyzing headers: {str(e)}", "ERROR")

    def _validate_header(self, header_name: str, header_value: str) -> Tuple[bool, str]:
        """Validate specific header value"""
        validators = {
            'Strict-Transport-Security': self.headers_checker.check_hsts,
            'Content-Security-Policy': self.headers_checker.check_csp,
            'X-Frame-Options': self.headers_checker.check_x_frame_options,
            'X-Content-Type-Options': self.headers_checker.check_x_content_type_options,
            'Referrer-Policy': self.headers_checker.check_referrer_policy,
            'Permissions-Policy': self.headers_checker.check_permissions_policy,
        }

        if header_name in validators:
            return validators[header_name](header_value)

        # For headers without specific validators, just check presence
        return True, "Header is present"

    def _get_risk_color(self, risk_level: str) -> str:
        """Get color based on risk level"""
        colors = {
            'CRITICAL': Colors.FAIL,
            'HIGH': Colors.FAIL,
            'MEDIUM': Colors.WARNING,
            'LOW': Colors.OKCYAN
        }
        return colors.get(risk_level, Colors.ENDC)

    def _get_score_color(self, percentage: float) -> str:
        """Get color based on score percentage"""
        if percentage >= 80:
            return Colors.OKGREEN
        elif percentage >= 60:
            return Colors.OKCYAN
        elif percentage >= 40:
            return Colors.WARNING
        else:
            return Colors.FAIL

    def _calculate_grade(self, percentage: float) -> str:
        """Calculate letter grade"""
        if percentage >= 90:
            return "A"
        elif percentage >= 80:
            return "B"
        elif percentage >= 70:
            return "C"
        elif percentage >= 60:
            return "D"
        else:
            return "F"

    def _get_grade_color(self, grade: str) -> str:
        """Get color for grade"""
        if grade in ['A', 'B']:
            return Colors.OKGREEN
        elif grade == 'C':
            return Colors.OKCYAN
        elif grade == 'D':
            return Colors.WARNING
        else:
            return Colors.FAIL

    def _get_grade_description(self, grade: str) -> str:
        """Get description for grade"""
        descriptions = {
            'A': "Excellent security header configuration",
            'B': "Good security header configuration with minor improvements needed",
            'C': "Moderate security header configuration - several improvements needed",
            'D': "Poor security header configuration - immediate attention required",
            'F': "Critical security header issues - urgent remediation required"
        }
        return descriptions.get(grade, "")

    # ==================== OWASP TESTS (Previous implementations) ====================
    def test_broken_access_control(self, urls: List[str]):
        """Test for broken access control vulnerabilities"""
        self.log("Testing for Broken Access Control (OWASP #1)...", "INFO")

        for url in urls:
            if any(param in url.lower() for param in ['id=', 'user=', 'account=']):
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                for param, value in params.items():
                    if value[0].isdigit():
                        test_values = [str(int(value[0]) + 1), str(int(value[0]) - 1)]
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
                                        f"Parameter '{param}' may be vulnerable to IDOR",
                                        "HIGH"
                                    )
                                    break
                            except:
                                pass

    def test_sql_injection(self, urls: List[str]):
        """Test for SQL injection vulnerabilities"""
        self.log("Testing for SQL Injection (OWASP #3)...", "INFO")

        sqli_payloads = ["' OR '1'='1", "' OR '1'='1' --", "admin'--"]
        error_patterns = ["SQL syntax", "mysql_fetch", "mysqli", "syntax error"]

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
                            for error in error_patterns:
                                if error.lower() in response.text.lower():
                                    self.add_vulnerability(
                                        "SQL Injection",
                                        test_url,
                                        f"Parameter '{param}' appears vulnerable. Payload: {payload}",
                                        "CRITICAL"
                                    )
                                    return
                        except:
                            pass

    def test_xss(self, urls: List[str]):
        """Test for Cross-Site Scripting"""
        self.log("Testing for XSS (OWASP #3)...", "INFO")

        xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

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
                            if payload in response.text:
                                self.add_vulnerability(
                                    "Cross-Site Scripting (XSS)",
                                    test_url,
                                    f"Parameter '{param}' is vulnerable to reflected XSS",
                                    "HIGH"
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
        if self.verbose:
            self.log(f"Found: {title} - {severity}", "VULN")

    def generate_report(self):
        """Generate comprehensive scan report"""
        print(f"\n{Colors.OKBLUE}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}VULNERABILITY SCAN REPORT{Colors.ENDC}")
        print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}\n")

        if not self.vulnerabilities:
            print(f"{Colors.OKGREEN}No vulnerabilities found!{Colors.ENDC}\n")
        else:
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for vuln in self.vulnerabilities:
                severity_counts[vuln['severity']] += 1

            print(f"{Colors.BOLD}Summary:{Colors.ENDC}")
            print(f"  {Colors.FAIL}CRITICAL: {severity_counts['CRITICAL']}{Colors.ENDC}")
            print(f"  {Colors.WARNING}HIGH: {severity_counts['HIGH']}{Colors.ENDC}")
            print(f"  {Colors.OKCYAN}MEDIUM: {severity_counts['MEDIUM']}{Colors.ENDC}")
            print(f"  {Colors.OKGREEN}LOW: {severity_counts['LOW']}{Colors.ENDC}")
            print(f"\n{Colors.OKBLUE}{'-'*70}{Colors.ENDC}\n")

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
                print()

        print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}\n")

        # Save comprehensive report
        report_file = f"security_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'target': self.target_url,
                'scan_time': time.strftime("%Y-%m-%d %H:%M:%S"),
                'security_headers': self.security_headers_result,
                'vulnerabilities': self.vulnerabilities
            }, f, indent=4)

        self.log(f"Report saved to {report_file}", "SUCCESS")

    def scan(self):
        """Main scanning function"""
        start_time = time.time()
        self.print_banner()

        try:
            # Step 1: Security Headers Analysis
            self.test_security_headers()

            # Step 2: Crawl
            urls = self.crawl_site(self.target_url, depth=2)

            # Step 3: OWASP Tests
            self.test_broken_access_control(urls)
            self.test_sql_injection(urls)
            self.test_xss(urls)

            # Step 4: Generate report
            elapsed_time = time.time() - start_time
            self.log(f"Scan completed in {elapsed_time:.2f} seconds", "SUCCESS")
            self.generate_report()

        except KeyboardInterrupt:
            self.log("Scan interrupted by user", "WARNING")
        except Exception as e:
            self.log(f"Scan error: {str(e)}", "ERROR")

def main():
    parser = argparse.ArgumentParser(
        description='Enhanced OWASP Top 10 + Security Headers Scanner'
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.FAIL}Error: URL must start with http:// or https://{Colors.ENDC}")
        return

    scanner = VulnerabilityScanner(args.url, threads=args.threads, verbose=args.verbose)
    scanner.scan()

if __name__ == "__main__":
    main()
