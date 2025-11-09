#!/usr/bin/env python3
"""
Ultimate Web Security Scanner - Professional Edition
Features: OWASP Top 10 + Security Headers + Advanced Detection + HTML Reports
Author: Advanced Penetration Testing Framework
"""

import requests
import re
import time
import json
import argparse
import subprocess
import socket
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Tuple, Optional
from datetime import datetime
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ==================== RATE LIMITING DETECTION ====================
class RateLimitDetector:
    """Detect and analyze rate limiting mechanisms"""

    @staticmethod
    def detect_rate_limit(session: requests.Session, url: str) -> Dict:
        """Test for rate limiting"""
        print(f"\n{Colors.OKBLUE}[*] Testing Rate Limiting...{Colors.ENDC}")

        results = {
            'has_rate_limit': False,
            'threshold': 0,
            'headers_found': [],
            'bypass_techniques': []
        }

        # Send multiple rapid requests
        for i in range(15):
            try:
                response = session.get(url, timeout=5)

                # Check for rate limit headers
                rate_headers = {
                    'X-RateLimit-Limit': response.headers.get('X-RateLimit-Limit'),
                    'X-RateLimit-Remaining': response.headers.get('X-RateLimit-Remaining'),
                    'X-RateLimit-Reset': response.headers.get('X-RateLimit-Reset'),
                    'Retry-After': response.headers.get('Retry-After'),
                }

                for header, value in rate_headers.items():
                    if value:
                        results['headers_found'].append(f"{header}: {value}")

                # Check for rate limit status codes
                if response.status_code == 429:
                    results['has_rate_limit'] = True
                    results['threshold'] = i + 1
                    print(f"{Colors.WARNING}  [!] Rate limit detected after {i+1} requests{Colors.ENDC}")
                    break

            except Exception as e:
                pass

            time.sleep(0.1)

        # Suggest bypass techniques
        if results['has_rate_limit']:
            results['bypass_techniques'] = [
                "Use X-Forwarded-For header rotation",
                "Use X-Originating-IP, X-Remote-IP headers",
                "Implement delays between requests",
                "Use different User-Agents",
                "Use proxy rotation"
            ]
            print(f"{Colors.OKCYAN}  [+] Bypass Suggestions:{Colors.ENDC}")
            for technique in results['bypass_techniques']:
                print(f"      - {technique}")
        else:
            print(f"{Colors.OKGREEN}  [+] No rate limiting detected{Colors.ENDC}")

        return results

# ==================== WAF DETECTION ====================
class WAFDetector:
    """Detect Web Application Firewalls"""

    WAF_SIGNATURES = {
        'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
        'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
        'Akamai': ['akamai', 'ak-'],
        'Imperva': ['incap_', 'visid_incap'],
        'F5 BIG-IP': ['bigip', 'f5-'],
        'ModSecurity': ['mod_security', 'NOYB'],
        'Wordfence': ['wordfence'],
        'Sucuri': ['sucuri', 'x-sucuri'],
        'Barracuda': ['barra_counter_session'],
        'Fortinet': ['fortigate', 'fortiweb'],
    }

    @staticmethod
    def detect_waf(session: requests.Session, url: str) -> Dict:
        """Detect WAF presence and type"""
        print(f"\n{Colors.OKBLUE}[*] Detecting Web Application Firewall...{Colors.ENDC}")

        results = {
            'detected': False,
            'type': 'Unknown',
            'confidence': 'Low',
            'indicators': []
        }

        try:
            # Test with malicious payload
            test_url = f"{url}?test=<script>alert(1)</script>"
            response = session.get(test_url, timeout=10)

            # Check cookies and headers
            cookies = response.cookies
            headers = response.headers
            content = response.text.lower()

            # Check for WAF signatures
            for waf_name, signatures in WAFDetector.WAF_SIGNATURES.items():
                for sig in signatures:
                    sig_lower = sig.lower()

                    # Check in cookies
                    if any(sig_lower in cookie.lower() for cookie in cookies.keys()):
                        results['detected'] = True
                        results['type'] = waf_name
                        results['confidence'] = 'High'
                        results['indicators'].append(f"Cookie: {sig}")
                        break

                    # Check in headers
                    if any(sig_lower in header.lower() for header in headers.keys()):
                        results['detected'] = True
                        results['type'] = waf_name
                        results['confidence'] = 'High'
                        results['indicators'].append(f"Header: {sig}")
                        break

                    # Check in content
                    if sig_lower in content:
                        results['detected'] = True
                        results['type'] = waf_name
                        results['confidence'] = 'Medium'
                        results['indicators'].append(f"Content: {sig}")
                        break

                if results['detected']:
                    break

            # Check for generic WAF behavior
            if response.status_code in [403, 406, 419, 429, 501]:
                if not results['detected']:
                    results['detected'] = True
                    results['type'] = 'Generic WAF'
                    results['confidence'] = 'Low'
                    results['indicators'].append(f"Status Code: {response.status_code}")

            if results['detected']:
                print(f"{Colors.WARNING}  [!] WAF Detected: {results['type']}{Colors.ENDC}")
                print(f"  {Colors.OKCYAN}Confidence: {results['confidence']}{Colors.ENDC}")
                print(f"  {Colors.OKCYAN}Indicators:{Colors.ENDC}")
                for indicator in results['indicators']:
                    print(f"      - {indicator}")
            else:
                print(f"{Colors.OKGREEN}  [+] No WAF detected{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.FAIL}  [!] Error detecting WAF: {str(e)}{Colors.ENDC}")

        return results

# ==================== SUBDOMAIN ENUMERATION ====================
class SubdomainEnumerator:
    """Enumerate subdomains of target domain"""

    @staticmethod
    def enumerate_subdomains(domain: str, max_subdomains: int = 20) -> List[str]:
        """Find subdomains using DNS and common names"""
        print(f"\n{Colors.OKBLUE}[*] Enumerating Subdomains for {domain}...{Colors.ENDC}")

        subdomains = set()
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'staging', 'test',
            'api', 'app', 'portal', 'dashboard', 'secure', 'vpn', 'remote',
            'wiki', 'forum', 'support', 'help', 'docs', 'cdn', 'static',
            'img', 'images', 'media', 'assets', 'download', 'store', 'shop'
        ]

        # Try common subdomains
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.add(subdomain)
                print(f"{Colors.OKGREEN}  [+] Found: {subdomain}{Colors.ENDC}")

                if len(subdomains) >= max_subdomains:
                    break
            except:
                pass

        if not subdomains:
            print(f"{Colors.WARNING}  [!] No subdomains found{Colors.ENDC}")

        return list(subdomains)

# ==================== CVE DATABASE INTEGRATION ====================
class CVEChecker:
    """Check for known CVE vulnerabilities"""

    KNOWN_VULNERABLE_SOFTWARE = {
        'WordPress': {
            'indicators': ['wp-content', 'wp-includes', 'wp-admin'],
            'common_cves': ['CVE-2023-38000', 'CVE-2022-21661']
        },
        'Joomla': {
            'indicators': ['/administrator/', 'joomla'],
            'common_cves': ['CVE-2023-23752']
        },
        'Drupal': {
            'indicators': ['/sites/default/', 'drupal'],
            'common_cves': ['CVE-2018-7600']
        },
        'Apache': {
            'indicators': ['apache'],
            'common_cves': ['CVE-2021-41773', 'CVE-2021-42013']
        },
    }

    @staticmethod
    def check_cves(url: str, response: requests.Response) -> List[Dict]:
        """Check for known CVEs based on software detection"""
        print(f"\n{Colors.OKBLUE}[*] Checking for Known CVEs...{Colors.ENDC}")

        potential_cves = []
        content = response.text.lower()
        headers = response.headers

        # Check server header
        server = headers.get('Server', '').lower()

        for software, data in CVEChecker.KNOWN_VULNERABLE_SOFTWARE.items():
            # Check indicators
            for indicator in data['indicators']:
                if indicator.lower() in content or indicator.lower() in server:
                    for cve in data['common_cves']:
                        potential_cves.append({
                            'software': software,
                            'cve': cve,
                            'indicator': indicator
                        })
                    break

        if potential_cves:
            print(f"{Colors.WARNING}  [!] Potential CVE Matches:{Colors.ENDC}")
            for cve_info in potential_cves:
                print(f"      - {cve_info['software']}: {cve_info['cve']}")
        else:
            print(f"{Colors.OKGREEN}  [+] No known CVE patterns detected{Colors.ENDC}")

        return potential_cves

# ==================== API ENDPOINT DISCOVERY ====================
class APIEndpointDiscoverer:
    """Discover hidden API endpoints"""

    COMMON_API_PATHS = [
        '/api', '/api/v1', '/api/v2', '/api/v3',
        '/rest', '/rest/v1', '/rest/v2',
        '/graphql', '/gql',
        '/services', '/ws', '/webservices',
        '/api/users', '/api/auth', '/api/login',
        '/api/admin', '/api/config', '/api/debug',
        '/.well-known', '/swagger', '/api-docs',
    ]

    @staticmethod
    def discover_endpoints(base_url: str, session: requests.Session) -> List[str]:
        """Discover API endpoints"""
        print(f"\n{Colors.OKBLUE}[*] Discovering API Endpoints...{Colors.ENDC}")

        found_endpoints = []

        for path in APIEndpointDiscoverer.COMMON_API_PATHS:
            test_url = urljoin(base_url, path)
            try:
                response = session.get(test_url, timeout=5)
                if response.status_code in [200, 201, 401, 403]:
                    found_endpoints.append(test_url)
                    print(f"{Colors.OKGREEN}  [+] Found: {test_url} [{response.status_code}]{Colors.ENDC}")
            except:
                pass

        if not found_endpoints:
            print(f"{Colors.WARNING}  [!] No API endpoints discovered{Colors.ENDC}")

        return found_endpoints

# ==================== WEBSOCKET TESTING ====================
class WebSocketTester:
    """Test WebSocket connections"""

    @staticmethod
    def test_websocket(url: str, soup: BeautifulSoup) -> Dict:
        """Check for WebSocket usage"""
        print(f"\n{Colors.OKBLUE}[*] Testing for WebSocket Usage...{Colors.ENDC}")

        results = {
            'detected': False,
            'endpoints': [],
            'vulnerabilities': []
        }

        # Search for WebSocket URLs in scripts
        scripts = soup.find_all('script')
        ws_pattern = r'wss?://[^"\'\s]+'

        for script in scripts:
            if script.string:
                matches = re.findall(ws_pattern, script.string)
                if matches:
                    results['detected'] = True
                    results['endpoints'].extend(matches)

        if results['detected']:
            print(f"{Colors.WARNING}  [!] WebSocket detected{Colors.ENDC}")
            for endpoint in results['endpoints']:
                print(f"      - {endpoint}")
            results['vulnerabilities'].append(
                "WebSocket detected - Ensure proper authentication and encryption"
            )
        else:
            print(f"{Colors.OKGREEN}  [+] No WebSocket usage detected{Colors.ENDC}")

        return results

# ==================== CSRF TOKEN DETECTION ====================
class CSRFDetector:
    """Detect CSRF protection mechanisms"""

    @staticmethod
    def detect_csrf_tokens(soup: BeautifulSoup, cookies: dict) -> Dict:
        """Check for CSRF protection"""
        print(f"\n{Colors.OKBLUE}[*] Checking CSRF Protection...{Colors.ENDC}")

        results = {
            'tokens_found': [],
            'protected': False,
            'forms_without_tokens': 0
        }

        # Check for CSRF tokens in forms
        forms = soup.find_all('form')
        csrf_patterns = ['csrf', 'token', '_token', 'authenticity_token', 'xsrf']

        for form in forms:
            has_token = False
            inputs = form.find_all('input')

            for input_field in inputs:
                name = input_field.get('name', '').lower()
                if any(pattern in name for pattern in csrf_patterns):
                    has_token = True
                    token_value = input_field.get('value', '')[:20]
                    results['tokens_found'].append(f"{name}: {token_value}...")
                    break

            if not has_token:
                results['forms_without_tokens'] += 1

        # Check for CSRF cookies
        csrf_cookies = [key for key in cookies.keys() if any(p in key.lower() for p in csrf_patterns)]
        if csrf_cookies:
            results['tokens_found'].extend(csrf_cookies)

        results['protected'] = len(results['tokens_found']) > 0

        if results['protected']:
            print(f"{Colors.OKGREEN}  [+] CSRF tokens detected{Colors.ENDC}")
            for token in results['tokens_found'][:3]:
                print(f"      - {token}")
        else:
            print(f"{Colors.FAIL}  [!] No CSRF protection detected{Colors.ENDC}")

        if results['forms_without_tokens'] > 0:
            print(f"{Colors.WARNING}  [!] {results['forms_without_tokens']} form(s) without CSRF tokens{Colors.ENDC}")

        return results

# ==================== HTML REPORT GENERATOR ====================
class HTMLReportGenerator:
    """Generate beautiful HTML reports"""

    @staticmethod
    def generate_report(scan_data: Dict, output_file: str):
        """Generate comprehensive HTML report"""
        print(f"\n{Colors.OKBLUE}[*] Generating HTML Report...{Colors.ENDC}")

        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; }}
        .content {{ padding: 30px; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-bottom: 20px; }}
        .score-card {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .score-item {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }}
        .score-item h3 {{ color: #666; font-size: 0.9em; margin-bottom: 10px; }}
        .score-item .value {{ font-size: 2em; font-weight: bold; color: #333; }}
        .vulnerability {{ background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; margin-bottom: 15px; }}
        .severity-critical {{ border-left: 4px solid #dc3545; }}
        .severity-high {{ border-left: 4px solid #fd7e14; }}
        .severity-medium {{ border-left: 4px solid #ffc107; }}
        .severity-low {{ border-left: 4px solid #28a745; }}
        .badge {{ display: inline-block; padding: 5px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #28a745; color: white; }}
        .badge-success {{ background: #28a745; color: white; }}
        .badge-warning {{ background: #ffc107; color: black; }}
        .badge-danger {{ background: #dc3545; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .grade-A {{ color: #28a745; font-size: 3em; font-weight: bold; }}
        .grade-B {{ color: #17a2b8; font-size: 3em; font-weight: bold; }}
        .grade-C {{ color: #ffc107; font-size: 3em; font-weight: bold; }}
        .grade-D {{ color: #fd7e14; font-size: 3em; font-weight: bold; }}
        .grade-F {{ color: #dc3545; font-size: 3em; font-weight: bold; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; border-radius: 0 0 10px 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <p>Target: {target}</p>
            <p>Scan Date: {scan_time}</p>
        </div>

        <div class="content">
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="score-card">
                    <div class="score-item">
                        <h3>Security Score</h3>
                        <div class="value">{security_score}%</div>
                    </div>
                    <div class="score-item">
                        <h3>Overall Grade</h3>
                        <div class="value grade-{grade}">{grade}</div>
                    </div>
                    <div class="score-item">
                        <h3>Critical Issues</h3>
                        <div class="value" style="color: #dc3545;">{critical_count}</div>
                    </div>
                    <div class="score-item">
                        <h3>Total Findings</h3>
                        <div class="value">{total_vulns}</div>
                    </div>
                </div>
            </div>

            {security_headers_section}

            {vulnerabilities_section}

            {advanced_features_section}
        </div>

        <div class="footer">
            <p>Generated by Ultimate Web Security Scanner v2.0</p>
            <p>© 2025 Advanced Penetration Testing Framework</p>
        </div>
    </div>
</body>
</html>
        """

        # Build sections
        security_headers_html = HTMLReportGenerator._build_headers_section(scan_data.get('security_headers', {}))
        vulnerabilities_html = HTMLReportGenerator._build_vulnerabilities_section(scan_data.get('vulnerabilities', []))
        advanced_html = HTMLReportGenerator._build_advanced_section(scan_data.get('advanced_tests', {}))

        # Calculate summary stats
        vulns = scan_data.get('vulnerabilities', [])
        critical_count = sum(1 for v in vulns if v.get('severity') == 'CRITICAL')
        security_score = scan_data.get('security_headers', {}).get('percentage', 0)
        grade = HTMLReportGenerator._calculate_grade(security_score)

        # Fill template
        html_content = html_template.format(
            target=scan_data.get('target', 'Unknown'),
            scan_time=scan_data.get('scan_time', 'Unknown'),
            security_score=int(security_score),
            grade=grade,
            critical_count=critical_count,
            total_vulns=len(vulns),
            security_headers_section=security_headers_html,
            vulnerabilities_section=vulnerabilities_html,
            advanced_features_section=advanced_html
        )

        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"{Colors.OKGREEN}  [+] HTML report saved to: {output_file}{Colors.ENDC}")

    @staticmethod
    def _build_headers_section(headers_data: Dict) -> str:
        if not headers_data:
            return ""

        present = headers_data.get('present', [])
        missing = headers_data.get('missing', [])
        misconfigured = headers_data.get('misconfigured', [])

        html = '<div class="section"><h2>🔒 Security Headers Analysis</h2>'
        html += '<table><tr><th>Header</th><th>Status</th></tr>'

        for header in present:
            html += f'<tr><td>{header}</td><td><span class="badge badge-success">✓ Present</span></td></tr>'
        for header in misconfigured:
            html += f'<tr><td>{header}</td><td><span class="badge badge-warning">⚠ Misconfigured</span></td></tr>'
        for header in missing:
            html += f'<tr><td>{header}</td><td><span class="badge badge-danger">✗ Missing</span></td></tr>'

        html += '</table></div>'
        return html

    @staticmethod
    def _build_vulnerabilities_section(vulnerabilities: List) -> str:
        if not vulnerabilities:
            return '<div class="section"><h2>✅ No Vulnerabilities Found</h2></div>'

        html = '<div class="section"><h2>🚨 Vulnerabilities</h2>'

        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'MEDIUM').lower()
            html += f'<div class="vulnerability severity-{severity}">'
            html += f'<h3>[{i}] {vuln.get("title", "Unknown")} '
            html += f'<span class="badge badge-{severity}">{vuln.get("severity", "MEDIUM")}</span></h3>'
            html += f'<p><strong>URL:</strong> {vuln.get("url", "N/A")}</p>'
            html += f'<p><strong>Description:</strong> {vuln.get("description", "N/A")}</p>'
            html += f'<p><strong>Found at:</strong> {vuln.get("timestamp", "N/A")}</p>'
            html += '</div>'

        html += '</div>'
        return html

    @staticmethod
    def _build_advanced_section(advanced_data: Dict) -> str:
        if not advanced_data:
            return ""

        html = '<div class="section"><h2>🔍 Advanced Analysis</h2>'

        # Rate Limiting
        if 'rate_limit' in advanced_data:
            rl = advanced_data['rate_limit']
            status = "Detected" if rl.get('has_rate_limit') else "Not Detected"
            html += f'<p><strong>Rate Limiting:</strong> {status}</p>'

        # WAF Detection
        if 'waf' in advanced_data:
            waf = advanced_data['waf']
            if waf.get('detected'):
                html += f'<p><strong>WAF Detected:</strong> {waf.get("type", "Unknown")}</p>'

        # API Endpoints
        if 'api_endpoints' in advanced_data:
            endpoints = advanced_data['api_endpoints']
            if endpoints:
                html += f'<p><strong>API Endpoints Found:</strong> {len(endpoints)}</p>'

        html += '</div>'
        return html

    @staticmethod
    def _calculate_grade(percentage: float) -> str:
        if percentage >= 90: return "A"
        elif percentage >= 80: return "B"
        elif percentage >= 70: return "C"
        elif percentage >= 60: return "D"
        else: return "F"

# Continue in next part...

# ==================== MAIN SCANNER CLASS (INTEGRATED) ====================
class UltimateVulnerabilityScanner:
    """Ultimate scanner with all features integrated"""

    def __init__(self, target_url: str, threads: int = 10, verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.threads = threads
        self.verbose = verbose
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.scan_results: Dict = {
            'target': target_url,
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'security_headers': {},
            'vulnerabilities': [],
            'advanced_tests': {}
        }
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def print_banner(self):
        """Print scanner banner"""
        banner = f"""
{Colors.OKBLUE}{'='*70}
  ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗
  ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
  ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗  
  ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝  
  ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗
   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
{Colors.ENDC}
{Colors.OKGREEN}         Ultimate Web Security Scanner - Professional Edition{Colors.ENDC}
{Colors.WARNING}         Target: {self.target_url}{Colors.ENDC}
{Colors.OKBLUE}{'='*70}{Colors.ENDC}
        """
        print(banner)

    def log(self, message: str, level: str = "INFO"):
        """Logging function"""
        timestamp = time.strftime("%H:%M:%S")
        colors = {
            "INFO": Colors.OKBLUE,
            "SUCCESS": Colors.OKGREEN,
            "WARNING": Colors.WARNING,
            "ERROR": Colors.FAIL,
            "VULN": Colors.FAIL + Colors.BOLD
        }
        color = colors.get(level, Colors.ENDC)
        if self.verbose or level in ["SUCCESS", "VULN", "WARNING"]:
            print(f"[{timestamp}] {color}[{level}]{Colors.ENDC} {message}")

    def scan(self):
        """Main scanning orchestration"""
        start_time = time.time()
        self.print_banner()

        try:
            # Initial request
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}PHASE 1: ADVANCED RECONNAISSANCE{Colors.ENDC}")
            print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")

            # Advanced Tests
            self.scan_results['advanced_tests']['rate_limit'] = RateLimitDetector.detect_rate_limit(
                self.session, self.target_url
            )

            self.scan_results['advanced_tests']['waf'] = WAFDetector.detect_waf(
                self.session, self.target_url
            )

            self.scan_results['advanced_tests']['subdomains'] = SubdomainEnumerator.enumerate_subdomains(
                self.base_domain, max_subdomains=10
            )

            self.scan_results['advanced_tests']['cves'] = CVEChecker.check_cves(
                self.target_url, response
            )

            self.scan_results['advanced_tests']['api_endpoints'] = APIEndpointDiscoverer.discover_endpoints(
                self.target_url, self.session
            )

            self.scan_results['advanced_tests']['websocket'] = WebSocketTester.test_websocket(
                self.target_url, soup
            )

            self.scan_results['advanced_tests']['csrf'] = CSRFDetector.detect_csrf_tokens(
                soup, self.session.cookies
            )

            # Security Headers (from previous version)
            print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}PHASE 2: SECURITY HEADERS ANALYSIS{Colors.ENDC}")
            print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
            self.test_security_headers(response)

            # OWASP Top 10 Tests
            print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}PHASE 3: OWASP TOP 10 VULNERABILITY SCAN{Colors.ENDC}")
            print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")

            urls = self.crawl_site(self.target_url, depth=2)
            self.test_sql_injection(urls)
            self.test_xss(urls)
            self.test_broken_access_control(urls)

            # Generate Reports
            elapsed_time = time.time() - start_time
            self.log(f"Scan completed in {elapsed_time:.2f} seconds", "SUCCESS")

            self.generate_reports()

        except KeyboardInterrupt:
            self.log("Scan interrupted by user", "WARNING")
        except Exception as e:
            self.log(f"Scan error: {str(e)}", "ERROR")

    def test_security_headers(self, response):
        """Test security headers (simplified from previous version)"""
        headers = response.headers

        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy',
            'Permissions-Policy'
        ]

        present = []
        missing = []

        for header in security_headers:
            if header in headers:
                present.append(header)
                print(f"{Colors.OKGREEN}  [+] {header}: Present{Colors.ENDC}")
            else:
                missing.append(header)
                print(f"{Colors.FAIL}  [!] {header}: Missing{Colors.ENDC}")
                self.add_vulnerability(
                    f"Missing Security Header - {header}",
                    self.target_url,
                    f"Security header {header} is not configured",
                    "HIGH"
                )

        score = (len(present) / len(security_headers)) * 100
        self.scan_results['security_headers'] = {
            'present': present,
            'missing': missing,
            'percentage': score
        }

        print(f"\n{Colors.OKCYAN}  Security Headers Score: {score:.1f}%{Colors.ENDC}")

    def crawl_site(self, url: str, depth: int = 2) -> List[str]:
        """Crawl site (simplified)"""
        self.log(f"Crawling site (depth: {depth})...", "INFO")
        discovered_urls = set([url])

        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True)[:20]:  # Limit to 20 links
                href = link['href']
                full_url = urljoin(url, href)
                if urlparse(full_url).netloc == self.base_domain:
                    discovered_urls.add(full_url)
        except:
            pass

        self.log(f"Discovered {len(discovered_urls)} URLs", "SUCCESS")
        return list(discovered_urls)

    def test_sql_injection(self, urls: List[str]):
        """Test SQL injection (simplified)"""
        self.log("Testing for SQL Injection...", "INFO")

        payloads = ["' OR '1'='1", "admin'--"]
        errors = ["SQL syntax", "mysql", "mysqli"]

        for url in urls[:5]:
            if '=' in url:
                for payload in payloads:
                    test_url = url + payload
                    try:
                        response = self.session.get(test_url, timeout=5)
                        if any(error in response.text.lower() for error in errors):
                            self.add_vulnerability(
                                "SQL Injection",
                                test_url,
                                f"Potential SQL injection with payload: {payload}",
                                "CRITICAL"
                            )
                            return
                    except:
                        pass

    def test_xss(self, urls: List[str]):
        """Test XSS (simplified)"""
        self.log("Testing for XSS...", "INFO")

        payload = "<script>alert(1)</script>"

        for url in urls[:5]:
            if '=' in url:
                test_url = url + payload
                try:
                    response = self.session.get(test_url, timeout=5)
                    if payload in response.text:
                        self.add_vulnerability(
                            "Cross-Site Scripting (XSS)",
                            test_url,
                            "Reflected XSS vulnerability detected",
                            "HIGH"
                        )
                        return
                except:
                    pass

    def test_broken_access_control(self, urls: List[str]):
        """Test access control (simplified)"""
        self.log("Testing for Broken Access Control...", "INFO")

        for url in urls[:5]:
            if 'id=' in url.lower():
                try:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    if 'id' in params:
                        original_id = params['id'][0]
                        if original_id.isdigit():
                            test_id = str(int(original_id) + 1)
                            test_url = url.replace(f"id={original_id}", f"id={test_id}")
                            response = self.session.get(test_url, timeout=5)
                            if response.status_code == 200:
                                self.add_vulnerability(
                                    "Potential IDOR",
                                    test_url,
                                    "ID parameter may be vulnerable to IDOR",
                                    "HIGH"
                                )
                                return
                except:
                    pass

    def add_vulnerability(self, title: str, url: str, description: str, severity: str):
        """Add vulnerability"""
        vuln = {
            'title': title,
            'url': url,
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.vulnerabilities.append(vuln)
        self.scan_results['vulnerabilities'].append(vuln)
        self.log(f"Found: {title}", "VULN")

    def generate_reports(self):
        """Generate all reports"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}GENERATING REPORTS{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")

        # JSON Report
        json_file = f"scan_report_{int(time.time())}.json"
        with open(json_file, 'w') as f:
            json.dump(self.scan_results, f, indent=4)
        print(f"{Colors.OKGREEN}  [+] JSON report saved: {json_file}{Colors.ENDC}")

        # HTML Report
        html_file = f"scan_report_{int(time.time())}.html"
        HTMLReportGenerator.generate_report(self.scan_results, html_file)

        # Console Summary
        print(f"\n{Colors.BOLD}SCAN SUMMARY{Colors.ENDC}")
        print(f"  Total Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"  Critical: {sum(1 for v in self.vulnerabilities if v['severity'] == 'CRITICAL')}")
        print(f"  High: {sum(1 for v in self.vulnerabilities if v['severity'] == 'HIGH')}")
        print(f"  Medium: {sum(1 for v in self.vulnerabilities if v['severity'] == 'MEDIUM')}")
        print(f"  Low: {sum(1 for v in self.vulnerabilities if v['severity'] == 'LOW')}")

def main():
    parser = argparse.ArgumentParser(
        description='Ultimate Web Security Scanner - Professional Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ultimate_scanner.py -u https://example.com
  python3 ultimate_scanner.py -u https://example.com -v
  python3 ultimate_scanner.py -u https://example.com -t 20
        """
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.FAIL}Error: URL must start with http:// or https://{Colors.ENDC}")
        return

    scanner = UltimateVulnerabilityScanner(args.url, threads=args.threads, verbose=args.verbose)
    scanner.scan()

if __name__ == "__main__":
    main()
