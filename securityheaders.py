#!/usr/bin/env python3
"""
Security Headers Compliance Scanner
===================================
A professional tool for auditing HTTP security headers across multiple domains.
Checks compliance against industry-standard security headers and generates
comprehensive reports.

Author: Security Team
Version: 1.0
"""

import requests
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

# Industry-standard security headers for compliance checking
CRITICAL_SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "Content-Security-Policy": "Prevents XSS and injection attacks",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Referrer-Policy": "Controls referrer information disclosure",
    "X-XSS-Protection": "Legacy XSS protection (deprecated but monitored)",
    "Permissions-Policy": "Controls browser feature permissions"
}

class SecurityHeadersScanner:
    """Professional security headers compliance scanner."""
    
    def __init__(self, timeout=10, user_agent="SecurityScanner/1.0"):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self.results = []
        
    def scan_domain(self, domain):
        """
        Scan a single domain for security headers compliance.
        
        Args:
            domain (str): Domain name to scan
            
        Returns:
            dict: Scan results containing status and missing headers
        """
        # Normalize domain input
        if not domain.startswith(('http://', 'https://')):
            # Try HTTPS first, fallback to HTTP
            urls = [f"https://{domain}", f"http://{domain}"]
        else:
            urls = [domain]
        
        for url in urls:
            try:
                response = self.session.get(
                    url, 
                    timeout=self.timeout, 
                    allow_redirects=True,
                    verify=True
                )
                
                # Extract final URL after redirects
                final_url = response.url
                parsed_url = urlparse(final_url)
                protocol = parsed_url.scheme.upper()
                
                # Analyze headers
                headers = {k.lower(): v for k, v in response.headers.items()}
                missing_headers = []
                present_headers = []
                
                for header, description in CRITICAL_SECURITY_HEADERS.items():
                    header_lower = header.lower()
                    if header_lower in headers:
                        present_headers.append(header)
                    else:
                        missing_headers.append(header)
                
                # Calculate compliance score
                total_headers = len(CRITICAL_SECURITY_HEADERS)
                present_count = len(present_headers)
                compliance_score = (present_count / total_headers) * 100
                
                # Determine status
                if compliance_score == 100:
                    status = "COMPLIANT"
                    risk_level = "LOW"
                elif compliance_score >= 80:
                    status = "MOSTLY_COMPLIANT"
                    risk_level = "MEDIUM"
                elif compliance_score >= 60:
                    status = "PARTIALLY_COMPLIANT"
                    risk_level = "HIGH"
                else:
                    status = "NON_COMPLIANT"
                    risk_level = "CRITICAL"
                
                return {
                    'domain': domain,
                    'final_url': final_url,
                    'protocol': protocol,
                    'status': status,
                    'risk_level': risk_level,
                    'compliance_score': compliance_score,
                    'missing_headers': missing_headers,
                    'present_headers': present_headers,
                    'response_code': response.status_code,
                    'error': None
                }
                
            except requests.exceptions.SSLError as e:
                # If HTTPS fails, try HTTP if not already tried
                if url.startswith('https://') and f"http://{domain}" not in urls:
                    continue
                return self._create_error_result(domain, f"SSL Certificate Error: {str(e)}")
                
            except requests.exceptions.Timeout:
                return self._create_error_result(domain, "Connection Timeout")
                
            except requests.exceptions.ConnectionError as e:
                return self._create_error_result(domain, f"Connection Failed: {str(e)}")
                
            except requests.exceptions.RequestException as e:
                return self._create_error_result(domain, f"Request Error: {str(e)}")
        
        return self._create_error_result(domain, "All connection attempts failed")
    
    def _create_error_result(self, domain, error_msg):
        """Create a standardized error result."""
        return {
            'domain': domain,
            'final_url': 'N/A',
            'protocol': 'N/A',
            'status': 'ERROR',
            'risk_level': 'UNKNOWN',
            'compliance_score': 0,
            'missing_headers': list(CRITICAL_SECURITY_HEADERS.keys()),
            'present_headers': [],
            'response_code': 'N/A',
            'error': error_msg
        }
    
    def scan_multiple_domains(self, domains):
        """
        Scan multiple domains and store results.
        
        Args:
            domains (list): List of domain names to scan
        """
        total_domains = len(domains)
        print(f"[INFO] Initiating security headers scan for {total_domains} domains")
        print(f"[INFO] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 80)
        
        for i, domain in enumerate(domains, 1):
            print(f"[{i:3d}/{total_domains}] Scanning: {domain:<40}", end=" ... ")
            
            start_time = time.time()
            result = self.scan_domain(domain)
            scan_time = time.time() - start_time
            
            result['scan_time'] = round(scan_time, 2)
            self.results.append(result)
            
            # Print immediate status
            if result['status'] == 'ERROR':
                print(f"ERROR ({scan_time:.2f}s)")
            else:
                print(f"{result['status']} - {result['compliance_score']:.0f}% ({scan_time:.2f}s)")
        
        print("-" * 80)
        print(f"[INFO] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def generate_report(self):
        """Generate a comprehensive security compliance report."""
        if not self.results:
            print("[ERROR] No scan results available. Run scan first.")
            return
        
        # Report Header
        print("\n" + "=" * 120)
        print("SECURITY HEADERS COMPLIANCE REPORT".center(120))
        print("=" * 120)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"Total Domains Scanned: {len(self.results)}")
        print("=" * 120)
        
        # Summary Statistics
        compliant = len([r for r in self.results if r['status'] == 'COMPLIANT'])
        mostly_compliant = len([r for r in self.results if r['status'] == 'MOSTLY_COMPLIANT'])
        partially_compliant = len([r for r in self.results if r['status'] == 'PARTIALLY_COMPLIANT'])
        non_compliant = len([r for r in self.results if r['status'] == 'NON_COMPLIANT'])
        errors = len([r for r in self.results if r['status'] == 'ERROR'])
        
        avg_compliance = sum(r['compliance_score'] for r in self.results if r['status'] != 'ERROR') / max(len(self.results) - errors, 1)
        
        print(f"\nCOMPLIANCE SUMMARY:")
        print(f"├─ Fully Compliant (100%):     {compliant:3d} domains")
        print(f"├─ Mostly Compliant (≥80%):    {mostly_compliant:3d} domains")
        print(f"├─ Partially Compliant (≥60%): {partially_compliant:3d} domains")
        print(f"├─ Non-Compliant (<60%):       {non_compliant:3d} domains")
        print(f"└─ Scan Errors:                {errors:3d} domains")
        print(f"\nAverage Compliance Score: {avg_compliance:.1f}%")
        
        # Detailed Results Table
        print(f"\nDETAILED SCAN RESULTS:")
        print("-" * 120)
        header = f"{'DOMAIN':<35} {'STATUS':<18} {'SCORE':<7} {'PROTOCOL':<9} {'MISSING HEADERS':<50}"
        print(header)
        print("-" * 120)
        
        # Sort results by compliance score (descending)
        sorted_results = sorted(self.results, key=lambda x: x['compliance_score'], reverse=True)
        
        for result in sorted_results:
            domain = result['domain'][:34]
            status = result['status']
            score = f"{result['compliance_score']:.0f}%" if result['status'] != 'ERROR' else 'N/A'
            protocol = result['protocol'][:8]
            
            if result['status'] == 'ERROR':
                missing_info = result['error'][:49]
            elif result['missing_headers']:
                missing_info = ", ".join(result['missing_headers'])[:49]
            else:
                missing_info = "None"
            
            # Add visual indicators
            if result['status'] == 'COMPLIANT':
                status_display = f"✅ {status}"
            elif result['status'] == 'ERROR':
                status_display = f"❌ {status}"
            elif result['compliance_score'] >= 80:
                status_display = f"⚠️  {status}"
            else:
                status_display = f"🔴 {status}"
            
            print(f"{domain:<35} {status_display:<25} {score:<7} {protocol:<9} {missing_info:<50}")
        
        # Risk Assessment
        print(f"\nRISK ASSESSMENT:")
        critical_risk = len([r for r in self.results if r['risk_level'] == 'CRITICAL'])
        high_risk = len([r for r in self.results if r['risk_level'] == 'HIGH'])
        medium_risk = len([r for r in self.results if r['risk_level'] == 'MEDIUM'])
        low_risk = len([r for r in self.results if r['risk_level'] == 'LOW'])
        
        print(f"🔴 Critical Risk Domains: {critical_risk}")
        print(f"🟠 High Risk Domains:     {high_risk}")
        print(f"🟡 Medium Risk Domains:   {medium_risk}")
        print(f"🟢 Low Risk Domains:      {low_risk}")
        
        # Recommendations
        print(f"\nRECOMMENDations:")
        if critical_risk > 0:
            print("🔴 URGENT: Implement missing security headers on critical risk domains immediately")
        if high_risk > 0:
            print("🟠 HIGH PRIORITY: Address security headers on high-risk domains within 1 week")
        if medium_risk > 0:
            print("🟡 MEDIUM PRIORITY: Improve security headers on medium-risk domains within 1 month")
        
        print(f"\nMost Common Missing Headers:")
        header_counts = {}
        for result in self.results:
            if result['status'] != 'ERROR':
                for header in result['missing_headers']:
                    header_counts[header] = header_counts.get(header, 0) + 1
        
        for header, count in sorted(header_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / len([r for r in self.results if r['status'] != 'ERROR'])) * 100
            description = CRITICAL_SECURITY_HEADERS[header]
            print(f"├─ {header}: {count} domains ({percentage:.1f}%) - {description}")
        
        print("=" * 120)


def load_domains_from_file(file_path):
    """Load domains from a text file."""
    try:
        with open(file_path, "r", encoding='utf-8') as f:
            domains = []
            for line_num, line in enumerate(f, 1):
                domain = line.strip()
                if domain and not domain.startswith('#'):  # Skip empty lines and comments
                    domains.append(domain)
            return domains
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Error reading file {file_path}: {e}")
        sys.exit(1)


def main():
    """Main application entry point."""
    if len(sys.argv) != 2:
        print("Security Headers Compliance Scanner")
        print("=" * 40)
        print(f"Usage: python3 {sys.argv[0]} <domains_file>")
        print("\nExample:")
        print(f"  python3 {sys.argv[0]} subdomains.txt")
        print("\nFile format:")
        print("  - One domain per line")
        print("  - Lines starting with # are treated as comments")
        print("  - Empty lines are ignored")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Load domains
    domains = load_domains_from_file(file_path)
    
    if not domains:
        print("[ERROR] No valid domains found in the file.")
        sys.exit(1)
    
    # Initialize scanner
    scanner = SecurityHeadersScanner(timeout=10)
    
    # Perform scan
    scanner.scan_multiple_domains(domains)
    
    # Generate report
    scanner.generate_report()


if __name__ == "__main__":
    main()
