import requests
import argparse
import sys
import json
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from requests.exceptions import HTTPError
from tqdm import tqdm
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import tempfile
import os

API_KEY_PATTERNS = {
    "aws_key": r'AKIA[0-9A-Z]{16}',
    "google_api_key": r'AIza[0-9A-Za-z-_]{35}',
    "stripe_live_key": r'sk_live_[0-9a-zA-Z]{24}',
    "stripe_public_key": r'pk_live_[0-9a-zA-Z]{24}',
    "github_token": r'ghp_[A-Za-z0-9]{36}',
    "ssh_private_key": r'-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+-----END (RSA|OPENSSH) PRIVATE KEY-----',
    "heroku_api_key": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "mailchimp_api_key": r'[A-Za-z0-9]{32}-us[0-9]{1,2}',
    "mailgun_private_key": r'key-[A-Za-z0-9]{32}',
    "sendgrid_api_token": r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    "stripe_test_key": r'sk_test_[0-9a-zA-Z]{24}',
    "square_access_token": r'sq0atp-[0-9A-Za-z\-_]{22}',
    "twilio_account_sid": r'AC[a-zA-Z0-9]{32}',
    "twilio_api_key": r'SK[a-zA-Z0-9]{32}',
    "slack_token": r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
    "slack_webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
}

def parse_args():
    parser = argparse.ArgumentParser(description="API Key Scanner with TruffleHog Validation")
    parser.add_argument("-d", "--domain", help="Single domain to check (e.g., example.com)")
    parser.add_argument("-D", "--domain-list", help="File containing list of subdomains")
    parser.add_argument("--output-file", help="Save results to JSON file")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads for validation")
    parser.add_argument("--no-trufflehog", action="store_true", help="Disable TruffleHog scanning, use regex only")
    return parser.parse_args()

def find_js_files(url, visited=None, max_depth=2, depth=0):
    if visited is None:
        visited = set()
    if depth > max_depth or url in visited:
        return set()
    
    js_files = set()
    try:
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
        visited.add(url)

        soup = BeautifulSoup(response.text, 'html.parser')
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.endswith('.js'):
                js_url = urljoin(url, src)
                js_files.add(js_url)
        
        for link in soup.find_all('a', href=True):
            href = urljoin(url, link['href'])
            if urlparse(href).netloc == urlparse(url).netloc and href not in visited:
                js_files.update(find_js_files(href, visited, max_depth, depth + 1))
                
    except HTTPError:
        pass
    except requests.RequestException as e:
        js_files.add(f"error:{url}:{str(e)}")
    
    return js_files

def validate_aws_key(key):
    try:
        # Simulate TruffleHog's AWS validation (requires secret key for full validation)
        return {"valid": False, "response": "N/A", "body": "AWS keys require secret key for validation"}
    except Exception as e:
        return {"valid": False, "response": "error", "body": str(e)}

def validate_google_api_key(key):
    try:
        response = requests.get(f"https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={key}", timeout=10)
        return {
            "valid": response.status_code == 200 or "quotaExceeded" in response.text,
            "response": str(response.status_code),
            "body": response.json().get("error", {}).get("message", "Key is active" if response.status_code == 200 else "Invalid or restricted")
        }
    except Exception as e:
        return {"valid": False, "response": "error", "body": str(e)}

def validate_stripe_key(key):
    try:
        headers = {"Authorization": f"Bearer {key}"}
        response = requests.get("https://api.stripe.com/v1/charges", headers=headers, timeout=10)
        return {
            "valid": response.status_code in [200, 403],
            "response": str(response.status_code),
            "body": "Key is active" if response.status_code in [200, 403] else response.json().get("error", {}).get("message", "Invalid key")
        }
    except Exception as e:
        return {"valid": False, "response": "error", "body": str(e)}

def validate_github_token(token):
    try:
        headers = {"Authorization": f"token {token}"}
        response = requests.get("https://api.github.com/user", headers=headers, timeout=10)
        return {
            "valid": response.status_code == 200,
            "response": str(response.status_code),
            "body": "Token is active" if response.status_code == 200 else response.json().get("message", "Invalid token")
        }
    except Exception as e:
        return {"valid": False, "response": "error", "body": str(e)}

def validate_mailchimp_key(key):
    try:
        dc = key.split('-')[-1]
        url = f"https://{dc}.api.mailchimp.com/3.0/"
        auth = ('anystring', key)
        response = requests.get(url, auth=auth, timeout=10)
        return {
            "valid": response.status_code == 200,
            "response": str(response.status_code),
            "body": "Key is active" if response.status_code == 200 else response.json().get("detail", "Invalid key")
        }
    except Exception as e:
        return {"valid": False, "response": "error", "body": str(e)}

def validate_sendgrid_key(key):
    try:
        headers = {"Authorization": f"Bearer {key}"}
        response = requests.get("https://api.sendgrid.com/v3/user/account", headers=headers, timeout=10)
        return {
            "valid": response.status_code == 200,
            "response": str(response.status_code),
            "body": "Key is active" if response.status_code == 200 else response.json().get("error", "Invalid key")
        }
    except Exception as e:
        return {"valid": False, "response": "error", "body": str(e)}

def validate_slack_token(token):
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get("https://slack.com/api/auth.test", headers=headers, timeout=10)
        data = response.json()
        return {
            "valid": data.get('ok', False),
            "response": str(response.status_code),
            "body": "Token is active" if data.get('ok') else data.get('error', "Invalid token")
        }
    except Exception as e:
        return {"valid": False, "response": "error", "body": str(e)}

API_VALIDATORS = {
    "google_api_key": validate_google_api_key,
    "stripe_live_key": validate_stripe_key,
    "stripe_test_key": validate_stripe_key,
    "stripe_secret_key": validate_stripe_key,
    "github_token": validate_github_token,
    "mailchimp_api_key": validate_mailchimp_key,
    "sendgrid_api_token": validate_sendgrid_key,
    "slack_token": validate_slack_token,
    "aws_key": validate_aws_key,
}

def run_trufflehog_scan(content, file_url):
    """Run TruffleHog scan on content using the Go binary"""
    findings = []
    try:
        # Create temporary file with content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name
        
        # Try different TruffleHog binary locations
        trufflehog_paths = ['trufflehog', './bin/trufflehog', '~/.local/bin/trufflehog']
        trufflehog_cmd = None
        
        for path in trufflehog_paths:
            try:
                subprocess.run([path, '--version'], capture_output=True, timeout=5)
                trufflehog_cmd = path
                break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        if not trufflehog_cmd:
            raise FileNotFoundError("TruffleHog binary not found in any expected location")
        
        # Run TruffleHog binary
        cmd = [trufflehog_cmd, 'filesystem', temp_file_path, '--json', '--no-update']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0 and result.stdout:
            # Parse TruffleHog JSON output
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        secret_data = json.loads(line)
                        findings.append({
                            'detector_name': secret_data.get('DetectorName', 'unknown'),
                            'secret': secret_data.get('Raw', ''),
                            'verified': secret_data.get('Verified', False),
                            'file': file_url
                        })
                    except json.JSONDecodeError:
                        continue
        
        # Clean up temp file
        os.unlink(temp_file_path)
        
    except subprocess.TimeoutExpired:
        print(f"TruffleHog scan timed out for {file_url}")
    except FileNotFoundError:
        print("TruffleHog binary not found. Please install TruffleHog or use regex-only mode.")
    except Exception as e:
        print(f"TruffleHog scan error for {file_url}: {str(e)}")
    
    return findings

def scan_js_file(js_url, use_trufflehog=True):
    findings = []
    try:
        response = requests.get(js_url, timeout=10)
        response.raise_for_status()
        content = response.text
        
        # Use TruffleHog to scan content if available
        if use_trufflehog:
            trufflehog_findings = run_trufflehog_scan(content, js_url)
            
            for secret in trufflehog_findings:
                key_type = secret['detector_name'].lower().replace(' ', '_').replace('-', '_')
                key_value = secret['secret']
                
                # Validate using TruffleHog's verification if available, else fall back to custom validators
                validation_result = {"valid": False, "response": "N/A", "body": "No validator available"}
                if secret['verified']:
                    validation_result = {
                        "valid": True,
                        "response": "verified",
                        "body": f"Verified by TruffleHog for {secret['detector_name']}"
                    }
                elif key_type in API_VALIDATORS:
                    validation_result = API_VALIDATORS[key_type](key_value)
                    
                findings.append({
                    "API_key": key_value,
                    "type": key_type,
                    "file": js_url,
                    "Response": validation_result["response"],
                    "Body": validation_result["body"],
                    "valid": validation_result["valid"]
                })
        
        # Fallback to regex-based detection for keys not caught by TruffleHog
        for key_type, pattern in API_KEY_PATTERNS.items():
            matches = re.findall(pattern, content, re.MULTILINE | re.DOTALL)
            for match in matches:
                key_value = match if isinstance(match, str) else match[0]
                if not any(f["API_key"] == key_value for f in findings):  # Avoid duplicates
                    validation_result = API_VALIDATORS.get(key_type, lambda x: {"valid": False, "response": "N/A", "body": "No validator available"})(key_value)
                    findings.append({
                        "API_key": key_value,
                        "type": key_type,
                        "file": js_url,
                        "Response": validation_result["response"],
                        "Body": validation_result["body"],
                        "valid": validation_result["valid"]
                    })
                
        time.sleep(0.5)  # Avoid rate limiting
                
    except Exception as e:
        findings.append({
            "API_key": None,
            "type": "error",
            "file": js_url,
            "Response": "error",
            "Body": str(e),
            "valid": False
        })
    
    return findings

def read_domains_from_file(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

def main():
    args = parse_args()
    
    if not args.domain and not args.domain_list:
        print("Error: At least one of -d or -D is required")
        sys.exit(1)

    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.domain_list:
        domains.extend(read_domains_from_file(args.domain_list))

    use_trufflehog = not args.no_trufflehog
    results = []
    
    print(f"Starting scan with {'TruffleHog + Regex' if use_trufflehog else 'Regex only'} detection...")
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_info = {}
        
        for domain in tqdm(domains, desc="Processing domains"):
            js_files_raw = find_js_files(domain)
            js_files = [f for f in js_files_raw if not f.startswith("error:")]
            errors = [f.split(":", 2) for f in js_files_raw if f.startswith("error:")]
            
            domain_result = {"host": domain, "js_files": list(js_files), "findings": [], "errors": []}
            for _, url, error in errors:
                domain_result["errors"].append({"url": url, "details": error})
            
            # Submit JS file scans to thread pool
            for js_file in js_files:
                future = executor.submit(scan_js_file, js_file, use_trufflehog)
                future_to_info[future] = (domain_result, js_file)
        
        # Collect results with progress bar
        for future in tqdm(as_completed(future_to_info), total=len(future_to_info), desc="Scanning JS files"):
            domain_result, js_file = future_to_info[future]
            try:
                findings = future.result()
                domain_result["findings"].extend(findings)
            except Exception as e:
                domain_result["errors"].append({"url": js_file, "details": str(e)})
        
        # Add domain results only once per domain
        seen_domains = set()
        for domain_result, _ in future_to_info.values():
            if domain_result["host"] not in seen_domains:
                results.append(domain_result)
                seen_domains.add(domain_result["host"])

    # Deduplicate findings
    for domain_result in results:
        seen_keys = set()
        unique_findings = []
        for finding in domain_result["findings"]:
            if finding["type"] != "error":
                key = (finding["type"], finding["API_key"])
                if key not in seen_keys:
                    seen_keys.add(key)
                    unique_findings.append(finding)
            else:
                unique_findings.append(finding)
        domain_result["findings"] = unique_findings

    # Output results
    output_data = {"results": results}
    if args.output_file:
        with open(args.output_file, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"Results saved to {args.output_file}")
    else:
        print(json.dumps(output_data, indent=2))

if __name__ == "__main__":
    main()
