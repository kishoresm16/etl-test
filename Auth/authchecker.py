import requests
import argparse
import sys
import math
from collections import Counter
from urllib.parse import urljoin

def parse_args():
    parser = argparse.ArgumentParser(description="Broken Authentication Checker")
    parser.add_argument("url", help="Target URL to analyze (e.g., login page)")
    parser.add_argument("--login-url", help="Login endpoint URL (optional, for session fixation test)")
    parser.add_argument("--username", help="Test username for login (optional)")
    parser.add_argument("--password", help="Test password for login (optional)")
    parser.add_argument("--output", nargs="+", help="Output format (json) followed by optional filename (e.g., json output.json)")
    return parser.parse_args()

def check_cookie_security(cookies):
    results = []
    for cookie in cookies:
        name = cookie.name
        flags = []
        if cookie.get_nonstandard_attr('HttpOnly'):
            flags.append("HttpOnly")
        if cookie.secure:
            flags.append("Secure")
        samesite = cookie.get_nonstandard_attr('SameSite')
        if samesite:
            flags.append(f"SameSite={samesite}")
        
        issues = []
        if not cookie.get_nonstandard_attr('HttpOnly'):
            issues.append("Missing HttpOnly flag")
        if not cookie.secure:
            issues.append("Missing Secure flag")
        if not samesite:
            issues.append("Missing SameSite attribute")
        
        results.append({
            'name': name,
            'flags': flags or ["None"],
            'issues': issues or ["None"]
        })
    return results

def calculate_entropy(token):
    if not token:
        return 0
    char_counts = Counter(token)
    length = len(token)
    entropy = 0
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

def test_session_fixation(url, login_url, username, password):
    session = requests.Session()
    try:
        # Step 1: Get initial session ID
        pre_login_response = session.get(url, timeout=5)
        pre_login_cookies = session.cookies.get_dict()
        pre_login_session_id = pre_login_cookies.get('session') or pre_login_cookies.get('PHPSESSID')
        
        if not pre_login_session_id:
            return {"status": "Skipped", "reason": "No session cookie found before login"}

        # Step 2: Attempt login
        login_data = {'username': username, 'password': password}
        login_response = session.post(login_url, data=login_data, timeout=5)
        post_login_cookies = session.cookies.get_dict()
        post_login_session_id = post_login_cookies.get('session') or post_login_cookies.get('PHPSESSID')

        # Step 3: Check if session ID changed
        if pre_login_session_id == post_login_session_id:
            return {"status": "Vulnerable", "details": "Session ID did not change after login (possible session fixation)"}
        return {"status": "Secure", "details": "Session ID changed after login"}
    except requests.RequestException as e:
        return {"status": "Error", "reason": f"Failed to test session fixation: {e}"}

def main():
    args = parse_args()
    url = args.url
    print(f"Analyzing authentication for {url}...")

    # Step 1: Fetch cookies
    try:
        response = requests.get(url, timeout=5)
        cookies = response.cookies
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        sys.exit(1)

    # Step 2: Analyze cookie security
    cookie_results = check_cookie_security(cookies)

    # Step 3: Analyze token entropy
    session_cookie = cookies.get('session') or cookies.get('PHPSESSID')
    entropy = calculate_entropy(session_cookie) if session_cookie else 0
    entropy_warning = "Warning: Low entropy detected (potentially predictable token)" if entropy < 50 else "Entropy appears sufficient"

    # Step 4: Test session fixation
    fixation_result = test_session_fixation(url, args.login_url, args.username, args.password) if args.login_url and args.username and args.password else {"status": "Skipped", "reason": "Provide --login-url, --username, and --password to test session fixation"}

    # Prepare JSON output
    results = {
        "host": url,
        "cookie_security": cookie_results,
        "token_entropy": {
            "value": session_cookie[:10] + "..." if session_cookie else "None",
            "entropy": f"{entropy:.2f} bits" if session_cookie else "N/A",
            "assessment": entropy_warning
        },
        "session_fixation": fixation_result
    }

    # Handle output
    if args.output and args.output[0] == "json":
        output_data = json.dumps({"results": [results]}, indent=2)
        if len(args.output) > 1:
            with open(args.output[1], "w") as f:
                f.write(output_data)
        else:
            print(output_data)

if __name__ == "__main__":
    main()