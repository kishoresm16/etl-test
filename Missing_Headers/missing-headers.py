import requests
import pandas as pd
import argparse
import json

# Function to read URLs from a file
def read_urls(file_path):
    with open(file_path, 'r') as file:
        urls = file.readlines()
    return [url.strip() for url in urls]

# List of security headers to check for
security_headers = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Feature-Policy"
]

# Function to check for missing security headers
def check_security_headers(urls):
    results = []
    
    for url in urls:
        # Ensure URL starts with http:// or https://
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        try:
            response = requests.get(url, timeout=5)
            headers = response.headers
            missing = [header for header in security_headers if header not in headers]
            
            if missing:
                results.append({
                    "url": url,
                    "missing_headers": missing
                })
        
        except requests.exceptions.RequestException:
            continue
    
    return results

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Check for missing security headers in websites.")
    parser.add_argument('-d', '--domain', type=str, nargs="*", help="Single or multiple domains to check (e.g., example.com)")
    parser.add_argument('-D', '--domains-file', type=str, help="File containing list of domains")
    parser.add_argument("--output", nargs="+", help="Output format (json) followed by optional filename (e.g., json output.json)")
    
    args = parser.parse_args()
    
    # Prepare URLs list
    urls = []
    if args.domain:
        urls.extend(args.domain)
    if args.domains_file:
        urls.extend(read_urls(args.domains_file))
    
    if not urls:
        parser.error("You must provide at least one domain with -d or a domains file with -D.")
    
    # Get missing headers for the provided URLs
    results = check_security_headers(urls)
    
    # Handle output
    if args.output and args.output[0] == "json":
        output_data = json.dumps({"results": results}, indent=2)
        if len(args.output) > 1:
            with open(args.output[1], "w") as f:
                f.write(output_data)
        else:
            print(output_data)

if __name__ == "__main__":
    main()