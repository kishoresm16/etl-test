import requests
import argparse
import sys
import json
import dns.resolver
from requests.exceptions import HTTPError
from urllib.parse import urlparse

def parse_args():
    parser = argparse.ArgumentParser(description="Cohosted Domains Finder with IPs")
    parser.add_argument("-d", "--domain", help="Single domain to check (e.g., example.com)", nargs="+")
    parser.add_argument("-D", "--domain-list", help="File containing list of domains (one per line)")
    parser.add_argument("--output", nargs="+", help="Output format (json) followed by optional filename (e.g., json output.json)")
    return parser.parse_args()

def resolve_ip(domain):
    """Resolve domain to IP address using DNS."""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return []
    except Exception as e:
        return [f"error: {str(e)}"]

def reverse_ip_lookup(ip):
    """Perform reverse IP lookup using hackertarget.com API."""
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
        domains = response.text.strip().split("\n")
        return [d for d in domains if d and d != "API count exceeded" and d != "No DNS A records found"]
    except HTTPError:
        return []
    except requests.RequestException as e:
        return [f"error: {str(e)}"]

def find_cohosted_domains(domain):
    """Find domains cohosted with the target domain, including their IPs."""
    result = {"host": domain, "ips": [], "cohosted_domains": [], "errors": []}
    
    # Resolve IP(s) for the target domain
    ips = resolve_ip(domain)
    if not ips:
        result["errors"].append({"type": "dns", "details": f"No IP resolved for {domain}"})
        return result
    
    for ip in ips:
        if ip.startswith("error:"):
            result["errors"].append({"type": "dns", "details": ip})
            continue
        result["ips"].append(ip)
        
        # Perform reverse IP lookup
        domains = reverse_ip_lookup(ip)
        for domain_entry in domains:
            if domain_entry.startswith("error:"):
                result["errors"].append({"type": "reverse_ip", "details": domain_entry})
            else:
                # Resolve IP(s) for the cohosted domain
                cohosted_ips = resolve_ip(domain_entry)
                result["cohosted_domains"].append({
                    "domain": domain_entry,
                    "ips": cohosted_ips if cohosted_ips else ["None"]
                })
    
    # Remove duplicates by domain name and sort
    seen = set()
    unique_domains = []
    for d in result["cohosted_domains"]:
        if d["domain"] not in seen:
            seen.add(d["domain"])
            unique_domains.append(d)
    result["cohosted_domains"] = sorted(unique_domains, key=lambda x: x["domain"])
    return result

def read_domains_from_file(file_path):
    """Read domains from a file."""
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
        domains.extend(args.domain)
    if args.domain_list:
        domains.extend(read_domains_from_file(args.domain_list))

    results = []
    for domain in domains:
        result = find_cohosted_domains(domain)
        results.append(result)

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