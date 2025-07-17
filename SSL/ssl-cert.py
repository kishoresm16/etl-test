import ssl
import socket
import datetime
import argparse
import sys
import requests
import json
from urllib.parse import urlparse
from OpenSSL import crypto

def parse_args():
    parser = argparse.ArgumentParser(description="SSL/TLS Certificate Validity Checker")
    parser.add_argument("-d", "--domain", help="Single or multiple domains to check (e.g., example.com)", nargs="+")
    parser.add_argument("-D", "--domain-list", help="File containing list of subdomains (one per line)")
    parser.add_argument("--output", nargs="+", help="Output format (json) followed by optional filename (e.g., json output.json)")
    return parser.parse_args()

def get_certificate(host, port=443, timeout=5):
    try:
        # Create SSL context
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as sslsock:
                cert = sslsock.getpeercert(True)
                # Convert DER to PEM
                pem = ssl.DER_cert_to_PEM_cert(cert)
                return crypto.load_certificate(crypto.FILETYPE_PEM, pem), None
    except (socket.timeout, ssl.SSLError, socket.gaierror, ConnectionRefusedError) as e:
        return None, str(e)

def check_certificate(host, cert_data):
    cert, error = cert_data
    if not cert:
        return {"host": host, "valid": False, "error": f"Failed to retrieve certificate: {error}"}

    result = {"host": host, "valid": True, "issues": []}

    # Check expiration
    try:
        not_after = datetime.datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        days_to_expire = (not_after - datetime.datetime.now(datetime.UTC)).days
        result["not_after"] = not_after.isoformat()
        result["days_to_expire"] = days_to_expire
        if days_to_expire < 0:
            result["valid"] = False
            result["issues"].append(f"Certificate expired on {not_after}")
        elif days_to_expire < 30:
            result["issues"].append(f"Certificate expires soon: {days_to_expire} days remaining")
    except Exception as e:
        result["valid"] = False
        result["issues"].append(f"Error parsing expiration date: {str(e)}")

    # Check issuer
    try:
        issuer = dict(cert.get_issuer().get_components())
        result["issuer"] = issuer.get(b"CN", b"Unknown").decode()
        if cert.get_issuer() == cert.get_subject():
            result["issues"].append("Certificate is self-signed")
    except Exception as e:
        result["issues"].append(f"Error parsing issuer: {str(e)}")

    # Check hostname match
    try:
        requests.get(f"https://{host}", timeout=5, verify=True)
    except requests.exceptions.SSLError as e:
        result["valid"] = False
        result["issues"].append(f"Hostname mismatch or invalid certificate: {str(e)}")
    except requests.exceptions.RequestException as e:
        result["issues"].append(f"Error verifying hostname: {str(e)}")

    return result

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
        domains.extend(args.domain)
    if args.domain_list:
        domains.extend(read_domains_from_file(args.domain_list))

    results = []
    for domain in domains:
        cert_data = get_certificate(domain)
        result = check_certificate(domain, cert_data)
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