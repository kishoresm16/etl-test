import requests
import argparse
import json
import logging
import re
from urllib.parse import urlencode
from datetime import datetime
from bs4 import BeautifulSoup
from PIL import Image
from io import BytesIO
import pytesseract
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------
# Logging Configuration
# ----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ----------------------------
# Constants
# ----------------------------
API_BASE_URL = "https://buckets.grayhatwarfare.com/api/v2/files"
ACCESS_TOKEN = "51624b1146ebde332719e0367e91a96d"
STOP_EXTENSIONS = "png,jpg,gif,jpeg,webp"

TEXT_EXTENSIONS = (".php", ".xml", ".csv", ".json", ".txt", ".log", ".sql", ".bak")
IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".webp", ".svg")

SENSITIVE_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"(?i)secret[_-]?key\s*[:=]\s*[\"']?[a-z0-9]{32,}",
    r"(?i)api[_-]?key\s*[:=]\s*[\"']?[a-z0-9]{20,}",
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    r"(?i)(password|passwd)\s*[:=]\s*[\"']?.{6,}",
    r"\b(?:\d[ -]*?){13,16}\b",
    r"(?i)(firebase|ghp_)[a-z0-9]{20,}"
]

# ----------------------------
# Argument Parser
# ----------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(description="Cloud Storage Exposure Validator (Threaded)")
    parser.add_argument("-d", "--domain", required=True, help="Target domain name (e.g., example.com)")
    parser.add_argument("--output-file", default="cloud_results.json", help="Output JSON file name")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    return parser.parse_args()

# ----------------------------
# Fetch Bucket Files
# ----------------------------
def fetch_bucket_data(domain):
    params = {
        "is_open": 1,
        "keywords": domain,
        "full-path": "true",
        "stopextensions": STOP_EXTENSIONS,
        "access_token": ACCESS_TOKEN,
        "start": 0,
        "limit": 1000
    }
    url = f"{API_BASE_URL}?{urlencode(params)}"
    logger.info(f"Querying: {url}")

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json().get("files", [])
    except Exception as e:
        logger.error(f"Failed to fetch data: {e}")
        return []

# ----------------------------
# Sensitive Data Checker
# ----------------------------
def contains_sensitive_data(text):
    return any(re.search(pattern, text) for pattern in SENSITIVE_PATTERNS)

# ----------------------------
# Analyze File
# ----------------------------
def analyze_file_for_secrets(file_url):
    try:
        response = requests.get(file_url, timeout=10)
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "")

        # Text-based files
        if "text" in content_type or file_url.endswith(TEXT_EXTENSIONS):
            if contains_sensitive_data(response.text):
                return True, "Sensitive data found in text file"

        # Image OCR
        elif file_url.endswith(IMAGE_EXTENSIONS):
            image = Image.open(BytesIO(response.content))
            extracted_text = pytesseract.image_to_string(image)
            if contains_sensitive_data(extracted_text):
                return True, "Sensitive text found in image"

        return False, "No sensitive data found"
    except Exception as e:
        return False, f"Error analyzing file: {e}"

# ----------------------------
# Domain Ownership Validation (Improved)
# ----------------------------
def is_url_referenced_in_domain(file_url, domain):
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        if file_url in response.text:
            return True

        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup.find_all(["a", "img", "script", "link"]):
            for attr in ["href", "src"]:
                if file_url in str(tag.get(attr, "")):
                    return True

        return False
    except Exception as e:
        logger.warning(f"Domain fetch error: {e}")
        return False

# ----------------------------
# Validate Single File (used in threading)
# ----------------------------
def validate_file(item, domain):
    try:
        bucket = item.get("bucket")
        filename = item.get("filename")
        full_path = item.get("fullPath")
        file_url = item.get("url")
        file_type = item.get("type")
        file_size = item.get("size", 0)

        ownership_valid = is_url_referenced_in_domain(file_url, domain)
        has_sensitive, sensitive_status = analyze_file_for_secrets(file_url)

        return {
            "Bucket name": bucket,
            "FileName": filename,
            "FilePath": full_path,
            "URL": file_url,
            "Type": file_type,
            "Size": file_size,
            "OwnershipValidated": ownership_valid,
            "Confidence": "High" if ownership_valid else "Low",
            "Finding": sensitive_status if has_sensitive else "Null/negligible"
        }
    except Exception as e:
        logger.error(f"Thread error: {e}")
        return {}

# ----------------------------
# Parallel Processing
# ----------------------------
def process_findings_threaded(files, domain, max_threads=10):
    results = []
    seen = set()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for item in files:
            identifier = (item.get("bucket"), item.get("filename"))
            if identifier not in seen:
                seen.add(identifier)
                futures.append(executor.submit(validate_file, item, domain))

        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    return results

# ----------------------------
# Save Results
# ----------------------------
def export_results(findings, output_file):
    output = {
        "timestamp": datetime.utcnow().isoformat(),
        "results": findings
    }

    try:
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        logger.info(f"Results saved: {output_file}")
    except IOError as e:
        logger.error(f"Write error: {e}")

    print(json.dumps(output, indent=2))

# ----------------------------
# Main
# ----------------------------
def main():
    args = parse_arguments()
    logger.info(f"Scanning: {args.domain} with {args.threads} threads")

    files = fetch_bucket_data(args.domain)
    validated_results = process_findings_threaded(files, args.domain, args.threads)
    export_results(validated_results, args.output_file)

if __name__ == "__main__":
    main()
