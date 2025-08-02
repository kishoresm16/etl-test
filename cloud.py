import requests
import argparse
import sys
import json
from urllib.parse import urlencode
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# API configuration
API_BASE_URL = "https://buckets.grayhatwarfare.com/api/v2/files"
ACCESS_TOKEN = "51624b1146ebde332719e0367e91a96d"
STOP_EXTENSIONS = "png,jpg,gif,jpeg,webp"

def parse_args():
    parser = argparse.ArgumentParser(description="Cloud Storage File Scanner using GrayhatWarfare API")
    parser.add_argument("-d", "--domain", default="Domainhere", help="Domain to search for (default: Domainhere)")
    parser.add_argument("--output-file", default="cloud_files.json", help="Output JSON file (default: cloud_files.json)")
    return parser.parse_args()

def extract_data(domain):
    """Extract data from GrayhatWarfare API."""
    try:
        params = {
            "is_open": 1,
            "keywords": domain,
            "full-path": "true",
            "stopextensions": STOP_EXTENSIONS,
            "access_token": ACCESS_TOKEN,
            "start": 0,
            "limit": 1000  # Adjust based on API limits
        }
        url = f"{API_BASE_URL}?{urlencode(params)}"
        logger.info(f"Querying API: {url}")
        
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        if not data.get("files"):
            logger.warning(f"No files found for domain: {domain}")
            return []
        
        return data["files"]
    except requests.exceptions.RequestException as e:
        logger.error(f"Error querying API for domain {domain}: {str(e)}")
        return []

def transform_data(files):
    """Transform API response into required format."""
    findings = []
    seen_files = set()  # Avoid duplicates
    
    for file_data in files:
        file_key = (file_data.get("bucket"), file_data.get("filename"))
        if file_key in seen_files:
            continue
        
        seen_files.add(file_key)
        finding = {
            "Bucket name": file_data.get("bucket", ""),
            "FileName": file_data.get("filename", ""),
            "FilePath": file_data.get("fullPath", ""),
            "URL": file_data.get("url", ""),
            "Type": file_data.get("type", ""),
            "Size": file_data.get("size", 0),
            "Finding": "Null/negligible"  # Default as per requirement
        }
        findings.append(finding)
    
    return findings

def load_data(findings, output_file):
    """Save findings to JSON file."""
    output_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "results": findings
    }
    
    # Save to JSON file
    try:
        with open(output_file, "w") as f:
            json.dump(output_data, f, indent=2)
        logger.info(f"Results saved to {output_file}")
    except IOError as e:
        logger.error(f"Error saving to {output_file}: {str(e)}")
    
    # Print JSON to console
    print(json.dumps(output_data, indent=2))

def main():
    args = parse_args()
    logger.info(f"Starting cloud storage scan for domain: {args.domain}")
    
    # ETL Process
    files = extract_data(args.domain)  # Extract
    findings = transform_data(files)    # Transform
    load_data(findings, args.output_file)  # Load

if __name__ == "__main__":
    main()
