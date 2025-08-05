import requests
import argparse
import json
import logging
from datetime import datetime

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
API_ENDPOINT = "https://api.breachsense.com/creds"
DEFAULT_LICENSE_KEY = "da085668fd9ab288286d0f25ef726124"

# ----------------------------
# Argument Parser
# ----------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(description="BreachSense Credential Lookup Tool")
    parser.add_argument("-s", "--search", required=True, help="Search term (email, domain, or username)")
    parser.add_argument("--license", default=DEFAULT_LICENSE_KEY, help="BreachSense API license key")
    parser.add_argument("--page", type=int, default=1, help="Result page number (default: 1)")
    parser.add_argument("--output", default="breachsense_results.json", help="Output JSON file")
    return parser.parse_args()

# ----------------------------
# Query BreachSense API
# ----------------------------
def query_breachsense(license_key, search_term, page):
    try:
        params = {
            "lic": license_key,
            "s": search_term,
            "p": page
        }
        logger.info(f"Querying BreachSense API for: {search_term} (page {page})")
        response = requests.get(API_ENDPOINT, params=params, timeout=15)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"API request failed: {e}")
        return {}

# ----------------------------
# Save Results
# ----------------------------
def save_results(data, output_file):
    output = {
        "timestamp": datetime.utcnow().isoformat(),
        "results": data
    }
    try:
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        logger.info(f"Results saved to {output_file}")
    except IOError as e:
        logger.error(f"Failed to save results: {e}")

    print(json.dumps(output, indent=2))

# ----------------------------
# Main
# ----------------------------
def main():
    args = parse_arguments()
    data = query_breachsense(args.license, args.search, args.page)
    save_results(data, args.output)

if __name__ == "__main__":
    main()
