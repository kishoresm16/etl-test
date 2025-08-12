#!/usr/bin/env python3
import subprocess
import sys
import json
from tqdm import tqdm

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <domain>")
    sys.exit(1)

original_domain = sys.argv[1]

print(f"[+] Starting typosquat & cybersquat scan for: {original_domain}")

# Step 1: Get total permutations for ETA
list_cmd = ["python3", "dnstwist.py", "--format", "json", original_domain]
list_result = subprocess.run(list_cmd, capture_output=True, text=True)

if list_result.returncode != 0:
    print(f"[!] Error getting permutations: {list_result.stderr}")
    sys.exit(1)

try:
    permutations_list = json.loads(list_result.stdout)
except json.JSONDecodeError as e:
    print(f"[!] Failed to parse JSON output in list phase: {e}")
    sys.exit(1)

total_permutations = len(permutations_list)
print(f"[*] Total permutations found: {total_permutations}")

# Step 2: Run scan in text mode for live ETA
scan_cmd = ["python3", "dnstwist.py", "-t", "30", "-a", "-r", original_domain]
process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

results = []
with tqdm(total=total_permutations, desc="Scanning", bar_format="{l_bar}{bar} | ETA: {remaining}") as pbar:
    for line in process.stdout:
        line = line.strip()
        if not line or line.startswith("Domain"):  # skip header row
            continue
        parts = line.split()
        if len(parts) >= 1:
            domain = parts[0]
            ip = parts[1] if len(parts) > 1 and parts[1] != "-" else ""
            mx = parts[3] if len(parts) > 3 and parts[3] != "-" else ""
            if domain != original_domain:
                results.append({"domain": domain, "ip": ip, "mx": mx})
        pbar.update(1)

process.wait()

print("\n[+] Scan complete. JSON ready for ETL:")
print(json.dumps(results, indent=4))
