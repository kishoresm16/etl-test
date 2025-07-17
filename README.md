Execution Methods
--
You can run the script in the following ways:

1. Single Domain via -d:

    Command: python api_key_scanner.py -d x-cube.com

    This scans only the x-cube.com domain.

2. Multiple Domains via -d:

    Command: python api_key_scanner.py -d x-cube.com example.com
    
    This scans both x-cube.com and example.com.

3. Domain List via -D:
    Create a file (e.g., domains.txt) with one domain per line

    Command: python api_key_scanner.py -D domains.txt
    
    This scans all domains listed in domains.txt.

4. Combine -d and -D:

    Command: python api_key_scanner.py -d x-cube.com -D domains.txt
    
    This scans x-cube.com plus all domains in domains.txt.

Output Methods
--
1. Output to Console (Default JSON):

    Command: python api_key_scanner.py -d x-cube.com --output json

    This scans x-cube.com and prints the JSON to the console.

2. Save to File:
    
    Command: python api_key_scanner.py -d x-cube.com --output json example.json
    
    This scans x-cube.com and saves the JSON output to example.json.

3. Multiple Domains with File Output:
    
    Command: python api_key_scanner.py -d x-cube.com example.com --output json output.json
    
    This scans both domains and saves the JSON to output.json.

4. Domain List with File Output:
    
    Command: python api_key_scanner.py -D domains.txt --output json results.json
    
    This scans all domains in domains.txt and saves the JSON to results.json.