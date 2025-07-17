Execution Methods
You can run the script in the following ways:

Single Domain via -d:
Command: python api_key_scanner.py -d x-cube.com
This scans only the x-cube.com domain.

Multiple Domains via -d:
Command: python api_key_scanner.py -d x-cube.com example.com
This scans both x-cube.com and example.com.

Domain List via -D:
Create a file (e.g., domains.txt) with one domain per line
Command: python api_key_scanner.py -D domains.txt
This scans all domains listed in domains.txt.

Combine -d and -D:
Command: python api_key_scanner.py -d x-cube.com -D domains.txt
This scans x-cube.com plus all domains in domains.txt.