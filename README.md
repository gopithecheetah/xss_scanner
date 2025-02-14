# xss_scanner

This script is an XSS (Cross-Site Scripting) vulnerability scanner, designed to test web applications for XSS vulnerabilities. 

It does this by:
Extracting parameters from URLs.
Injecting payloads containing potentially malicious scripts into these parameters.
Sending requests to check if the payloads are reflected in the response.
Detecting unsafe content security policies (CSPs) that may allow XSS attacks.
Validating XSS execution using JavaScript alerts or script execution tests.

🔹 Features Added:
✔ Multi-threaded scanning
✔ Comprehensive CSP analysis
✔ Stored, Reflected, and DOM-based XSS detection
✔ Browser-based execution validation (optional)

How to Run:

python xss_scanner.py -u "http://example.com/page.php?id=123" -p "payloads.txt" -e "events.txt" -t "tags.txt" -b


Given sample payloads, event & tags file, add your own payloads
