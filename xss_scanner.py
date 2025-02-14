import requests
import re
import argparse
import warnings
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options

# Ignore SSL warnings
warnings.simplefilter('ignore', InsecureRequestWarning)

# Load payloads, events, and tags from files  - Include your own files
def load_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file.readlines()]
    except Exception as e:
        print(f"[-] Error loading file: {e}")
        return []

def extract_parameters(url):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return list(params.keys())

def inject_payload(url, param, payload, event, tag):
    # Inject into specified tag with event
    injected_payload = f"<{tag} {event}={payload}></{tag}>"
    return re.sub(f"{param}=([^&]+)", f"{param}={injected_payload}", url)

def check_xss(url, param, payload, event, tag):
    test_url = inject_payload(url, param, payload, event, tag)
    response = requests.get(test_url, verify=False)
    
    if payload in response.text:
        print(f"[+] XSS Possible: {test_url}")
        return test_url
    return None

def test_xss(url, payloads, events, tags):
    params = extract_parameters(url)
    print(f"[+] Testing {len(params)} parameters: {params}")
    
    vulnerable_urls = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for param in params:
            for payload in payloads:
                for event in events:
                    for tag in tags:
                        future = executor.submit(check_xss, url, param, payload, event, tag)
                        result = future.result()
                        if result:
                            vulnerable_urls.append(result)

    if vulnerable_urls:
        print("\n[!] Potential XSS vulnerabilities found:")
        for v_url in vulnerable_urls:
            print(f"  - {v_url}")
    else:
        print("[✓] No XSS detected.")

    return vulnerable_urls

# CSP Security Analysis
def analyze_csp(headers):
    csp = headers.get("Content-Security-Policy", None)
    if not csp:
        print("[-] No CSP Header Found! Site is vulnerable to script injection.")
        return

    issues = []
    if "'unsafe-inline'" in csp or '*' in csp:
        issues.append("[!] CSP allows unsafe-inline execution, XSS risk!")

    if not issues:
        print("[✓] CSP appears secure.")
    else:
        for issue in issues:
            print(issue)

# Using Selenium for automating browser-based XSS validation
def validate_xss_browser(url):
    options = Options()
    options.add_argument("--headless")
    service = Service("/path/to/chromedriver")  # Adjust chromedriver path
    driver = webdriver.Chrome(service=service, options=options)
    
    print(f"[*] Testing {url} in browser...")
    driver.get(url)

    # Check for alert presence
    try:
        alert = driver.switch_to.alert
        alert_text = alert.text
        alert.accept()
        print(f"[!!!] XSS Confirmed! Alert popped: {alert_text}")
    except:
        print("[✓] No XSS execution detected.")

    driver.quit()

# Main function
def main():
    parser = argparse.ArgumentParser(description="Advanced XSS Scanner")
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    parser.add_argument("-p", "--payloads", help="File with XSS Payloads", required=True)
    parser.add_argument("-e", "--events", help="File with XSS Events", required=True)
    parser.add_argument("-t", "--tags", help="File with HTML Tags", required=True)
    parser.add_argument("-b", "--browser", help="Validate via browser", action="store_true")
    args = parser.parse_args()

    # Load payloads, events, and tags from files
    payloads = load_from_file(args.payloads)
    events = load_from_file(args.events)
    tags = load_from_file(args.tags)

    if not payloads or not events or not tags:
        print("[-] Failed to load payloads, events, or tags.")
        return

    url = args.url
    print(f"[+] Scanning: {url}")

    # Test for XSS
    vulnerable_urls = test_xss(url, payloads, events, tags)

    # Fetch HTTP headers
    response = requests.get(url, verify=False)
    analyze_csp(response.headers)

    # Validate via browser if required
    if args.browser and vulnerable_urls:
        print("\n[!] Running browser-based validation...")
        for vul_url in vulnerable_urls:
            validate_xss_browser(vul_url)

if __name__ == "__main__":
    main()
