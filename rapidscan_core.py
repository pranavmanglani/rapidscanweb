import socket
import whois
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"DNS Lookup: {domain} resolves to {ip}"
    except Exception as e:
        return f"DNS Lookup Failed: {e}"

def whois_lookup(domain):
    try:
        data = whois.whois(domain)
        return f"WHOIS:\n{data.text if hasattr(data, 'text') else str(data)}"
    except Exception as e:
        return f"WHOIS Lookup Failed: {e}"

def port_scan(domain, ports=[21, 22, 80, 443, 3306]):
    output = []
    for port in ports:
        try:
            with socket.create_connection((domain, port), timeout=2):
                output.append(f"Port {port} is OPEN")
        except:
            output.append(f"Port {port} is CLOSED")
    return "\n".join(output)

def http_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        return "\n".join([f"{k}: {v}" for k, v in headers.items()])
    except Exception as e:
        return f"Header Check Failed: {e}"

def check_robots(url):
    try:
        r = requests.get(url.rstrip("/") + "/robots.txt", timeout=5)
        return r.text if r.status_code == 200 else "robots.txt not found"
    except:
        return "robots.txt check failed"

def xss_test(url):
    payload = "<script>alert(1)</script>"
    try:
        test_url = f"{url}?xss={payload}"
        r = requests.get(test_url, timeout=5)
        return "XSS Found!" if payload in r.text else "XSS Not Detected"
    except Exception as e:
        return f"XSS Check Failed: {e}"

def sqli_test(url):
    payload = "' OR '1'='1"
    try:
        test_url = f"{url}?id={payload}"
        r = requests.get(test_url, timeout=5)
        if any(x in r.text.lower() for x in ["sql syntax", "mysql", "syntax error"]):
            return "SQLi Detected!"
        return "SQLi Not Detected"
    except Exception as e:
        return f"SQLi Check Failed: {e}"

def lfi_test(url):
    try:
        test_url = f"{url}?file=../../../../etc/passwd"
        r = requests.get(test_url, timeout=5)
        return "LFI Detected!" if "root:x:0:0:" in r.text else "LFI Not Detected"
    except Exception as e:
        return f"LFI Check Failed: {e}"

def open_redirect_test(url):
    try:
        test_url = f"{url}?redirect=https://evil.com"
        r = requests.get(test_url, allow_redirects=False, timeout=5)
        if 'Location' in r.headers and "evil.com" in r.headers['Location']:
            return "Open Redirect Detected!"
        return "No Open Redirect"
    except Exception as e:
        return f"Open Redirect Check Failed: {e}"

def ssti_test(url):
    try:
        payload = "{{7*7}}"
        test_url = f"{url}?ssti={payload}"
        r = requests.get(test_url, timeout=5)
        return "SSTI Detected!" if "49" in r.text else "SSTI Not Detected"
    except Exception as e:
        return f"SSTI Check Failed: {e}"

def run_selected_scans(url, tests):
    url = normalize_url(url)
    domain = urlparse(url).netloc
    results = []

    if tests.get("DNS Lookup"):
        results.append(dns_lookup(domain))
    if tests.get("WHOIS Lookup"):
        results.append(whois_lookup(domain))
    if tests.get("Port Scan"):
        results.append(port_scan(domain))
    if tests.get("HTTP Headers Check"):
        results.append(http_headers(url))
    if tests.get("Robots.txt Check"):
        results.append(check_robots(url))
    if tests.get("XSS Test"):
        results.append(xss_test(url))
    if tests.get("SQLi Test"):
        results.append(sqli_test(url))
    if tests.get("LFI Test"):
        results.append(lfi_test(url))
    if tests.get("Open Redirect Test"):
        results.append(open_redirect_test(url))
    if tests.get("SSTI Test"):
        results.append(ssti_test(url))

    return "\n\n".join(results)
