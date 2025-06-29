import socket
import whois
import requests

def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url.split("//")[-1].split("/")[0].strip()

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"DNS Lookup: {domain} resolved to {ip}"
    except Exception as e:
        return f"DNS Lookup Failed: {str(e)}"

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return f"WHOIS Info:\n{w.text if hasattr(w, 'text') else str(w)}"
    except Exception as e:
        return f"WHOIS Lookup Failed: {str(e)}"

def port_scan(domain, ports=[80, 443, 22, 21, 3306]):
    results = [f"Scanning common ports on {domain}..."]
    for port in ports:
        try:
            with socket.create_connection((domain, port), timeout=2):
                results.append(f"Port {port}: OPEN")
        except Exception:
            results.append(f"Port {port}: CLOSED or FILTERED")
    return "\n".join(results)

def xss_check(url):
    test_payload = "<script>alert('xss')</script>"
    try:
        full_url = url + "?input=" + test_payload
        response = requests.get(full_url, timeout=5)
        if test_payload in response.text:
            return "XSS Check: ⚠️ Potential XSS vulnerability detected!"
        else:
            return "XSS Check: ✅ No reflected XSS detected."
    except Exception as e:
        return f"XSS Check Failed: {str(e)}"

def sqli_check(url):
    payload = "' OR '1'='1"
    try:
        full_url = url + "?id=" + payload
        response = requests.get(full_url, timeout=5)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            return "SQL Injection Check: ⚠️ Potential SQLi vulnerability detected!"
        else:
            return "SQL Injection Check: ✅ No SQL error-based injection detected."
    except Exception as e:
        return f"SQL Injection Check Failed: {str(e)}"

def run_full_scan(url):
    domain = normalize_url(url)
    output = [
        dns_lookup(domain),
        whois_lookup(domain),
        port_scan(domain),
        xss_check("http://" + domain),
        sqli_check("http://" + domain)
    ]
    return "\n\n".join(output)
