import subprocess
import re
from urllib.parse import urlsplit

# Define tools and corresponding commands (partial sample)
TOOL_COMMANDS = [
    ("host", ["host", "{target}"]),
    ("whois", ["whois", "{target}"]),
    ("nmap quick scan", ["nmap", "-F", "{target}"]),
]

def normalize_url(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host or parsed.path

def run_full_scan(url):
    target = normalize_url(url)
    output = []
    for name, cmd_template in TOOL_COMMANDS:
        cmd = [arg.format(target=target) for arg in cmd_template]
        output.append(f"--- Running: {name} ---")
        try:
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=60)
            output.append(result)
        except subprocess.CalledProcessError as e:
            output.append(f"Error running {name}: {e.output}")
        except Exception as e:
            output.append(f"Unexpected error in {name}: {str(e)}")
        output.append("\n")
    return "\n".join(output)
