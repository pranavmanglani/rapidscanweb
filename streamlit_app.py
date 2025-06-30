import streamlit as st
from rapidscan_core import run_selected_scans

st.set_page_config(page_title="🔍 RapidScan Pro", layout="wide")
st.title("🛡️ RapidScan - Web Vulnerability Scanner")

url = st.text_input("Target URL (e.g. http://example.com)")

st.subheader("🔧 Select Tests to Run")
options = {
    "DNS Lookup": st.checkbox("DNS Lookup", value=True),
    "WHOIS Lookup": st.checkbox("WHOIS Lookup", value=True),
    "Port Scan": st.checkbox("Port Scan", value=True),
    "HTTP Headers Check": st.checkbox("HTTP Header Analysis", value=True),
    "Robots.txt Check": st.checkbox("Robots.txt", value=True),
    "XSS Test": st.checkbox("Cross-Site Scripting (XSS)", value=True),
    "SQLi Test": st.checkbox("SQL Injection (SQLi)", value=True),
    "LFI Test": st.checkbox("Local File Inclusion (LFI)", value=True),
    "Open Redirect Test": st.checkbox("Open Redirect", value=True),
    "SSTI Test": st.checkbox("Server-Side Template Injection (SSTI)", value=True)
}

if st.button("Run Scan"):
    if url:
        st.info("Running selected scans. This may take a moment...")
        results = run_selected_scans(url, options)
        st.success("Scan complete!")
        st.text_area("🔍 Results", results, height=500)
    else:
        st.warning("Please enter a valid URL.")
