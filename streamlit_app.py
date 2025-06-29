import streamlit as st
from rapidscan_core import run_full_scan

st.set_page_config(page_title="RapidScan Web", layout="wide")
st.title("⚡ RapidScan - Python-Only Vulnerability Scanner")

url = st.text_input("Enter a target URL:", "example.com")
run_button = st.button("Run Scan")

if run_button:
    if not url:
        st.warning("Please enter a valid URL.")
    else:
        st.info("Scanning in progress. Please wait...")
        result = run_full_scan(url)
        st.success("Scan complete!")
        st.text_area("Scan Output:", result, height=400)
