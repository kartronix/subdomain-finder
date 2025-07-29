import streamlit as st
import requests
import socket
import pandas as pd

# --- Functions ---
def fetch_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0"}

    session = requests.Session()
    retries = requests.adapters.Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[429, 502, 503, 504]
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retries)
    session.mount('https://', adapter)

    try:
        response = session.get(url, headers=headers, timeout=60)
        if response.status_code != 200:
            st.error(f"crt.sh returned status code {response.status_code}")
            return []

        data = response.json()
        subdomains = set()

        for entry in data:
            if 'name_value' in entry:
                names = entry['name_value'].split('\n')
                for name in names:
                    cleaned = name.strip()
                    if cleaned.endswith(domain):
                        subdomains.add(cleaned.lower())

        return sorted(subdomains)
    except Exception as e:
        st.error(f"Error fetching subdomains: {e}")
        return []

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unresolved"

# --- Streamlit UI ---
st.set_page_config(page_title="Subdomain & IP Finder", layout="centered")
st.title("🔍 Subdomain & IP Finder")

domain_input = st.text_input("Enter a domain (e.g., google.com, openai.com)", key="domain_input")

if st.button("🔍 Search"):
    if domain_input:
        with st.spinner("🔎 Fetching subdomains..."):
            subdomains = fetch_subdomains(domain_input)

        if subdomains:
            with st.spinner("🌐 Resolving IP addresses..."):
                results = [{"Subdomain": sub, "IP": resolve_ip(sub)} for sub in subdomains]
                df = pd.DataFrame(results)
            st.success(f"✅ Found {len(df)} unique subdomains.")
            st.session_state["last_result"] = df
            st.session_state["last_domain"] = domain_input
        else:
            st.warning("⚠️ No subdomains found.")
            st.session_state["last_result"] = None
            st.session_state["last_domain"] = None

# Show last result (if available)
if "last_result" in st.session_state and st.session_state["last_result"] is not None:
    st.dataframe(st.session_state["last_result"])
    csv = st.session_state["last_result"].to_csv(index=False).encode("utf-8")
    st.download_button(
        "📥 Download as CSV",
        data=csv,
        file_name=f"{st.session_state['last_domain']}_subdomains.csv",
        mime="text/csv"
    )
