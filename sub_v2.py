import streamlit as st
import requests
import socket
import pandas as pd
import concurrent.futures

# --- Configuration ---
st.set_page_config(page_title="Subdomain & IP Finder", layout="centered")
st.title("🔍 Subdomain & IP Finder")

# --- Helper Functions ---
def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unresolved"

def resolve_all(subdomains):
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        return list(executor.map(lambda d: {"Subdomain": d, "IP": resolve_ip(d)}, subdomains))

@st.cache_data(ttl=600)
def fetch_subdomains(domain: str):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0"}

    session = requests.Session()
    retries = requests.adapters.Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[429, 502, 503, 504],
        raise_on_status=False
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retries)
    session.mount('https://', adapter)

    try:
        response = session.get(url, headers=headers, timeout=60)
        if response.status_code != 200:
            st.error(f"crt.sh returned status code {response.status_code}")
            return []

        try:
            data = response.json()
        except ValueError:
            st.error("crt.sh returned invalid JSON.")
            return []

        subdomains = set()
        domain_lower = domain.lower()

        for entry in data:
            if 'name_value' in entry:
                names = entry['name_value'].split('\n')
                for name in names:
                    cleaned = name.strip().lower()
                    if cleaned.endswith(domain_lower):
                        subdomains.add(cleaned)

        return sorted(subdomains)

    except requests.exceptions.RequestException as e:
        st.error(f"Error fetching subdomains: {e}")
        return []

# --- UI Elements ---
domain_input = st.text_input("Enter a domain", value="", placeholder="google.com, openai.com").strip().lower()
resolve_ips = st.checkbox("🌐 Resolve IP addresses (slower)", value=True)

if st.button("🔍 Search"):
    if domain_input:
        with st.spinner("🔎 Fetching subdomains..."):
            subdomains = fetch_subdomains(domain_input)

        if subdomains:
            if resolve_ips:
                with st.spinner("🌐 Resolving IP addresses..."):
                    results = resolve_all(subdomains)
            else:
                results = [{"Subdomain": sub, "IP": "Not Resolved"} for sub in subdomains]

            df = pd.DataFrame(results)
            st.session_state["last_result"] = df
            st.session_state["last_domain"] = domain_input
            st.success(f"✅ Found {len(df)} unique subdomains.")
        else:
            st.warning("⚠️ No subdomains found.")
            st.session_state["last_result"] = None
            st.session_state["last_domain"] = None

# --- Display Last Result and Download ---
if "last_result" in st.session_state and st.session_state["last_result"] is not None:
    st.dataframe(st.session_state["last_result"])
    csv = st.session_state["last_result"].to_csv(index=False).encode("utf-8")
    st.download_button(
        "📥 Download as CSV",
        data=csv,
        file_name=f"{st.session_state['last_domain']}_subdomains.csv",
        mime="text/csv"
    )
