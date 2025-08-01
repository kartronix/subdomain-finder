import streamlit as st
import requests
import socket
import pandas as pd
import concurrent.futures

# --- Streamlit Config ---
st.set_page_config(page_title="Subdomain & IP Finder", layout="centered")
st.title("🔍 Subdomain & IP Finder")

# --- IP Resolver ---
def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unresolved"

def resolve_all(subdomains):
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        return list(executor.map(lambda d: {"Subdomain": d, "IP": resolve_ip(d)}, subdomains))

# --- Source: crt.sh ---
def fetch_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=60)
        if response.status_code != 200:
            return []
        data = response.json()
        subdomains = set()
        for entry in data:
            if 'name_value' in entry:
                for name in entry['name_value'].split('\n'):
                    name = name.strip().lower()
                    if name.endswith(domain):
                        subdomains.add(name)
        return list(subdomains)
    except:
        return []

# --- Source: ThreatCrowd ---
def fetch_threatcrowd(domain):
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            return [d.lower() for d in data.get("subdomains", []) if d.endswith(domain)]
    except:
        return []
    return []

# --- Source: HackerTarget ---
def fetch_hackertarget(domain):
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=30)
        if response.status_code == 200 and not response.text.startswith("error"):
            return [line.split(',')[0].strip().lower() for line in response.text.strip().split('\n') if line.split(',')[0].endswith(domain)]
    except:
        return []
    return []

# --- Source: Anubis (jldc.me) ---
def fetch_anubis(domain):
    try:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            return [f"{sub}.{domain}" for sub in response.json()]
    except:
        return []
    return []

# --- Source: BufferOver ---
def fetch_bufferover(domain):
    try:
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            return [entry.split(',')[1] for entry in data.get("FDNS_A", []) if entry.split(',')[1].endswith(domain)]
    except:
        return []
    return []

# --- Source: AlienVault ---
def fetch_alienvault(domain):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            return [record["hostname"] for record in data.get("passive_dns", []) if record["hostname"].endswith(domain)]
    except:
        return []
    return []

# --- Consolidated Fetch ---
@st.cache_data(ttl=600)
def fetch_subdomains(domain):
    crtsh = set(fetch_crtsh(domain))
    threatcrowd = set(fetch_threatcrowd(domain))
    hackertarget = set(fetch_hackertarget(domain))
    anubis = set(fetch_anubis(domain))
    bufferover = set(fetch_bufferover(domain))
    alienvault = set(fetch_alienvault(domain))

    all_subdomains = crtsh | threatcrowd | hackertarget | anubis | bufferover | alienvault
    unique_subdomains = sorted(s for s in all_subdomains if s.endswith(domain))

    st.success(f"""
✅ Total Unique Subdomains: {len(unique_subdomains)}

• crt.sh: {len(crtsh)}
• ThreatCrowd: {len(threatcrowd)}
• HackerTarget: {len(hackertarget)}
• Anubis: {len(anubis)}
• BufferOver: {len(bufferover)}
• AlienVault: {len(alienvault)}
    """)
    return unique_subdomains

# --- UI ---
domain_input = st.text_input("Enter a domain", value="", placeholder="example.com").strip().lower()
resolve_ips = st.checkbox("🌐 Resolve IP addresses (slower)", value=True)

if st.button("🔍 Search"):
    if domain_input:
        with st.spinner("🔎 Collecting subdomains..."):
            subdomains = fetch_subdomains(domain_input)

        if subdomains:
            if resolve_ips:
                with st.spinner("🌐 Resolving IPs..."):
                    results = resolve_all(subdomains)
            else:
                results = [{"Subdomain": sub, "IP": "Not Resolved"} for sub in subdomains]

            df = pd.DataFrame(results)
            unresolved = sum(1 for r in results if r["IP"] == "Unresolved")

            st.session_state["last_result"] = df
            st.session_state["last_domain"] = domain_input
            st.success(f"✅ Found {len(df)} subdomains. {unresolved} unresolved.")
        else:
            st.warning("⚠️ No subdomains found.")
            st.session_state["last_result"] = None
            st.session_state["last_domain"] = None

# --- Results Display ---
if "last_result" in st.session_state and st.session_state["last_result"] is not None:
    st.dataframe(st.session_state["last_result"])
    csv = st.session_state["last_result"].to_csv(index=False).encode("utf-8")
    st.download_button(
        "📥 Download as CSV",
        data=csv,
        file_name=f"{st.session_state['last_domain']}_subdomains.csv",
        mime="text/csv"
    )
