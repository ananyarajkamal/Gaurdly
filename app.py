import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
import re
import math
import tldextract
import whois
import requests
from urllib.parse import urlparse, parse_qs
from streamlit_option_menu import option_menu
from datetime import datetime
import plotly.graph_objects as go

# --- 1. SETUP & ASSET LOADING ---
st.set_page_config(page_title="Gaurdly | URL Intelligence", layout="wide", page_icon="🛡️")

@st.cache_resource(show_spinner=False)
def load_assets():
    try:
        model = joblib.load('malicious_url_rf_model.pkl')
        with open('feature_names.json', 'r') as f:
            feature_names = json.load(f)
        return model, feature_names
    except:
        return None, None

model, feature_names = load_assets()

# --- 2. EXACT SAAS UI ENGINE ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=DM+Mono:wght@400;500&display=swap');
    
    html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }
    .stApp { background-color: #F8F9FA; }
    
    #MainMenu, footer, header { visibility: hidden; }
    .block-container { padding-top: 2rem !important; max-width: 1100px !important; }

    /* Sidebar Navigation */
    [data-testid="stSidebar"] { background-color: #FFFFFF !important; border-right: 1px solid #E5E7EB !important; min-width: 280px !important; }
    
    /* Main Typography */
    .main-title { font-size: 52px; font-weight: 800; color: #0F172A; text-align: center; margin-top: 40px; letter-spacing: -1.5px; line-height: 1.1; }
    .sub-title { font-size: 18px; color: #64748B; text-align: center; margin-bottom: 40px; max-width: 650px; margin-left: auto; margin-right: auto; line-height: 1.6; }

    /* Input and Button Alignment Fix */
    div[data-testid="stColumn"] {
        display: flex;
        align-items: flex-end !important;
    }
    .stTextInput { width: 100%; }
    .stTextInput > div > div > input {
        height: 48px !important;
        border-radius: 8px !important;
        border: 1.5px solid #E5E7EB !important;
        font-family: 'DM Mono', monospace !important;
    }
    .stButton > button {
        background-color: #A78BFA !important;
        color: white !important;
        height: 48px !important;
        width: 100% !important;
        border: none !important;
        font-weight: 700 !important;
        border-radius: 8px !important;
        transition: 0.2s;
        margin-top: 0px !important;
    }
    .stButton > button:hover { background-color: #7C3AED !important; box-shadow: 0 4px 12px rgba(124, 58, 237, 0.35) !important; transform: translateY(-1px); }

    /* Split-Card UI */
    .result-card { border-radius: 12px; border: 1px solid #E2E8F0; background: #FFFFFF; display: flex; margin-top: 30px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.05); min-height: 240px; }
    .danger-border { border-color: #FCA5A5 !important; }
    .safe-border { border-color: #86EFAC !important; }
    
    .card-left { width: 30%; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; padding: 40px 20px; border-right: 1px solid; }
    .danger-left { background-color: #FEF2F2; border-color: #FEE2E2; color: #DC2626; }
    .safe-left { background-color: #F0FDF4; border-color: #DCFCE7; color: #16A34A; }
    
    .card-right { width: 70%; padding: 32px; background: white; display: flex; flex-direction: column; justify-content: space-between; }
    .label-meta { color: #94A3B8; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
    .url-display { color: #0F172A; font-size: 16px; font-family: 'DM Mono', monospace; word-break: break-all; margin-bottom: 20px; }
    .score-value { font-size: 56px; font-weight: 800; line-height: 1; letter-spacing: -2px; }
    
    .info-item { background: #F8FAFC; border: 1px solid #E2E8F0; padding: 12px 16px; border-radius: 8px; flex: 1; }
    .funny-tag { font-size: 13px; font-style: italic; color: #94A3B8; margin-top: 12px; }

    /* Universal Cards */
    .help-card { background: white; border: 1px solid #E5E7EB; padding: 25px; border-radius: 12px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.02); }
    </style>
""", unsafe_allow_html=True)

# --- 3. THE 48-FEATURE ENGINE ---
def compute_entropy(s):
    if not s: return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((v / len(s)) * math.log2(v / len(s)) for v in freq.values())

def extract_features(url):
    ext = tldextract.extract(url)
    root = f"{ext.domain}.{ext.suffix}".lower()
    parsed = urlparse(url if url.startswith(("http", "https")) else "http://" + url)
    sub, dom, tld = ext.subdomain or "", ext.domain or "", ext.suffix or ""
    path, query = parsed.path or "", parsed.query or ""
    
    f = {}
    f['url_length'] = len(url); f['domain_length'] = len(dom); f['tld_length'] = len(tld)
    f['path_length'] = len(path); f['query_length'] = len(query); f['fragment_length'] = len(parsed.fragment)
    f['subdomain_length'] = len(sub); f['num_dots'] = url.count("."); f['num_hyphens'] = url.count("-")
    f['num_underscores'] = url.count("_"); f['num_slashes'] = url.count("/"); f['num_question_marks'] = url.count("?")
    f['num_equal_signs'] = url.count("="); f['num_ampersands'] = url.count("&"); f['num_at_signs'] = url.count("@")
    f['num_exclamations'] = url.count("!"); f['num_spaces'] = url.count(" ") + url.count("%20"); f['num_tilde'] = url.count("~")
    f['num_comma'] = url.count(","); f['num_plus'] = url.count("+"); f['num_asterisk'] = url.count("*")
    f['num_hash'] = url.count("#"); f['num_dollar'] = url.count("$"); f['num_percent'] = url.count("%")
    f['num_digits'] = sum(c.isdigit() for c in url); f['num_letters'] = sum(c.isalpha() for c in url)
    f['num_subdomains'] = len(sub.split(".")) if sub else 0; f['num_path_tokens'] = len([t for t in path.split("/") if t])
    f['num_query_params'] = len(parse_qs(query)); f['num_dots_domain'] = dom.count("."); f['num_hyphens_domain'] = dom.count("-")
    f['digit_ratio'] = f['num_digits'] / max(len(url), 1); f['letter_ratio'] = f['num_letters'] / max(len(url), 1)
    f['special_char_ratio'] = (len(url) - f['num_letters'] - f['num_digits']) / max(len(url), 1)
    f['url_entropy'] = compute_entropy(url); f['domain_entropy'] = compute_entropy(dom); f['path_entropy'] = compute_entropy(path)
    f['has_https'] = 1 if parsed.scheme == "https" else 0; f['has_ip_address'] = 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", parsed.hostname or "") else 0
    f['has_port'] = 1 if parsed.port else 0; f['has_at_sign'] = 1 if "@" in url else 0
    f['has_double_slash'] = 1 if "//" in path else 0; f['has_hex_encoding'] = 1 if re.search(r"%[0-9a-fA-F]{2}", url) else 0
    f['has_shortener'] = 1 if dom in {"bit.ly", "t.co", "tinyurl", "goo.gl"} else 0; f['domain_is_numeric'] = 1 if re.match(r"^[0-9.-]+$", dom) else 0
    f['has_suspicious_tld'] = 1 if tld in {"tk", "ml", "ga", "xyz"} else 0
    f['has_brand_in_domain'] = 1 if any(b in (sub + dom).lower() for b in {"paypal", "apple", "google", "amazon"}) else 0
    f['has_long_subdomain'] = 1 if len(sub) > 20 else 0

    if feature_names:
        vector = np.array([f.get(name, 0) for name in feature_names]).reshape(1, -1)
        return vector, f
    return None, f

# --- 4. TRUSTED WHITELIST ---
TRUSTED_DOMAINS = {"google.com", "youtube.com", "instagram.com", "facebook.com", "netflix.com", "amazon.com", "microsoft.com", "apple.com", "github.com", "wikipedia.org", "kaggle.com", "escholarship.org", "claude.ai", "openai.com", "flipkart.com", "casamanana.org"}

# --- 5. SIDEBAR ---
if "page" not in st.session_state: st.session_state.page = "Scanner"

with st.sidebar:
    st.markdown("""
        <div style="padding: 20px 10px;">
            <div style="display:flex; align-items:center; gap:12px; margin-bottom:15px;">
                <div style="background:#7C3AED; color:white; font-weight:800; font-size:20px; width:36px; height:36px; border-radius:8px; display:flex; align-items:center; justify-content:center;">G</div>
                <span style="font-weight:800; font-size:22px; color:#0F172A; letter-spacing:-1px;">Gaurdly</span>
            </div>
            <p style="color:#64748B; font-size:12px; line-height:1.4; margin-bottom:25px;">The AI that drinks coffee and hunts phishers.</p>
        </div>
    """, unsafe_allow_html=True)
    
    selected = option_menu(None, ["Scanner", "Technical Analysis", "Domain Intel", "Help Center"], 
                           icons=['search', 'activity', 'globe', 'info-circle'], 
                           default_index=0, styles={
                               "nav-link": {"font-size": "14px", "color": "#64748B", "padding": "10px"},
                               "nav-link-selected": {"background-color": "#F3F0FF", "color": "#7C3AED", "font-weight": "700", "border-left": "4px solid #7C3AED"}
                           })
    st.session_state.page = selected

# --- 6. SCANNER PAGE ---
if st.session_state.page == "Scanner":
    st.markdown('<div class="main-title">URL Intelligence Platform</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Paste a link below. Our AI will virtually poke it with a 10-foot pole and tell you if it is safe to click, or if it is just a scammer trying to steal your Netflix passwords.</div>', unsafe_allow_html=True)

    c1, c2 = st.columns([4, 1])
    with c1:
        url_input = st.text_input("url_field", placeholder="Paste that suspicious link here...", label_visibility="collapsed")
    with c2:
        st.markdown('<div class="analyze-btn">', unsafe_allow_html=True)
        analyze_clicked = st.button("Analyze URL")
        st.markdown('</div>', unsafe_allow_html=True)

    if (analyze_clicked or url_input) and url_input:
        url = url_input.strip()
        vector, raw_f = extract_features(url)
        ext = tldextract.extract(url)
        whitelisted = ext.registered_domain.lower() in TRUSTED_DOMAINS or ext.suffix == 'edu'
        
        if whitelisted:
            risk, pred = 0, 0
            funny = "This URL is in the VIP Vault. It is safer than a puppy in a sweater."
        elif model:
            prob = model.predict_proba(vector)[0][1]
            pred = 1 if prob > 0.5 else 0
            risk = int(prob * 100)
            funny = "This link is more suspicious than a 'Free iPhone' email from a long-lost uncle." if pred == 1 else "This link is cleaner than my search history after a job interview."
        else:
            risk, pred = 0, 0
            funny = "Model is sleeping. URL assumed safe but proceed with caution."

        v_label, v_class, v_icon = ("DANGER", "danger", "!") if pred == 1 else ("SAFE", "safe", "✓")

        # Flat HTML string to fix markdown indentation bugs
        st.markdown(
            f"<div class='result-card {v_class}-border'>"
            f"<div class='card-left {v_class}-left'>"
            f"<div style='font-size:42px; font-weight:800; margin-bottom:8px;'>{v_icon}</div>"
            f"<h2 style='font-weight:800; margin:0; font-size:30px; letter-spacing:1px;'>{v_label}</h2>"
            f"</div>"
            f"<div class='card-right'>"
            f"<div><p class='label-meta'>Analyzed Resource</p><p class='url-display'>{url}</p></div>"
            f"<div style='display:flex; justify-content:space-between; align-items:flex-end;'>"
            f"<div style='width:50%;'><p class='label-meta'>Risk Score</p><span class='score-value' style='color:{'#DC2626' if pred == 1 else '#16A34A'}'>{risk}</span><span style='color:#94A3B8; font-weight:600; font-size:18px;'>/100</span><p class='funny-tag'>{funny}</p></div>"
            f"<div style='display:flex; gap:12px; width:50%;'><div class='info-item'><p class='label-meta'>Analysis Date</p><p style='font-weight:700; font-size:14px; margin:0;'>{datetime.now().strftime('%d/%m/%Y')}</p></div><div class='info-item'><p class='label-meta'>Status</p><p style='font-weight:700; font-size:14px; margin:0;'>{'Threat' if pred == 1 else 'Solid'}</p></div></div>"
            f"</div>"
            f"</div>"
            f"</div>", unsafe_allow_html=True
        )
        st.session_state.last_f = raw_f
        st.session_state.last_url = url

# --- 7. TECHNICAL ANALYSIS ---
elif st.session_state.page == "Technical Analysis":
    st.markdown('<h2 style="font-weight:800; font-size:32px; color:#0F172A; margin-bottom:10px;">Technical Breakdown</h2>', unsafe_allow_html=True)
    st.markdown("<p style='color:#64748B; margin-bottom:30px;'>Look at all these numbers the AI had to crunch. Respect the hustle.</p>", unsafe_allow_html=True)
    if "last_f" in st.session_state:
        col1, col2 = st.columns([1, 1], gap="large")
        with col1:
            st.markdown("<p class='label-meta'>Feature Matrix</p>", unsafe_allow_html=True)
            display_f = {k: v for k, v in st.session_state.last_f.items() if k in feature_names} if feature_names else st.session_state.last_f
            df = pd.DataFrame(display_f.items(), columns=["Feature", "Value"])
            st.dataframe(df, use_container_width=True, height=500, hide_index=True)
        with col2:
            st.markdown("<p class='label-meta'>Heuristic Contribution</p>", unsafe_allow_html=True)
            markers = {"Digits": st.session_state.last_f.get("digit_ratio", 0), "Special Chars": st.session_state.last_f.get("special_char_ratio", 0), "Entropy": st.session_state.last_f.get("url_entropy", 0)/8, "Subdomains": min(st.session_state.last_f.get("num_subdomains", 0)/5, 1), "TLD Risk": st.session_state.last_f.get("has_suspicious_tld", 0)}
            fig = go.Figure(go.Bar(x=list(markers.values()), y=list(markers.keys()), orientation='h', marker=dict(color=['#A78BFA', '#8B5CF6', '#7C3AED', '#6D28D9', '#4C1D95'])))
            fig.update_layout(height=400, margin=dict(l=0, r=0, t=10, b=10), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', xaxis=dict(showgrid=True, gridcolor='#E5E7EB'))
            st.plotly_chart(fig, use_container_width=True)
    else: st.info("Scan a URL first. The AI is waiting for work.")

# --- 8. DOMAIN INTEL ---
elif st.session_state.page == "Domain Intel":
    st.markdown('<h2 style="font-weight:800; font-size:32px; color:#0F172A; margin-bottom:10px;">Domain Intelligence</h2>', unsafe_allow_html=True)
    st.markdown("<p style='color:#64748B; margin-bottom:30px;'>Deep structural breakdown of the analyzed resource.</p>", unsafe_allow_html=True)
    
    if "last_f" in st.session_state and "last_url" in st.session_state:
        url = st.session_state.last_url
        f = st.session_state.last_f
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        reg_id, registrar, creation, expiration, country = "Not Available", "Not Available", "Not Available", "Not Available", "Not Available"
        try:
            w = whois.whois(domain)
            reg_id = w.get('registry_domain_id', 'Not Available') or 'Not Available'
            reg_list = w.get('registrar', 'Not Available')
            registrar = reg_list[0] if isinstance(reg_list, list) else reg_list
            c_date = w.get('creation_date')
            c_date = c_date[0] if isinstance(c_date, list) else c_date
            creation = c_date.strftime('%Y-%m-%d') if c_date else "Not Available"
            e_date = w.get('expiration_date')
            e_date = e_date[0] if isinstance(e_date, list) else e_date
            expiration = e_date.strftime('%Y-%m-%d') if e_date else "Not Available"
            country = w.get('country', 'Not Available')
        except:
            pass

        flags = [
            ("HTTPS Enabled", f.get('has_https', 0) == 1),
            ("Valid TLD", f.get('has_suspicious_tld', 1) == 0),
            ("Clean Domain (No IP)", f.get('has_ip_address', 1) == 0),
            ("No Brand Spoofing", f.get('has_brand_in_domain', 1) == 0),
            ("Direct Link (No Shortener)", f.get('has_shortener', 1) == 0),
            ("Valid Chars (No @)", f.get('has_at_sign', 1) == 0),
            ("Clean Encoding (No Hex)", f.get('has_hex_encoding', 1) == 0),
            ("Normal Subdomain", f.get('has_long_subdomain', 1) == 0),
            ("Standard Port", f.get('has_port', 1) == 0),
            ("Non-Numeric Domain", f.get('domain_is_numeric', 1) == 0),
        ]
        
        flag_html = ""
        for i in range(0, len(flags), 2):
            left_label, left_ok = flags[i]
            right_label, right_ok = flags[i+1] if i+1 < len(flags) else ("", False)
            
            l_icon = "<span style='color:#16A34A; margin-right:8px;'>✓</span>" if left_ok else "<span style='color:#DC2626; margin-right:8px;'>✗</span>"
            r_icon = "<span style='color:#16A34A; margin-right:8px;'>✓</span>" if right_ok else "<span style='color:#DC2626; margin-right:8px;'>✗</span>"
            
            flag_html += f"<div style='display:flex; justify-content:space-between; margin-bottom:12px;'><div style='width:50%; font-size:13px; font-weight:600; color:#0F172A;'>{l_icon}{left_label}</div><div style='width:50%; font-size:13px; font-weight:600; color:#0F172A;'>{r_icon}{right_label}</div></div>"

        c1, c2 = st.columns(2)
        with c1:
            # Flattened HTML to fix markdown indentation bugs
            st.markdown(
                "<div class='help-card' style='height: 100%;'>"
                "<p class='label-meta'>WHOIS REGISTRATION DATA</p>"
                "<div style='display:flex; flex-direction:column; gap:14px; margin-top:20px;'>"
                f"<div style='display:flex; justify-content:space-between; border-bottom:1px solid #F1F5F9; padding-bottom:8px;'><span style='color:#64748B; font-size:13px; font-weight:600;'>Registry Domain ID:</span><span style='color:#0F172A; font-size:13px; font-weight:700;'>{reg_id}</span></div>"
                f"<div style='display:flex; justify-content:space-between; border-bottom:1px solid #F1F5F9; padding-bottom:8px;'><span style='color:#64748B; font-size:13px; font-weight:600;'>Registrar Name:</span><span style='color:#0F172A; font-size:13px; font-weight:700;'>{registrar}</span></div>"
                f"<div style='display:flex; justify-content:space-between; border-bottom:1px solid #F1F5F9; padding-bottom:8px;'><span style='color:#64748B; font-size:13px; font-weight:600;'>Creation Date:</span><span style='color:#0F172A; font-size:13px; font-weight:700;'>{creation}</span></div>"
                f"<div style='display:flex; justify-content:space-between; border-bottom:1px solid #F1F5F9; padding-bottom:8px;'><span style='color:#64748B; font-size:13px; font-weight:600;'>Expiration Date:</span><span style='color:#0F172A; font-size:13px; font-weight:700;'>{expiration}</span></div>"
                f"<div style='display:flex; justify-content:space-between; padding-bottom:4px;'><span style='color:#64748B; font-size:13px; font-weight:600;'>Host Country:</span><span style='color:#0F172A; font-size:13px; font-weight:700;'>{country}</span></div>"
                "</div></div>", unsafe_allow_html=True
            )
        with c2:
            st.markdown(
                "<div class='help-card' style='height: 100%;'>"
                "<p class='label-meta'>SECURITY FLAGS</p>"
                "<div style='margin-top:20px;'>"
                f"{flag_html}"
                "</div></div>", unsafe_allow_html=True
            )
    else: st.info("Scan a URL first.")

# --- 9. HELP CENTER ---
elif st.session_state.page == "Help Center":
    st.markdown('<h2 style="font-weight:800; font-size:32px; color:#0F172A; margin-bottom:10px;">Help Center</h2>', unsafe_allow_html=True)
    st.markdown("<p style='color:#64748B; margin-bottom:30px;'>Got questions? We have answers. Some of them are even helpful.</p>", unsafe_allow_html=True)
    
    faqs = [
        ("How does this magic actually work?", "It strips the URL down to 48 raw metrics—like symbol counts, lengths, and general bad vibes—and feeds them to a Random Forest algorithm. Basically, it's a math-powered bouncer for your browser."),
        ("What exactly is the Risk Score?", "0 means it's an angel. 100 means you should probably set your router on fire if you clicked it. Anything above 50 means the AI is heavily judging your life choices."),
        ("Why did a completely safe site get flagged?", "The AI is highly caffeinated and occasionally paranoid. If a site has too many weird characters or a sketchy domain, it hits the panic button. We use a VIP Whitelist for big sites to keep it calm."),
        ("Are you secretly saving my search history?", "Absolutely not. The AI inspects your link, judges you silently in milliseconds, and then immediately wipes its memory. We really do not want to know what you are up to.")
    ]
    
    for q, a in faqs:
        st.markdown(f"<div class='help-card'><b>{q}</b><p style='font-size:14px; color:#64748B; margin-top:8px;'>{a}</p></div>", unsafe_allow_html=True)