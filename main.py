from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Tuple, List, Dict
import asyncio
import httpx
import os
import sqlite3
import hashlib
import re
import shutil
import tempfile
import subprocess
import json
import ssl
import socket
import concurrent.futures
import certifi
import dns.resolver
import dns.zone
import dns.query
from datetime import datetime, timezone
from urllib.parse import urlparse

import scanner_logic
from scanner_logic import Finding, compute_score

app = FastAPI(title="Shield Works API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def read_index():
    return FileResponse("static/index.html")


class URLScanRequest(BaseModel):
    url: str


class GitHubScanRequest(BaseModel):
    repo_url: str


class LocalScanRequest(BaseModel):
    directory: str

class ScanRecord(BaseModel):
    username: str
    target: str
    scan_type: str
    score: int
    findings: str  # JSON string
    scanned_at: str

class LoginRequest(BaseModel):
    username: str
    password: str

class SignupRequest(BaseModel):
    username: str
    password: str
    role: str

def init_db():
    conn = sqlite3.connect("shieldworks.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    
    # Migration: Add theme_color if it doesn't exist
    c.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in c.fetchall()]
    if 'theme_color' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN theme_color TEXT DEFAULT '#38bdf8'")

    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            target TEXT,
            scan_type TEXT,
            score INTEGER,
            findings TEXT,
            scanned_at TEXT,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')
    
    # Hash all old plaintext passwords on startup
    c.execute('SELECT username, password FROM users')
    for row in c.fetchall():
        uname, pword = row
        if not (len(pword) == 64 and all(ch in '0123456789abcdefABCDEF' for ch in pword)):
            hashed = hashlib.sha256(pword.encode('utf-8')).hexdigest()
            c.execute('UPDATE users SET password = ? WHERE username = ?', (hashed, uname))

    # Add test user 'asad'
    c.execute('SELECT * FROM users WHERE username = ?', ('asad',))
    if not c.fetchone():
        hashed_pw = hashlib.sha256('password'.encode('utf-8')).hexdigest()
        c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ('asad', hashed_pw, 'Manager'))
        
        # Inject mock history for asad
        import json
        mock_findings = json.dumps([
            {"category": "URL Scan", "title": "Insecure Header", "severity": "medium", "description": "X-Frame-Options missing.", "recommendation": "Add DENY header."},
            {"category": "Software Scan", "title": "Logic Flaw", "severity": "high", "description": "Hardcoded key found in binary.", "recommendation": "Use ENV variables."}
        ])
        c.execute('''
            INSERT INTO scans (username, target, scan_type, score, findings, scanned_at) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('asad', 'https://example-test.com', 'url', 85, mock_findings, datetime.now(timezone.utc).isoformat()))
        
    conn.commit()
    conn.close()

init_db()

def get_db():
    return sqlite3.connect("shieldworks.db")

@app.post("/api/auth/signup")
async def signup(request: SignupRequest):
    conn = get_db()
    c = conn.cursor()
    hashed_pw = hashlib.sha256(request.password.encode('utf-8')).hexdigest()
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  (request.username, hashed_pw, request.role))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")
    conn.close()
    return {"status": "success", "username": request.username, "role": request.role}

@app.post("/api/auth/login")
async def login(request: LoginRequest):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT password, role, theme_color FROM users WHERE username = ?", (request.username,))
    row = c.fetchone()
    conn.close()
    hashed_pw = hashlib.sha256(request.password.encode('utf-8')).hexdigest()
    if not row or row[0] != hashed_pw:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"status": "success", "username": request.username, "role": row[1], "theme_color": row[2] if len(row) > 2 else "#38bdf8"}

@app.post("/api/user/settings")
async def save_settings(request: dict):
    username = request.get("username")
    theme_color = request.get("theme_color")
    if not username or not theme_color:
        raise HTTPException(status_code=400, detail="Missing data")
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET theme_color = ? WHERE username = ?", (theme_color, username))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.post("/api/scans")
async def save_scan(request: ScanRecord):
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans (username, target, scan_type, score, findings, scanned_at) 
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (request.username, request.target, request.scan_type, request.score, request.findings, request.scanned_at))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.get("/api/scans/{username}")
async def get_user_scans(username: str):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT target, scan_type, score, findings, scanned_at FROM scans WHERE username = ?', (username,))
    rows = c.fetchall()
    conn.close()
    
    import json
    scans = []
    for row in rows:
        scans.append({
            "target": row[0],
            "scan_type": row[1],
            "score": row[2],
            "findings": json.loads(row[3]),
            "scanned_at": row[4]
        })
    return scans

@app.delete("/api/scans/{username}")
async def delete_user_scans(username: str):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM scans WHERE username = ?', (username,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"All scans for {username} deleted."}



# ─── SCAN UTILS ─────────────────────────────────────────────────────────────
# Scan functions have been moved to scanner_logic.py for modularity.



# ─── SSL/TLS SCANNER ────────────────────────────────────────────────────────


def scan_ssl(hostname: str, port: int = 443):
    findings = []
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Check TLS version
                if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    findings.append(
                        Finding(
                            "SSL/TLS",
                            f"Outdated TLS Version: {version}",
                            "high",
                            f"Server supports {version} which is deprecated and vulnerable.",
                            "Upgrade to TLS 1.2 or TLS 1.3.",
                        ).to_dict()
                    )
                else:
                    findings.append(
                        Finding(
                            "SSL/TLS",
                            f"TLS Version: {version}",
                            "info",
                            f"Server uses {version}.",
                            "No action needed.",
                        ).to_dict()
                    )

                # Check cert expiry
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).days
                    if days_left < 0:
                        findings.append(
                            Finding(
                                "SSL/TLS",
                                "SSL Certificate Expired",
                                "critical",
                                f"Certificate expired {abs(days_left)} days ago.",
                                "Renew your SSL certificate immediately.",
                            ).to_dict()
                        )
                    elif days_left < 14:
                        findings.append(
                            Finding(
                                "SSL/TLS",
                                "SSL Certificate Expiring Soon",
                                "high",
                                f"Certificate expires in {days_left} days.",
                                "Renew your SSL certificate immediately.",
                            ).to_dict()
                        )
                    elif days_left < 30:
                        findings.append(
                            Finding(
                                "SSL/TLS",
                                "SSL Certificate Expiring Soon",
                                "medium",
                                f"Certificate expires in {days_left} days.",
                                "Plan to renew your SSL certificate soon.",
                            ).to_dict()
                        )
                    else:
                        findings.append(
                            Finding(
                                "SSL/TLS",
                                "SSL Certificate Valid",
                                "info",
                                f"Certificate valid for {days_left} more days.",
                                "No action needed.",
                            ).to_dict()
                        )

                # Weak cipher
                if cipher and cipher[0]:
                    cipher_name = cipher[0]
                    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
                    if any(w in cipher_name for w in weak_ciphers):
                        findings.append(
                            Finding(
                                "SSL/TLS",
                                f"Weak Cipher Suite: {cipher_name}",
                                "high",
                                "Server is using a weak or deprecated cipher suite.",
                                "Configure server to use strong cipher suites only (AES-GCM, ChaCha20).",
                            ).to_dict()
                        )

    except ssl.SSLCertVerificationError as e:
        findings.append(
            Finding(
                "SSL/TLS",
                "SSL Certificate Verification Failed",
                "critical",
                str(e),
                "Obtain a valid certificate from a trusted Certificate Authority.",
            ).to_dict()
        )
    except ConnectionRefusedError:
        findings.append(
            Finding(
                "SSL/TLS",
                "HTTPS Not Available",
                "high",
                "Could not connect on port 443. Site may not support HTTPS.",
                "Enable HTTPS with a valid SSL certificate.",
            ).to_dict()
        )
    except Exception as e:
        findings.append(
            Finding(
                "SSL/TLS",
                "SSL Check Error",
                "medium",
                f"Could not complete SSL check: {str(e)}",
                "Verify your SSL configuration manually.",
            ).to_dict()
        )
    return findings


# ─── HTTP HEADERS SCANNER ───────────────────────────────────────────────────


async def scan_headers(url: str):
    findings = []
    security_headers = {
        "strict-transport-security": {
            "title": "Missing HSTS Header",
            "severity": "high",
            "description": "HTTP Strict Transport Security (HSTS) is not set. Attackers can downgrade connections to HTTP.",
            "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        },
        "content-security-policy": {
            "title": "Missing Content-Security-Policy",
            "severity": "high",
            "description": "No CSP header found. Site is vulnerable to XSS and data injection attacks.",
            "recommendation": "Define a Content-Security-Policy to restrict resource loading.",
        },
        "x-frame-options": {
            "title": "Missing X-Frame-Options",
            "severity": "medium",
            "description": "No X-Frame-Options header. Site may be vulnerable to clickjacking.",
            "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        },
        "x-content-type-options": {
            "title": "Missing X-Content-Type-Options",
            "severity": "medium",
            "description": "No X-Content-Type-Options header. Browsers may MIME-sniff responses.",
            "recommendation": "Add: X-Content-Type-Options: nosniff",
        },
        "referrer-policy": {
            "title": "Missing Referrer-Policy",
            "severity": "low",
            "description": "No Referrer-Policy set. Sensitive URL data may leak to third parties.",
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        },
        "permissions-policy": {
            "title": "Missing Permissions-Policy",
            "severity": "low",
            "description": "No Permissions-Policy header. Browser features may be unnecessarily exposed.",
            "recommendation": "Add a Permissions-Policy to restrict access to browser APIs.",
        },
    }

    info_headers = {
        "x-powered-by": {
            "title": "Server Technology Disclosed (X-Powered-By)",
            "severity": "medium",
            "description": "The X-Powered-By header reveals backend technology, helping attackers fingerprint your stack.",
            "recommendation": "Remove the X-Powered-By header from server responses.",
        },
        "server": {
            "title": "Server Banner Disclosure",
            "severity": "low",
            "description": "The Server header reveals software and possibly version info.",
            "recommendation": "Configure your server to suppress or genericize the Server header.",
        },
    }

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check if HTTP redirects to HTTPS
            if url.startswith("http://"):
                if str(resp.url).startswith("https://"):
                    findings.append(
                        Finding(
                            "HTTP Headers",
                            "HTTP Redirects to HTTPS",
                            "info",
                            "Site correctly redirects HTTP to HTTPS.",
                            "No action needed.",
                        ).to_dict()
                    )
                else:
                    findings.append(
                        Finding(
                            "HTTP Headers",
                            "No HTTPS Redirect",
                            "high",
                            "Site does not redirect HTTP traffic to HTTPS.",
                            "Configure a 301 redirect from HTTP to HTTPS.",
                        ).to_dict()
                    )

            for header, meta in security_headers.items():
                if header not in headers:
                    findings.append(
                        Finding("HTTP Headers", meta["title"], meta["severity"], meta["description"], meta["recommendation"]).to_dict()
                    )
                else:
                    findings.append(
                        Finding("HTTP Headers", f"✓ {header.title()} Present", "info", f"Header value: {headers[header][:120]}", "No action needed.").to_dict()
                    )

            for header, meta in info_headers.items():
                if header in headers:
                    findings.append(
                        Finding("HTTP Headers", meta["title"], meta["severity"], f"{meta['description']} Value: {headers[header]}", meta["recommendation"]).to_dict()
                    )

    except Exception as e:
        findings.append(
            Finding("HTTP Headers", "Header Scan Error", "medium", str(e), "Ensure the URL is accessible.").to_dict()
        )
    return findings


# ─── APPLICATION LAYER DAST ──────────────────────────────────────────────────

async def scan_application_layer(base_url: str):
    findings = []
    if base_url.endswith("/"):
        base_url = base_url[:-1]
        
    sensitive_paths = {
        "/.env": ("Exposed Environment File", "critical", "The .env config file is publicly readable!", "Block access to hidden files (.env) immediately."),
        "/.git/config": ("Git Repository Exposed", "critical", "The .git config file is exposed. Attackers can download your entire source code history.", "Block web access to the .git directory."),
        "/server-status": ("Apache Server Status Exposed", "medium", "Server status module is enabled and publicly readable.", "Restrict access to an internal IP or disable it."),
        "/phpinfo.php": ("PHP Info Page Exposed", "high", "phpinfo() is dumping server configuration and env variables.", "Delete or restrict the phpinfo page.")
    }

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8) as client:
            tasks = [client.get(base_url + path) for path in sensitive_paths.keys()]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for path, response in zip(sensitive_paths.keys(), responses):
                if isinstance(response, Exception):
                    continue
                if response.status_code == 200:
                    title, severity, desc, rec = sensitive_paths[path]
                    
                    # Fast sanity checks for false positive home pages returning 200 OKs
                    content_type = response.headers.get("content-type", "").lower()
                    text_head = response.text[:200].lower()
                    
                    is_soft_404 = "html" in content_type and path in ["/.env", "/.git/config"]
                    is_git_confirm = path == "/.git/config" and "[core]" in text_head
                    is_env_confirm = path == "/.env" and "=" in text_head

                    if is_soft_404 and not (is_git_confirm or is_env_confirm):
                        continue # Standard HTML page fake-out!
                        
                    findings.append(Finding("Application Layer", f"{title} ({path})", severity, desc, rec).to_dict())
    except Exception as e:
        findings.append(
            Finding("Application Layer", "Application Scan Error", "medium", str(e), "Ensure target is responsive.").to_dict()
        )

    if not findings:
        findings.append(Finding("Application Layer", "No Exposed Endpoints", "info", "Common sensitive files are securely hidden or missing.", "Maintain strict directory traversal protections.").to_dict())
        
    return findings


# ─── OPEN PORTS SCANNER ─────────────────────────────────────────────────────

RISKY_PORTS = {
    21: ("FTP", "high", "FTP transmits credentials in plaintext.", "Disable FTP; use SFTP or SCP instead."),
    22: ("SSH", "low", "SSH port is open. Ensure strong auth and no root login.", "Use key-based auth, disable root login, and consider port knocking."),
    23: ("Telnet", "critical", "Telnet is open — transmits all data in plaintext including passwords.", "Disable Telnet immediately. Use SSH."),
    25: ("SMTP", "medium", "SMTP port open. Could be exploited for spam relay if misconfigured.", "Restrict SMTP relay and use authentication."),
    80: ("HTTP", "info", "Port 80 (HTTP) is open.", "Ensure HTTP redirects to HTTPS."),
    443: ("HTTPS", "info", "Port 443 (HTTPS) is open — expected.", "No action needed."),
    3306: ("MySQL", "critical", "MySQL database port is publicly exposed!", "Restrict MySQL to localhost or private network only."),
    5432: ("PostgreSQL", "critical", "PostgreSQL database port is publicly exposed!", "Restrict PostgreSQL to localhost or private network only."),
    6379: ("Redis", "critical", "Redis port is publicly exposed — often has no auth by default!", "Restrict Redis access and enable authentication."),
    27017: ("MongoDB", "critical", "MongoDB port is publicly exposed!", "Enable authentication and restrict MongoDB network access."),
    8080: ("HTTP-Alt", "medium", "Alternate HTTP port open. May expose dev/admin services.", "Ensure this port is intentional and properly secured."),
    8443: ("HTTPS-Alt", "low", "Alternate HTTPS port open.", "Verify this is intentional."),
    9200: ("Elasticsearch", "critical", "Elasticsearch port is publicly exposed — often unauthenticated!", "Restrict Elasticsearch to internal network only."),
    11211: ("Memcached", "high", "Memcached port is exposed. Can be abused for DDoS amplification.", "Bind Memcached to localhost only."),
}


def check_port(hostname, port, timeout=2):
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Step 1: Wait to see if server natively broadcasts a service banner (SSH, FTP)
            try:
                data = sock.recv(1024)
                if data:
                    return True
            except socket.timeout:
                pass
            
            # Step 2: Fire an active application payload to force a reaction from silent services
            try:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: " + hostname.encode() + b"\r\n\r\n")
                data = sock.recv(1024)
                if data:
                    return True
            except (socket.timeout, OSError):
                pass
                
            # Step 3: Connection accepted but completely dead -> Firewall False Positive!
            return False
    except:
        return False


def scan_ports(hostname: str):
    findings = []
    ports_to_check = list(RISKY_PORTS.keys())

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = {port: executor.submit(check_port, hostname, port) for port in ports_to_check}

    for port, future in results.items():
        is_open = future.result()
        if is_open and port in RISKY_PORTS:
            service, severity, description, recommendation = RISKY_PORTS[port]
            findings.append(
                Finding(
                    "Open Ports",
                    f"Port {port} ({service}) Open",
                    severity,
                    description,
                    recommendation,
                ).to_dict()
            )

    if not findings:
        findings.append(
            Finding("Open Ports", "No Risky Ports Detected", "info", "No commonly exploited ports were found open.", "Continue monitoring for new exposures.").to_dict()
        )
    return findings


# ─── DNS SCANNER ────────────────────────────────────────────────────────────


def scan_dns(hostname: str):
    findings = []

    # SPF
    try:
        answers = dns.resolver.resolve(hostname, "TXT")
        spf_found = False
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=spf1"):
                spf_found = True
                if "+all" in txt:
                    findings.append(
                        Finding("DNS", "Permissive SPF Record (+all)", "high", "SPF record uses +all which allows any server to send email on your behalf.", "Change +all to ~all or -all.").to_dict()
                    )
                elif "~all" in txt:
                    findings.append(
                        Finding("DNS", "SPF SoftFail (~all)", "low", "SPF uses ~all (softfail). Emails from unauthorized servers won't be rejected.", "Consider changing to -all for stricter enforcement.").to_dict()
                    )
                else:
                    findings.append(
                        Finding("DNS", "SPF Record Present", "info", f"SPF record: {txt[:100]}", "No action needed.").to_dict()
                    )

        if not spf_found:
            findings.append(
                Finding("DNS", "Missing SPF Record", "high", "No SPF DNS record found. Anyone can spoof email from your domain.", "Add an SPF TXT record to your DNS.").to_dict()
            )
    except dns.resolver.NoAnswer:
        findings.append(
            Finding("DNS", "Missing SPF Record", "high", "No SPF DNS record found. Anyone can spoof email from your domain.", "Add an SPF TXT record to your DNS.").to_dict()
        )
    except Exception as e:
        findings.append(
            Finding("DNS", "SPF Lookup Failed", "medium", str(e), "Verify your DNS configuration.").to_dict()
        )

    # DMARC
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{hostname}", "TXT")
        dmarc_found = False
        for rdata in dmarc_answers:
            txt = str(rdata).strip('"')
            if "v=DMARC1" in txt:
                dmarc_found = True
                if "p=none" in txt:
                    findings.append(
                        Finding("DNS", "DMARC Policy: None (Monitor Only)", "medium", "DMARC is set to p=none — emails won't be rejected even if they fail.", "Upgrade to p=quarantine or p=reject.").to_dict()
                    )
                else:
                    findings.append(
                        Finding("DNS", "DMARC Policy Present", "info", f"DMARC: {txt[:100]}", "No action needed.").to_dict()
                    )
        if not dmarc_found:
            findings.append(
                Finding("DNS", "Missing DMARC Record", "high", "No valid DMARC record found. Your domain is vulnerable to email spoofing.", "Add _dmarc TXT record with at least p=quarantine.").to_dict()
            )
    except Exception:
        findings.append(
            Finding("DNS", "Missing DMARC Record", "high", "No DMARC record found. Your domain is vulnerable to email spoofing.", "Add _dmarc TXT record with at least p=quarantine.").to_dict()
        )

    # DNSSEC
    try:
        answers = dns.resolver.resolve(hostname, "DNSKEY")
        findings.append(
            Finding("DNS", "DNSSEC Enabled", "info", "DNSSEC is configured for this domain.", "No action needed.").to_dict()
        )
    except dns.resolver.NoAnswer:
        findings.append(
            Finding("DNS", "DNSSEC Not Enabled", "low", "DNSSEC is not configured. DNS responses could be spoofed.", "Enable DNSSEC through your DNS registrar.").to_dict()
        )
    except Exception:
        findings.append(
            Finding("DNS", "DNSSEC Not Detected", "low", "Could not verify DNSSEC status.", "Check DNSSEC configuration with your DNS registrar.").to_dict()
        )

    # Zone transfer attempt
    try:
        ns_answers = dns.resolver.resolve(hostname, "NS")
        for ns in list(ns_answers)[:1]:
            ns_host = str(ns.target).rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, hostname, timeout=3))
                findings.append(
                    Finding("DNS", "DNS Zone Transfer Allowed!", "critical", f"The nameserver {ns_host} allows unauthenticated zone transfers, exposing all DNS records.", "Disable zone transfers or restrict to authorized IPs only.").to_dict()
                )
            except:
                findings.append(
                    Finding("DNS", "Zone Transfer Blocked", "info", "DNS zone transfer is not publicly allowed.", "No action needed.").to_dict()
                )
    except Exception:
        pass

    return findings


# ─── GITHUB SCANNER (no API — uses git clone) ───────────────────────────────

SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', "API Key", "critical"),
    (r'(?i)(secret[_-]?key|secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', "Secret Key", "critical"),
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s\'"]{8,})', "Hardcoded Password", "critical"),
    (r'(?i)(aws_access_key_id)\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})', "AWS Access Key", "critical"),
    (r'(?i)(aws_secret_access_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Key", "critical"),
    (r'(?i)(token)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{20,})', "Auth Token", "high"),
    (r'(?i)(private[_-]?key)\s*[:=]\s*["\']?([^\s\'"]{20,})', "Private Key", "critical"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token", "critical"),
    (r'sk-[A-Za-z0-9]{48}', "OpenAI API Key", "critical"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private Key in Code", "critical"),
    (r'(?i)(database_url|db_url|connection_string)\s*[:=]\s*["\']?([^\s\'"]{10,})', "DB Connection String", "high"),
]

SAST_PATTERNS = [
    (r'(?i)eval\s*\(', "Insecure code evaluation (eval)", "high", "Using eval() allows Remote Code Execution if user input is passed.", "Avoid eval(). Use safe parsers like ast.literal_eval."),
    (r'(?i)exec\s*\(', "Insecure code execution (exec)", "high", "Using exec() processes dynamic code, leading to RCE.", "Refactor logic to eliminate exec()."),
    (r'(?i)subprocess\.(call|Popen|run)\s*\([^)]*shell\s*=\s*True', "Command Injection (shell=True)", "critical", "Executing commands with shell=True is highly vulnerable to injection attacks.", "Set shell=False and pass arguments as a list."),
    (r'(?i)(SELECT\s+.*?\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*)["\']?\s*\+\s*[a-zA-Z_]', "SQL Injection Potential (String Concatenation)", "critical", "Building SQL queries manually with strings invites SQL Injection.", "Use parameterized queries or ORMs."),
    (r'(?i)dangerouslySetInnerHTML', "Cross-Site Scripting (Reflected/Stored XSS)", "high", "Using dangerouslySetInnerHTML in React completely bypasses HTML sanitization.", "Sanitize inputs with DOMPurify before rendering HTML, or use native JSX properties."),
    (r'(?i)(pickle|yaml)\.(load|loads)\s*\(', "Insecure Deserialization", "high", "Loading untrusted YAML or Pickle data allows arbitrary code execution.", "Use yaml.safe_load() or JSON libraries instead of pickle."),
]

DEPENDENCY_CVE_HINTS = {
    "log4j": ("log4j", "critical", "Log4Shell (CVE-2021-44228): Critical RCE in Log4j. Update to 2.17.1+"),
    "struts": ("struts", "critical", "Apache Struts has had critical RCE CVEs. Verify your version."),
    "jackson-databind": ("jackson-databind", "high", "jackson-databind has had multiple deserialization CVEs."),
    "spring-core": ("spring-core", "high", "Spring4Shell (CVE-2022-22965) affects Spring Core. Ensure you're on 5.3.18+."),
    "lodash": ("lodash", "medium", "Older lodash versions have prototype pollution CVEs."),
    "moment": ("moment", "low", "moment.js has ReDoS vulnerabilities. Consider migrating to date-fns."),
    "pyyaml": ("pyyaml", "high", "Older PyYAML versions allow arbitrary code execution via yaml.load(). Use yaml.safe_load()."),
    "requests": ("requests", "low", "Ensure requests library is up to date for latest security patches."),
    "cryptography": ("cryptography", "medium", "Keep cryptography library updated to avoid known vulnerabilities."),
    "django": ("django", "medium", "Ensure Django is on latest LTS version for security patches."),
    "flask": ("flask", "low", "Keep Flask updated for security patches."),
    "express": ("express", "low", "Keep Express.js updated for security patches."),
    "axios": ("axios", "medium", "Older axios versions have SSRF and ReDoS vulnerabilities."),
    "node-fetch": ("node-fetch", "medium", "Some node-fetch versions have known vulnerabilities."),
    "serialize-javascript": ("serialize-javascript", "high", "Older versions allow XSS. Update to 3.1.0+."),
}

SENSITIVE_FILE_PATTERNS = [
    (r'(^|/)\.env(\.|$)', "Environment File Found", "critical",
     ".env files often contain secrets and should never be committed.",
     "Add .env to .gitignore immediately and rotate any exposed secrets."),
    (r'(^|/)\.env\.(local|prod|production|staging|dev)$', "Environment File Found", "critical",
     "Environment-specific config file committed.",
     "Remove from repo and add to .gitignore."),
    (r'(private|secret|credentials)[_\-].*\.(key|pem|json|yaml|yml)$', "Credential File in Repo", "critical",
     "A file named after credentials or private keys was found.",
     "Remove from git history and rotate credentials."),
    (r'.*\.pem$', "PEM Certificate/Key File", "high",
     "PEM files may contain private keys.",
     "Remove from repo; never commit private keys."),
    (r'(^|/)id_rsa$', "SSH Private Key", "critical",
     "SSH private key committed to repository.",
     "Remove immediately and regenerate keys."),
    (r'(wp-config\.php|web\.config|config\.php)$', "Configuration File Exposed", "medium",
     "Application config file may contain database credentials.",
     "Audit this file for hardcoded secrets."),
    (r'.*\.tfstate$', "Terraform State File", "high",
     "Terraform state files may contain sensitive infrastructure data.",
     "Use remote state backends and never commit .tfstate."),
    (r'(^|/)\.git-credentials$', "Git Credentials File", "critical",
     "Git credentials file committed — may contain plaintext passwords.",
     "Remove immediately and rotate credentials."),
]

SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml",
    ".json", ".php", ".rb", ".go", ".java", ".sh", ".bash", ".config",
    ".toml", ".ini", ".cfg", ".xml",
}

DEP_FILES = {
    "requirements.txt", "package.json", "pom.xml", "build.gradle",
    "gemfile", "composer.json", "pipfile", "pyproject.toml", "go.mod",
}


def _clone_repo(clone_url: str, target_dir: str) -> Tuple[bool, str]:
    """Shallow clone a repo into target_dir. Returns (success, error_msg)."""
    result = subprocess.run(
        ["git", "clone", "--depth=1", "--single-branch", "-q", clone_url, target_dir],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        return False, result.stderr.strip()
    return True, ""


def scan_github_local(repo_url: str) -> list:
    findings = []

    # Normalize URL
    match = re.search(r"github\.com[/:]([^/]+)/([^/\s]+)", repo_url)
    if not match:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")
    owner = match.group(1)
    repo = match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    clone_url = f"https://github.com/{owner}/{repo}.git"

    tmpdir = tempfile.mkdtemp(prefix="shieldworks_")
    repo_dir = os.path.join(tmpdir, "repo")

    try:
        # Clone
        ok, err = _clone_repo(clone_url, repo_dir)
        if not ok:
            raise HTTPException(status_code=400, detail=f"Could not clone repo: {err}")

        findings.append(
            Finding("GitHub", "Repository Cloned Successfully", "info",
                    f"Scanned {owner}/{repo} via shallow clone (no API key required).",
                    "No action needed.").to_dict()
        )

        secrets_found = set()
        dep_checked = set()

        for root, dirs, files in os.walk(repo_dir):
            # Skip .git internals
            dirs[:] = [d for d in dirs if d != ".git"]

            for fname in files:
                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, repo_dir)
                fname_lower = fname.lower()
                ext = os.path.splitext(fname_lower)[1]

                # ── Sensitive file name check ──
                for pattern, title, severity, description, recommendation in SENSITIVE_FILE_PATTERNS:
                    if re.search(pattern, rel_path, re.IGNORECASE):
                        findings.append(
                            Finding("GitHub", f"{title}: {rel_path}", severity,
                                    description, recommendation).to_dict()
                        )
                        break

                # ── Dependency CVE check ──
                if fname_lower in DEP_FILES and fname_lower not in dep_checked:
                    dep_checked.add(fname_lower)
                    try:
                        with open(full_path, "r", errors="ignore") as f:
                            content = f.read()
                        for keyword, (pkg, severity, description) in DEPENDENCY_CVE_HINTS.items():
                            if keyword.lower() in content.lower():
                                findings.append(
                                    Finding(
                                        "GitHub",
                                        f"Potentially Vulnerable Dependency: {pkg}",
                                        severity,
                                        f"Found in {rel_path}. {description}",
                                        "Run `pip audit` or `npm audit` to check for known CVEs.",
                                    ).to_dict()
                                )
                    except Exception:
                        pass

                # ── Secret scan in source files ──
                if ext in SOURCE_EXTENSIONS:
                    try:
                        size = os.path.getsize(full_path)
                        if size > 500_000:  # skip huge files
                            continue
                        with open(full_path, "r", errors="ignore") as f:
                            content = f.read()
                        for pattern, secret_type, severity in SECRET_PATTERNS:
                            if secret_type in secrets_found:
                                continue
                            if re.search(pattern, content):
                                secrets_found.add(secret_type)
                                findings.append(
                                    Finding(
                                        "GitHub",
                                        f"Potential {secret_type} in Source Code",
                                        severity,
                                        f"Found in {rel_path}. Hardcoded secrets are a critical security risk.",
                                        "Remove the secret, rotate it immediately, and use environment variables or a secrets manager.",
                                    ).to_dict()
                                )
                                
                        # New SAST Pattern Scan
                        for pattern, ast_type, severity, description, rec in SAST_PATTERNS:
                            if re.search(pattern, content):
                                findings.append(
                                    Finding("GitHub SAST", f"Vulnerable Pattern: {ast_type}", severity, f"Found in {rel_path}. {description}", rec).to_dict()
                                )
                    except Exception:
                        pass

        if not any(f["category"] == "GitHub" and f["severity"] in ["critical", "high"] for f in findings):
            findings.append(
                Finding("GitHub", "No Critical Secrets Detected", "info",
                        "No obvious hardcoded secrets found in scanned files.",
                        "Continue using tools like GitGuardian for full historical coverage.").to_dict()
            )

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return findings


# ─── LOCAL CODEBASE SCANNER ─────────────────────────────────────────────────

def scan_local_dir(directory: str) -> list:
    findings = []
    if not os.path.exists(directory) or not os.path.isdir(directory):
        raise HTTPException(status_code=400, detail="Local directory does not exist or is inaccessible.")

    findings.append(Finding("Local Source", "Started Local Static Analysis", "info", f"Scanning: {directory}. Loaded via scanner_logic.", "Ensure this folder is fully trusted before running SAST.").to_dict())

    # Offload scanning to scanner_logic
    raw_findings = scanner_logic.scan_repo(directory)
    
    for f in raw_findings:
        findings.append(Finding(
            category=f.get("category", "Local SAST"),
            title=f.get("category", "Analysis Finding"),
            severity=f.get("severity", "info").lower(),
            description=f.get("detail", ""),
            recommendation=f"File: {os.path.basename(f.get('source', ''))}"
        ).to_dict())

    if len(findings) == 1:
        findings.append(Finding("Local SAST", "No Issues Detected", "info", "No hardcoded secrets or patterns were found by scanner_logic.", "Keep dependencies updated.").to_dict())

    return findings


# ─── SOFTWARE / APK SCANNER COMPONENT ────────────────────────────────────────

def scan_software_file(file_bytes: bytes, filename: str) -> list:
    findings = []
    
    # Write to a temporary file because scanner_logic expects a path
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        report = scanner_logic.full_scan(apk_path=tmp_path, skip_virustotal=True)
        raw_findings = report.get("findings", [])
        
        for f in raw_findings:
            findings.append(Finding(
                category=f.get("category", "Software Scan"),
                title=f.get("category", "Analysis Finding"),
                severity=f.get("severity", "info").lower(),
                description=f.get("detail", ""),
                recommendation=f"Found in source file"
            ).to_dict())
            
        if not findings:
             findings.append(Finding("Software Scan", "No Obvious Secrets Found", "info", "Did not detect standard API keys or tokens in plain text.", "Employ obfuscation (e.g. ProGuard) regardless to slow reverse engineering.").to_dict())

    finally:
        os.remove(tmp_path)

    return findings


# ─── ROUTES ─────────────────────────────────────────────────────────────────




@app.post("/api/scan/url")
async def scan_url(request: URLScanRequest):
    url = request.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL")

    # Run scans concurrently
    loop = asyncio.get_event_loop()
    ssl_task = loop.run_in_executor(None, scan_ssl, hostname)
    port_task = loop.run_in_executor(None, scan_ports, hostname)
    dns_task = loop.run_in_executor(None, scan_dns, hostname)
    header_task = scan_headers(url)
    app_layer_task = scan_application_layer(url)

    ssl_findings, port_findings, dns_findings, header_findings, app_findings = await asyncio.gather(
        ssl_task, port_task, dns_task, header_task, app_layer_task
    )

    all_findings = ssl_findings + header_findings + port_findings + dns_findings + app_findings
    score = compute_score(all_findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    return {
        "target": url,
        "hostname": hostname,
        "scan_type": "url",
        "score": score,
        "severity_counts": severity_counts,
        "findings": all_findings,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan/github")
async def scan_github_repo(request: GitHubScanRequest):
    loop = asyncio.get_event_loop()
    findings = await loop.run_in_executor(None, scan_github_local, request.repo_url)
    score = compute_score(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    return {
        "target": request.repo_url,
        "scan_type": "github",
        "score": score,
        "severity_counts": severity_counts,
        "findings": findings,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan/local")
async def scan_local_codebase(request: LocalScanRequest):
    loop = asyncio.get_event_loop()
    findings = await loop.run_in_executor(None, scan_local_dir, request.directory)
    score = compute_score(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    return {
        "target": request.directory,
        "scan_type": "local",
        "score": score,
        "severity_counts": severity_counts,
        "findings": findings,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan/software")
async def scan_software_post(file: UploadFile = File(...)):
    content = await file.read()
    
    loop = asyncio.get_event_loop()
    findings = await loop.run_in_executor(None, scan_software_file, content, file.filename)
    score = compute_score(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    return {
        "target": file.filename,
        "scan_type": "software",
        "score": score,
        "severity_counts": severity_counts,
        "findings": findings,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/status")
async def get_status():
    """Returns the operational status of the scanner and its environment."""
    git_installed = shutil.which("git") is not None
    return {
        "status": "online",
        "version": "1.1.0",
        "environment": {
            "git_available": git_installed,
            "os": os.name,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    }


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
