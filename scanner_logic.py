import os
import hashlib
import re
import xml.etree.ElementTree as ET
import ssl
import socket
import dns.resolver
import dns.zone
import dns.query
import httpx
import tempfile
import shutil
import asyncio
import concurrent.futures
import certifi
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Tuple, List, Dict

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ==============================
# CONFIG
# ==============================
VT_API_KEY = "your_api_key_here"  # Replace with your VirusTotal API key

# ==============================
# PATTERN DEFINITIONS
# ==============================

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
    (r'(?i)exec\s*\(', "Insecure code evaluation (exec)", "high", "Using exec() processes dynamic code, leading to RCE.", "Refactor logic to eliminate exec()."),
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
}

SENSITIVE_FILE_PATTERNS = [
    (r'(^|/)\.env(\.|$)', "Environment File Found", "critical", ".env files often contain secrets and should never be committed.", "Add .env to .gitignore immediately and rotate any exposed secrets."),
    (r'(^|/)\.env\.(local|prod|production|staging|dev)$', "Environment File Found", "critical", "Environment-specific config file committed.", "Remove from repo and add to .gitignore."),
    (r'(private|secret|credentials)[_\-].*\.(key|pem|json|yaml|yml)$', "Credential File in Repo", "critical", "A file named after credentials or private keys was found.", "Remove from git history and rotate credentials."),
    (r'.*\.pem$', "PEM Certificate/Key File", "high", "PEM files may contain private keys.", "Remove from repo; never commit private keys."),
    (r'(^|/)id_rsa$', "SSH Private Key", "critical", "SSH private key committed to repository.", "Remove immediately and regenerate keys."),
    (r'(wp-config\.php|web\.config|config\.php)$', "Configuration File Exposed", "medium", "Application config file may contain database credentials.", "Audit this file for hardcoded secrets."),
    (r'.*\.tfstate$', "Terraform State File", "high", "Terraform state files may contain sensitive infrastructure data.", "Use remote state backends and never commit .tfstate."),
    (r'(^|/)\.git-credentials$', "Git Credentials File", "critical", "Git credentials file committed — may contain plaintext passwords.", "Remove immediately and rotate credentials."),
]

SOURCE_EXTENSIONS = { ".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml", ".json", ".php", ".rb", ".go", ".java", ".sh", ".bash", ".config", ".toml", ".ini", ".cfg", ".xml" }

DEP_FILES = { "requirements.txt", "package.json", "pom.xml", "build.gradle", "gemfile", "composer.json", "pipfile", "pyproject.toml", "go.mod" }

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}

# ==============================
# CLASSES & UTILITY
# ==============================

class Finding:
    def __init__(self, category, title, severity, description, recommendation):
        self.category = category
        self.title = title
        self.severity = severity.lower()  # critical, high, medium, low, info
        self.description = description
        self.recommendation = recommendation

    def to_dict(self):
        return {
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
        }

def compute_score(findings):
    if not findings:
        return 100
    penalties = sum(
        {"critical": 30, "high": 15, "medium": 8, "low": 3, "info": 0}.get(
            f["severity"], 0
        )
        for f in findings
    )
    score = max(0, 100 - penalties)
    return score

def _severity_label(category: str) -> str:
    """Map finding category to severity string."""
    HIGH = {"MALWARE RISK", "SUSPICIOUS FILE", "PRIVATE_KEY", "AWS_KEY", "critical", "high"}
    MEDIUM = {"DATA LEAK", "MISCONFIG", "medium"}
    if category.upper() in HIGH:
        return "high"
    if category.upper() in MEDIUM:
        return "medium"
    return "low"

# ==============================
# 1. FILE VALIDATION
# ==============================

def is_apk_valid(file_path: str) -> bool:
    """Return True if the path points to an existing .apk file."""
    return os.path.isfile(file_path) and file_path.lower().endswith(".apk")

# ==============================
# 2. HASH GENERATION
# ==============================

def get_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Compute and return the hex digest of a file."""
    h = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# ==============================
# 3. VIRUSTOTAL SCAN
# ==============================

def scan_with_virustotal(file_path: str) -> dict:
    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed"}
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    try:
        with open(file_path, "rb") as f:
            response = requests.post(url, files={"file": f}, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        return {"error": str(exc)}

def parse_vt_result(vt_result: dict) -> tuple:
    if "error" in vt_result:
        return 0, f"VirusTotal unavailable: {vt_result['error']}"
    try:
        stats = vt_result["data"]["attributes"]["last_analysis_stats"]
        hits = stats.get("malicious", 0)
        return hits, f"{hits} malicious detection(s)"
    except (KeyError, TypeError):
        return 0, "Could not parse VirusTotal response"

# ==============================
# 4. ANDROID MANIFEST CHECK
# ==============================

def check_manifest(manifest_path: str) -> list:
    findings = []
    if not manifest_path or not os.path.isfile(manifest_path):
        return findings
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        raw = ET.tostring(root).decode()
        if 'debuggable="true"' in raw:
            findings.append({"category": "MISCONFIG", "detail": 'App is debuggable (debuggable="true")', "severity": "high", "source": manifest_path})
        for elem in root.iter():
            if elem.attrib.get("exported") == "true":
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                name = elem.attrib.get("{http://schemas.android.com/apk/res/android}name", tag)
                findings.append({"category": "MISCONFIG", "detail": f"Exported component: {name}", "severity": "medium", "source": manifest_path})
    except ET.ParseError as exc:
        findings.append({"category": "MISCONFIG", "detail": f"Manifest parse error: {exc}", "severity": "low", "source": manifest_path})
    return findings

# ==============================
# 5. STATIC FILE ANALYSIS
# ==============================

def scan_file_content(file_path: str) -> list:
    findings = []
    if os.path.splitext(file_path)[1].lower() in {".exe", ".dll", ".bin", ".sh"}:
        findings.append({"category": "SUSPICIOUS FILE", "detail": f"Suspicious extension: {os.path.basename(file_path)}", "severity": "high", "source": file_path})
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
    except OSError:
        return findings

    for pattern, secret_type, severity in SECRET_PATTERNS:
        if re.search(pattern, content):
            findings.append({"category": "DATA LEAK", "detail": f"Potential {secret_type} in Source Code", "severity": severity, "source": file_path})
    
    for pattern, ast_type, severity, description, rec in SAST_PATTERNS:
        if re.search(pattern, content):
            findings.append({"category": "SAST", "detail": f"Vulnerable Pattern: {ast_type}", "severity": severity, "source": file_path})

    return findings

def scan_repo(repo_path: str) -> list:
    all_findings = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            file_path = os.path.join(root, filename)
            all_findings.extend(scan_file_content(file_path))
    return all_findings

# ==============================
# 6. EXTERNAL SCAN MODULES (URL, DNS, PORTS, ETC.)
# ==============================

def scan_ssl(hostname: str, port: int = 443):
    findings = []
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    findings.append(Finding("SSL/TLS", f"Outdated TLS Version: {version}", "high", "Server supports deprecated TLS version.", "Upgrade to TLS 1.2+.").to_dict())
                else:
                    findings.append(Finding("SSL/TLS", f"TLS Version: {version}", "info", f"Server uses {version}.", "No action needed.").to_dict())
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        findings.append(Finding("SSL/TLS", "SSL Certificate Expired", "critical", f"Expired {abs(days_left)} days ago.", "Renew certificate.").to_dict())
                    elif days_left < 30:
                        findings.append(Finding("SSL/TLS", "SSL Certificate Expiring Soon", "medium", f"Expires in {days_left} days.", "Plan renewal.").to_dict())
    except Exception as e:
        findings.append(Finding("SSL/TLS", "SSL Check Error", "medium", str(e), "Verify SSL config.").to_dict())
    return findings

async def scan_headers(url: str):
    findings = []
    security_headers = {
        "strict-transport-security": {"title": "Missing HSTS", "severity": "high", "desc": "HSTS not set.", "rec": "Add HSTS header."},
        "content-security-policy": {"title": "Missing CSP", "severity": "high", "desc": "No CSP header.", "rec": "Add CSP header."},
        "x-frame-options": {"title": "Missing X-Frame-Options", "severity": "medium", "desc": "Clickjacking risk.", "rec": "Add X-Frame-Options."},
    }
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            for header, meta in security_headers.items():
                if header not in headers:
                    findings.append(Finding("HTTP Headers", meta["title"], meta["severity"], meta["desc"], meta["rec"]).to_dict())
    except Exception as e:
        findings.append(Finding("HTTP Headers", "Header Scan Error", "medium", str(e), "Check URL.").to_dict())
    return findings

def check_port(hostname, port, timeout=2):
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            return True
    except:
        return False

def scan_ports(hostname: str):
    findings = []
    RISKY_PORTS = { 21: "FTP", 22: "SSH", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis" }
    for port, svc in RISKY_PORTS.items():
        if check_port(hostname, port):
            findings.append(Finding("Open Ports", f"Port {port} ({svc}) Open", "critical" if port in [21, 23, 3306, 6379] else "medium", f"Exposed {svc} service.", "Restrict access.").to_dict())
    return findings

def scan_dns(hostname: str):
    findings = []
    try:
        answers = dns.resolver.resolve(hostname, "TXT")
        spf_found = any("v=spf1" in str(rdata) for rdata in answers)
        if not spf_found:
            findings.append(Finding("DNS", "Missing SPF Record", "high", "No SPF record found.", "Add SPF record.").to_dict())
    except:
        findings.append(Finding("DNS", "Missing SPF Record", "high", "No SPF record found.", "Add SPF record.").to_dict())
    return findings

async def scan_application_layer(base_url: str):
    findings = []
    sensitive_paths = { "/.env": "Environment file", "/.git/config": "Git config" }
    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        for path, desc in sensitive_paths.items():
            try:
                resp = await client.get(base_url.rstrip("/") + path)
                if resp.status_code == 200:
                    findings.append(Finding("App Layer", f"Exposed {desc}", "critical", f"Found {path}.", "Block access.").to_dict())
            except:
                pass
    return findings

def scan_github_local(repo_url: str) -> list:
    findings = []
    tmpdir = tempfile.mkdtemp(prefix="shield_")
    repo_dir = os.path.join(tmpdir, "repo")
    try:
        res = subprocess.run(["git", "clone", "--depth=1", repo_url, repo_dir], capture_output=True, text=True)
        if res.returncode == 0:
            findings.extend(scan_repo(repo_dir))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return findings

# ==============================
# 7. UNIFIED ENTRY POINT
# ==============================

def full_scan(apk_path: str, skip_virustotal: bool = False) -> dict:
    if not is_apk_valid(apk_path):
        return {}
    file_hash = get_file_hash(apk_path)
    vt_hits, vt_status = 0, "Skipped"
    if not skip_virustotal:
        vt_result = scan_with_virustotal(apk_path)
        vt_hits, vt_status = parse_vt_result(vt_result)
    
    static_findings = scan_repo(os.path.dirname(apk_path))
    all_findings = static_findings
    score = compute_score(all_findings)
    
    return {
        "target": apk_path,
        "sha256": file_hash,
        "virustotal": {"hits": vt_hits, "status": vt_status},
        "findings": all_findings,
        "score": score,
        "scanned_at": datetime.now(timezone.utc).isoformat()
    }

if __name__ == "__main__":
    import subprocess
