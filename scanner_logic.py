"""
Shield Works - Unified Mobile & Repository Security Scanner
Merges APK/manifest scanning with repo-wide static analysis.
"""

import os
import hashlib
import re
import xml.etree.ElementTree as ET

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

SENSITIVE_DATA_PATTERNS = {
    "API_KEY":      r"(?i)api[_-]?key\s*=\s*['\"].+['\"]",
    "PASSWORD":     r"(?i)password\s*=\s*['\"].+['\"]",
    "TOKEN":        r"(?i)token\s*=\s*['\"].+['\"]",
    "EMAIL":        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "AWS_KEY":      r"AKIA[0-9A-Z]{16}",
    "PRIVATE_KEY":  r"-----BEGIN PRIVATE KEY-----",
    "HTTP_URL":     r"http://[^\s\"']+",   # Insecure HTTP endpoints
}

MALWARE_PATTERNS = {
    "EVAL_USAGE":    r"\beval\(",
    "EXEC_USAGE":    r"\bexec\(",
    "BASE64_DECODE": r"base64\.b64decode",
    "SYSTEM_CALL":   r"os\.system|subprocess\.Popen",
}

MISCONFIG_PATTERNS = {
    "DEBUG_MODE":    r"DEBUG\s*=\s*True",
    "OPEN_DB_HOST":  r"host\s*=\s*['\"]0\.0\.0\.0['\"]",
}

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bin", ".sh"}

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}

# ==============================
# UTILITY
# ==============================

def _severity_label(category: str) -> str:
    """Map finding category to severity string."""
    HIGH = {"MALWARE RISK", "SUSPICIOUS FILE", "PRIVATE_KEY", "AWS_KEY"}
    MEDIUM = {"DATA LEAK", "MISCONFIG"}
    if category in HIGH:
        return "HIGH"
    if category in MEDIUM:
        return "MEDIUM"
    return "LOW"


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
    """
    Upload a file to VirusTotal and return the raw JSON response.
    Returns an error dict if requests is unavailable or the call fails.
    """
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
    """
    Extract malware hit count and a status message from a VT response.
    Returns (hit_count, status_message).
    """
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
    """
    Parse AndroidManifest.xml and return a list of misconfiguration findings.
    Each finding is a dict: {category, detail, severity, source}
    """
    findings = []

    if not manifest_path or not os.path.isfile(manifest_path):
        return findings

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        raw = ET.tostring(root).decode()

        if 'debuggable="true"' in raw:
            findings.append({
                "category": "MISCONFIG",
                "detail": 'App is debuggable (debuggable="true")',
                "severity": "HIGH",
                "source": manifest_path,
            })

        for elem in root.iter():
            if elem.attrib.get("exported") == "true":
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                name = elem.attrib.get(
                    "{http://schemas.android.com/apk/res/android}name", tag
                )
                findings.append({
                    "category": "MISCONFIG",
                    "detail": f"Exported component: {name}",
                    "severity": "MEDIUM",
                    "source": manifest_path,
                })

    except ET.ParseError as exc:
        findings.append({
            "category": "MISCONFIG",
            "detail": f"Manifest parse error: {exc}",
            "severity": "LOW",
            "source": manifest_path,
        })

    return findings


# ==============================
# 5. STATIC FILE ANALYSIS
# ==============================

def scan_file_content(file_path: str) -> list:
    """
    Scan a single file for sensitive data, malware indicators, and misconfigs.
    Returns a list of finding dicts.
    """
    findings = []

    # Flag suspicious file extensions immediately
    if os.path.splitext(file_path)[1].lower() in SUSPICIOUS_EXTENSIONS:
        findings.append({
            "category": "SUSPICIOUS FILE",
            "detail": f"Suspicious extension: {os.path.basename(file_path)}",
            "severity": "HIGH",
            "source": file_path,
        })

    # Read and pattern-match file content
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
    except OSError:
        return findings  # Unreadable — skip silently

    for name, pattern in SENSITIVE_DATA_PATTERNS.items():
        matches = re.findall(pattern, content)
        for match in matches:
            preview = (match[:80] + "...") if len(match) > 80 else match
            findings.append({
                "category": "DATA LEAK",
                "detail": f"{name}: {preview}",
                "severity": _severity_label(name),
                "source": file_path,
            })

    for name, pattern in MALWARE_PATTERNS.items():
        if re.search(pattern, content):
            findings.append({
                "category": "MALWARE RISK",
                "detail": f"Indicator detected: {name}",
                "severity": "HIGH",
                "source": file_path,
            })

    for name, pattern in MISCONFIG_PATTERNS.items():
        if re.search(pattern, content):
            findings.append({
                "category": "MISCONFIG",
                "detail": f"Misconfiguration: {name}",
                "severity": "MEDIUM",
                "source": file_path,
            })

    return findings


def scan_repo(repo_path: str) -> list:
    """
    Walk a directory tree and scan every file.
    Returns a flat list of all findings.
    """
    all_findings = []

    for root, dirs, files in os.walk(repo_path):
        # Prune irrelevant directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            file_path = os.path.join(root, filename)
            all_findings.extend(scan_file_content(file_path))

    return all_findings


# ==============================
# 6. RISK SCORING
# ==============================

def calculate_risk_score(vt_hits: int, findings: list) -> tuple:
    """
    Compute a numeric risk score and return (score, label).

    Weights:
      VT malware hit  -> +5 each
      HIGH finding    -> +3 each
      MEDIUM finding  -> +2 each
      LOW finding     -> +1 each
    """
    score = vt_hits * 5
    severity_weights = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for f in findings:
        score += severity_weights.get(f.get("severity", "LOW"), 1)

    if score >= 15:
        label = "CRITICAL"
    elif score >= 10:
        label = "HIGH RISK"
    elif score >= 5:
        label = "MEDIUM RISK"
    else:
        label = "LOW RISK"

    return score, label


# ==============================
# 7. REPORT GENERATION
# ==============================

def build_report(
    apk_path: str,
    file_hash: str,
    vt_hits: int,
    vt_status: str,
    manifest_findings: list,
    static_findings: list,
) -> dict:
    """Assemble and return a structured report dict from all scan results."""
    all_findings = manifest_findings + static_findings
    score, risk_label = calculate_risk_score(vt_hits, all_findings)

    by_severity = {"HIGH": [], "MEDIUM": [], "LOW": []}
    for f in all_findings:
        by_severity.setdefault(f.get("severity", "LOW"), []).append(f)

    return {
        "target": apk_path,
        "sha256": file_hash,
        "virustotal": {"hits": vt_hits, "status": vt_status},
        "findings": all_findings,
        "findings_by_severity": by_severity,
        "total_findings": len(all_findings),
        "risk_score": score,
        "risk_label": risk_label,
        "summary": {
            "malware_hits": vt_hits,
            "manifest_issues": len(manifest_findings),
            "static_issues": len(static_findings),
            "high": len(by_severity["HIGH"]),
            "medium": len(by_severity["MEDIUM"]),
            "low": len(by_severity["LOW"]),
        },
    }


def print_report(report: dict) -> None:
    """Pretty-print a scan report to stdout."""
    divider = "=" * 62

    print(f"\n{divider}")
    print("  Shield Works — Security Scan Report")
    print(divider)
    print(f"  Target  : {report['target']}")
    print(f"  SHA-256 : {report['sha256']}")
    print(f"  VT      : {report['virustotal']['status']}")
    print(divider)

    if report["findings"]:
        print(f"\n  Findings ({report['total_findings']} total):\n")
        icons = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}
        for sev in ("HIGH", "MEDIUM", "LOW"):
            for f in report["findings_by_severity"].get(sev, []):
                icon = icons.get(sev, "•")
                print(f"  {icon} [{sev}] [{f['category']}] {f['detail']}")
                print(f"       Source: {f['source']}")
    else:
        print("\n  No issues found.")

    s = report["summary"]
    print(f"\n{divider}")
    print("  SUMMARY")
    print(f"  Risk Level  : {report['risk_label']}  (score: {report['risk_score']})")
    print(f"  VT Hits     : {s['malware_hits']}")
    print(f"  High        : {s['high']}")
    print(f"  Medium      : {s['medium']}")
    print(f"  Low         : {s['low']}")
    print(divider + "\n")


# ==============================
# 8. UNIFIED ENTRY POINT
# ==============================

def full_scan(
    apk_path: str,
    manifest_path: str = None,
    repo_path: str = None,
    skip_virustotal: bool = False,
) -> dict:
    """
    Run a complete security scan.

    Parameters
    ----------
    apk_path        : Path to the .apk file (required).
    manifest_path   : Path to AndroidManifest.xml (optional).
    repo_path       : Root directory for static file scan (optional).
                      Defaults to the directory containing the APK.
    skip_virustotal : Set True to bypass the VT upload (useful for testing).

    Returns
    -------
    A structured report dict (see build_report).
    """
    print("\n🔍 Shield Works — Starting Security Scan...\n")

    # --- Validate APK ---
    if not is_apk_valid(apk_path):
        print(f"❌ Invalid APK path: {apk_path}")
        return {}

    print(f"✔ APK found : {apk_path}")

    # --- Hash ---
    file_hash = get_file_hash(apk_path)
    print(f"✔ SHA-256   : {file_hash}")

    # --- VirusTotal ---
    vt_hits, vt_status = 0, "Skipped"
    if not skip_virustotal:
        print("🛡  Uploading to VirusTotal...")
        vt_result = scan_with_virustotal(apk_path)
        vt_hits, vt_status = parse_vt_result(vt_result)
        print(f"✔ VT result : {vt_status}")

    # --- Manifest ---
    manifest_findings = check_manifest(manifest_path)
    if manifest_path:
        print(f"✔ Manifest  : {len(manifest_findings)} issue(s) found")

    # --- Static / Repo scan ---
    scan_root = repo_path or os.path.dirname(os.path.abspath(apk_path)) or "."
    print(f"🔎 Static scan root: {scan_root}")
    static_findings = scan_repo(scan_root)
    print(f"✔ Static scan: {len(static_findings)} finding(s)")

    # --- Build & display report ---
    report = build_report(
        apk_path, file_hash, vt_hits, vt_status,
        manifest_findings, static_findings
    )
    print_report(report)
    return report


# ==============================
# CLI
# ==============================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Shield Works — APK & Repository Security Scanner"
    )
    parser.add_argument("apk", help="Path to the .apk file")
    parser.add_argument("--manifest", default=None,
                        help="Path to AndroidManifest.xml")
    parser.add_argument("--repo", default=None,
                        help="Root path for static repo scan (default: APK directory)")
    parser.add_argument("--no-vt", action="store_true",
                        help="Skip VirusTotal upload")
    args = parser.parse_args()

    full_scan(
        apk_path=args.apk,
        manifest_path=args.manifest,
        repo_path=args.repo,
        skip_virustotal=args.no_vt,
    )
