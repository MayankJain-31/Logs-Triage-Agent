"""Tool implementations for the Cybersecurity Log Triage Agent."""

import json
import re


_ATTACK_SIGNATURES = [
    (re.compile(r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table|--\s*$|%27)", re.S),
     "SQL Injection (SQLi)", "Critical"),
    (re.compile(r"(?i)(<script|onerror\s*=|javascript:|on(load|click|mouse)\s*=)", re.S),
     "Cross-Site Scripting (XSS)", "High"),
    (re.compile(r"(?i)(/etc/passwd|/etc/shadow|cmd\.exe|powershell|/bin/(ba)?sh)", re.S),
     "Remote Code Execution (RCE)", "Critical"),
    (re.compile(r"(\.\./|\.\.\\|%2e%2e(%2f|%5c))", re.I),
     "Directory Traversal", "High"),
    (re.compile(r"(?i)(;\s*\w|&&\s*\w|\|\s*\w|`[^`]+`)", re.S),
     "Command Injection", "Critical"),
    (re.compile(r"(?i)(failed\s+(password|login)|authentication\s+fail|invalid\s+user)", re.S),
     "Brute-Force / Credential Stuffing", "Medium"),
    (re.compile(r"(?i)(sudo|su\s+root|privilege|escalat)", re.S),
     "Privilege Escalation", "High"),
    (re.compile(r"(?i)(syn\s+flood|dos|ddos|rate.limit.exceeded)", re.S),
     "Denial of Service (DoS)", "High"),
]

_LOG_TYPE_PATTERNS = [
    (re.compile(r"(?i)(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+/"), "HTTP Access Log"),
    (re.compile(r"(?i)sshd|pam_unix|authentication"), "Authentication Log"),
    (re.compile(r"(?i)(iptables|firewalld|ufw|nftables|DROP|REJECT)"), "Firewall Log"),
    (re.compile(r"(?i)(query|SELECT|INSERT|UPDATE|DELETE\s+FROM)", re.S), "Database Audit Log"),
    (re.compile(r"(?i)(dns|query\[|named\[)"), "DNS Query Log"),
    (re.compile(r"(?i)(error|exception|traceback|warning)", re.S), "Application Log"),
]

_SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _detect_log_type(log):
    for pattern, label in _LOG_TYPE_PATTERNS:
        if pattern.search(log):
            return label
    return "Unknown"


def _detect_attacks(log):
    hits = []
    seen = set()
    for pattern, attack_type, severity in _ATTACK_SIGNATURES:
        if attack_type not in seen and pattern.search(log):
            hits.append({"attack_type": attack_type, "severity": severity})
            seen.add(attack_type)
    return hits


def _max_severity(a, b):
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


def analyze_logs(logs: list[str]) -> dict:
    """Analyse one or more log entries for security threats.

    Args:
        logs: A list of raw log strings to analyse.

    Returns:
        A dict with per-log analysis results and overall risk.
    """
    results = []
    overall_risk = "Low"

    for idx, log in enumerate(logs):
        log = log.strip()
        if not log:
            continue

        log_type = _detect_log_type(log)
        attacks = _detect_attacks(log)
        is_suspicious = len(attacks) > 0
        attack_labels = [a["attack_type"] for a in attacks]
        severity = "Low"
        for a in attacks:
            severity = _max_severity(severity, a["severity"])
        overall_risk = _max_severity(overall_risk, severity)

        vulnerabilities = []
        joined = " ".join(attack_labels)
        if "SQL Injection" in joined:
            vulnerabilities.append("Unparameterised SQL queries or missing input validation")
        if "XSS" in joined:
            vulnerabilities.append("Missing output encoding / Content-Security-Policy")
        if "RCE" in joined:
            vulnerabilities.append("Unsafe command execution or file-include vulnerability")
        if "Directory Traversal" in joined:
            vulnerabilities.append("Path not canonicalised before file access")
        if "Command Injection" in joined:
            vulnerabilities.append("User input passed directly to shell")
        if "Brute-Force" in joined:
            vulnerabilities.append("No account-lockout or rate-limiting policy")
        if "Privilege" in joined:
            vulnerabilities.append("Insufficient privilege-boundary controls")
        if "DoS" in joined:
            vulnerabilities.append("No rate-limiting or traffic-shaping in place")

        results.append({
            "log_index": idx,
            "raw_log": log,
            "log_type": log_type,
            "explanation": "",
            "is_suspicious": is_suspicious,
            "attack_type": ", ".join(attack_labels) if attack_labels else "None detected",
            "vulnerabilities": vulnerabilities,
            "severity": severity,
            "remediation": "",
        })

    return {"analysis": results, "overall_risk": overall_risk}


def generate_summary(resource: str = "") -> str:
    """Produce an executive summary from prior analysis JSON.

    Args:
        resource: JSON string of analysis results (default empty string).

    Returns:
        A human-readable executive summary string.
    """
    if not resource:
        return "No analysis data was provided to summarise."

    try:
        data = json.loads(resource)
    except (json.JSONDecodeError, TypeError):
        return "Could not parse the supplied analysis JSON."

    entries = data.get("analysis", [])
    total = len(entries)
    suspicious_count = sum(1 for e in entries if e.get("is_suspicious"))
    severity_counts = {}
    for e in entries:
        sev = e.get("severity", "Low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    overall_risk = data.get("overall_risk", "Low")

    lines = [
        f"Analysed {total} log(s).",
        f"Suspicious entries: {suspicious_count}/{total}.",
        "Severity breakdown: " + ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items())),
        f"Overall risk level: {overall_risk}.",
    ]

    if suspicious_count == 0:
        lines.append("No threats detected - environment appears healthy.")
    elif overall_risk in ("High", "Critical"):
        lines.append("IMMEDIATE ACTION REQUIRED - high/critical threats detected.")
    else:
        lines.append("Some anomalies found. Review recommended.")

    return " ".join(lines)
