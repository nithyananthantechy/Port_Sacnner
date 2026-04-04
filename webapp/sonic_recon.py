"""
Sonic Recon AI — deterministic, rule-based threat scoring (no external ML/API).
"""
from __future__ import annotations

import datetime
import re
from typing import Any, Dict, List, Optional, Tuple

# ── Shared ────────────────────────────────────────────────────────────────────


def _cap(score: int) -> int:
    return min(max(int(score), 0), 100)


def risk_level_from_score(score: Optional[int]) -> str:
    if score is None:
        return "Info"
    if score <= 30:
        return "Low"
    if score <= 60:
        return "Medium"
    if score <= 85:
        return "High"
    return "Critical"


def _result(
    score: Optional[int],
    breakdown: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    remediation: List[Dict[str, Any]],
    *,
    informational: bool = False,
) -> Dict[str, Any]:
    rl = risk_level_from_score(0 if score is None and informational else score)
    if informational and score is None:
        rl = "Info"
    out: Dict[str, Any] = {
        "score": score,
        "risk_level": rl,
        "breakdown": breakdown,
        "findings": findings,
        "remediation": remediation,
        "informational": informational,
    }
    return out


# ── Tool 1: Port scan ─────────────────────────────────────────────────────────

_PORT_RISK: Dict[int, Tuple[str, str]] = {
    21: ("high", "FTP allows unencrypted file transfer"),
    22: ("medium", "SSH exposed, brute force risk"),
    23: ("high", "Telnet is unencrypted, replace with SSH"),
    25: ("high", "Mail server exposed publicly"),
    53: ("medium", "DNS exposed, potential amplification risk"),
    80: ("medium", "Unencrypted HTTP in use"),
    110: ("medium", "Legacy mail protocol exposed"),
    139: ("high", "NetBIOS exposed, SMB attack surface"),
    143: ("medium", "Mail retrieval port exposed"),
    443: ("low", "HTTPS present — good"),
    445: ("critical", "SMB exposed — EternalBlue/ransomware risk"),
    1433: ("critical", "Database port publicly exposed"),
    3306: ("critical", "MySQL exposed — critical risk"),
    3389: ("critical", "RDP exposed — ransomware entry point"),
    5432: ("critical", "PostgreSQL exposed publicly"),
    6379: ("critical", "Redis exposed — no auth by default"),
    8080: ("medium", "Alternative HTTP port exposed"),
    27017: ("critical", "MongoDB exposed — data breach risk"),
}


def _open_ports_count_score(n: int) -> Tuple[int, str]:
    if n <= 0:
        return 0, "No open ports detected"
    if n <= 3:
        return 15, "1–3 open ports"
    if n <= 9:
        return 30, "4–9 open ports"
    return 50, "10+ open ports"


def analyze_port_scan(open_ports: List[Any]) -> Dict[str, Any]:
    """open_ports: list of dicts with port, service, banner (optional) or int ports."""
    ports: List[int] = []
    meta: Dict[int, Dict[str, str]] = {}
    for item in open_ports or []:
        if isinstance(item, dict):
            p = int(item.get("port", 0))
            if p:
                ports.append(p)
                meta[p] = {
                    "service": str(item.get("service") or "unknown"),
                    "banner": str(item.get("banner") or ""),
                }
        elif isinstance(item, int):
            ports.append(item)
    ports_sorted = sorted(set(ports))
    n = len(ports_sorted)
    total = 0
    breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    remediation: List[Dict[str, Any]] = []

    pts, blabel = _open_ports_count_score(n)
    if pts:
        total += pts
        breakdown.append({"factor": "Open port exposure", "impact": pts, "detail": blabel})

    high_impact = 0
    for p in ports_sorted:
        if p in _PORT_RISK:
            sev, msg = _PORT_RISK[p]
            if p == 443:
                findings.append({"severity": "low", "text": f"Port {p} (HTTPS): {msg}", "impact": 0})
                breakdown.append({"factor": f"Port {p} HTTPS", "impact": 0, "detail": msg})
                continue
            add = 10
            total += add
            high_impact += add
            sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
            findings.append(
                {
                    "severity": sev_map.get(sev, "medium"),
                    "text": f"Port {p}: {msg}",
                    "impact": add,
                }
            )
            breakdown.append({"factor": f"High-risk service port {p}", "impact": add, "detail": msg})
        else:
            findings.append(
                {
                    "severity": "info",
                    "text": f"Port {p} open — review service exposure and firewall rules",
                    "impact": 0,
                }
            )

    total = _cap(total)

    if n == 0:
        findings.insert(0, {"severity": "low", "text": "No open ports found in scanned range.", "impact": 0})
        remediation.append(
            {
                "step": 1,
                "action": "Maintain default-deny ingress; scan regularly after network changes.",
                "code": "",
            }
        )
    else:
        remediation.append(
            {
                "step": 1,
                "action": "Close unused services; restrict management ports (SSH, RDP) to VPN or allow-lists.",
                "code": "# iptables / cloud SG: allow 22/3389 only from trusted CIDRs",
            }
        )
        if any(p in (445, 3389, 3306, 1433, 27017, 6379) for p in ports_sorted):
            remediation.append(
                {
                    "step": 2,
                    "action": "Never expose databases or SMB/RDP directly to the internet; place behind VPN or bastion.",
                    "code": "",
                }
            )

    return _result(total, breakdown, findings, remediation)


# ── Tool 2: SSL ───────────────────────────────────────────────────────────────


def analyze_ssl(ssl_data: Dict[str, Any]) -> Dict[str, Any]:
    breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    remediation: List[Dict[str, Any]] = []
    total = 0

    if ssl_data.get("error") or not ssl_data.get("valid", True):
        err = ssl_data.get("error") or "Certificate could not be validated"
        total = _cap(total + 70)
        breakdown.append({"factor": "Certificate / handshake failure", "impact": 70, "detail": err})
        findings.append({"severity": "critical", "text": err, "impact": 70})
        remediation.append(
            {
                "step": 1,
                "action": "Install a valid certificate from a public CA; fix hostname and chain issues.",
                "code": "",
            }
        )
        return _result(_cap(total), breakdown, findings, remediation)

    days_left = int(ssl_data.get("days_left") or 0)
    if days_left < 0:
        total += 60
        breakdown.append({"factor": "Certificate expired", "impact": 60, "detail": "Renew immediately"})
        findings.append({"severity": "critical", "text": "Certificate is expired", "impact": 60})
    elif days_left < 7:
        total += 50
        breakdown.append({"factor": "Expiry < 7 days", "impact": 50, "detail": f"{days_left} days left"})
        findings.append({"severity": "critical", "text": f"Certificate expires in {days_left} days", "impact": 50})
    elif days_left < 30:
        total += 30
        breakdown.append({"factor": "Expiry < 30 days", "impact": 30, "detail": f"{days_left} days left"})
        findings.append({"severity": "high", "text": f"Certificate expires in {days_left} days", "impact": 30})
    elif days_left < 90:
        total += 15
        breakdown.append({"factor": "Expiry < 90 days", "impact": 15, "detail": f"{days_left} days left"})
        findings.append({"severity": "medium", "text": f"Renew within {days_left} days", "impact": 15})
    else:
        breakdown.append({"factor": "Certificate validity window", "impact": 0, "detail": f"{days_left} days remaining — OK"})
        findings.append({"severity": "low", "text": f"Certificate valid ({days_left} days)", "impact": 0})

    sig = (ssl_data.get("signature_algorithm") or "").upper()
    if "MD5" in sig:
        total += 40
        breakdown.append({"factor": "Signature MD5", "impact": 40, "detail": "MD5 is broken"})
        findings.append({"severity": "critical", "text": "MD5 is broken, replace immediately", "impact": 40})
    elif "SHA1" in sig or "SHA-1" in sig:
        total += 25
        breakdown.append({"factor": "Signature SHA1", "impact": 25, "detail": "SHA1 deprecated"})
        findings.append({"severity": "high", "text": "SHA1 is deprecated, upgrade to SHA256", "impact": 25})
    elif sig:
        breakdown.append({"factor": "Signature algorithm", "impact": 0, "detail": sig})
        findings.append({"severity": "low", "text": f"Signature: {sig} — acceptable if SHA256+", "impact": 0})

    if ssl_data.get("self_signed"):
        total += 35
        breakdown.append({"factor": "Self-signed certificate", "impact": 35, "detail": "No public CA trust"})
        findings.append(
            {
                "severity": "high",
                "text": "Self-signed cert causes browser warnings and no CA verification",
                "impact": 35,
            }
        )

    if ssl_data.get("chain_incomplete"):
        total += 20
        breakdown.append({"factor": "Incomplete chain", "impact": 20, "detail": "Intermediate missing"})
        findings.append({"severity": "medium", "text": "Intermediate certificate missing from chain", "impact": 20})

    if ssl_data.get("subject_mismatch"):
        total += 45
        breakdown.append({"factor": "Hostname mismatch", "impact": 45, "detail": "CN/SAN does not match host"})
        findings.append({"severity": "critical", "text": "Certificate does not match the domain", "impact": 45})

    proto = (ssl_data.get("protocol") or "").upper().replace(" ", "")
    tls_add = 0
    tls_msg = ""
    if "SSLV2" in proto or proto == "SSLV2":
        tls_add, tls_msg = 50, "SSLv2 is broken, disable immediately"
    elif "SSLV3" in proto or proto == "SSLV3":
        tls_add, tls_msg = 45, "SSLv3 vulnerable to POODLE"
    elif "TLSV1" == proto or proto.startswith("TLSV1.0"):
        tls_add, tls_msg = 25, "TLS 1.0 deprecated"
    elif "TLSV1.1" in proto or proto.startswith("TLSV1.1"):
        tls_add, tls_msg = 15, "TLS 1.1 deprecated"
    elif "TLSV1.2" in proto or "TLS1.2" in proto:
        tls_add, tls_msg = 5, "TLS 1.2 acceptable; 1.3 preferred"
    elif "TLSV1.3" in proto or "TLS1.3" in proto:
        tls_add, tls_msg = 0, "TLS 1.3 — excellent"
    if proto:
        total += tls_add
        breakdown.append({"factor": f"TLS version ({ssl_data.get('protocol')})", "impact": tls_add, "detail": tls_msg or proto})
        findings.append(
            {
                "severity": "critical" if tls_add >= 45 else "high" if tls_add >= 25 else "medium" if tls_add else "low",
                "text": tls_msg or f"Protocol {ssl_data.get('protocol')}",
                "impact": tls_add,
            }
        )

    total = _cap(total)
    if total == 0 or (total <= 15 and days_left >= 90 and not ssl_data.get("subject_mismatch")):
        findings.insert(0, {"severity": "low", "text": "SSL Healthy — no major issues detected", "impact": 0})

    step_n = 1
    if days_left < 30:
        remediation.append({"step": step_n, "action": "Renew certificate before expiry; automate ACME where possible.", "code": ""})
        step_n += 1
    if ssl_data.get("self_signed"):
        remediation.append(
            {
                "step": step_n,
                "action": "Replace with a publicly trusted certificate (Let's Encrypt, commercial CA).",
                "code": "certbot certonly --nginx -d example.com",
            }
        )
        step_n += 1
    if tls_add and tls_add >= 15:
        remediation.append(
            {
                "step": step_n,
                "action": "Disable legacy SSL/TLS; enable TLS 1.2+ and prefer TLS 1.3.",
                "code": "ssl_protocols TLSv1.2 TLSv1.3;",
            }
        )

    return _result(total, breakdown, findings, remediation)


# ── Tool 3: DNS ───────────────────────────────────────────────────────────────

_DMARC_HINT = re.compile(r"v\s*=\s*DMARC1", re.I)
_SPF_HINT = re.compile(r"v\s*=\s*spf1", re.I)
_DKIM_HINT = re.compile(r"v\s*=\s*DKIM1", re.I)


def analyze_dns(dns_data: Dict[str, Any]) -> Dict[str, Any]:
    records = dns_data.get("records") or {}
    domain = (dns_data.get("domain") or "").strip() or "domain"
    txt_flat = " ".join(records.get("TXT") or [])
    mx_list = records.get("MX") or []
    a_list = records.get("A") or []
    aaaa = records.get("AAAA") or []
    dmarc_txts = dns_data.get("dmarc_txt") or []

    total = 0
    breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    remediation: List[Dict[str, Any]] = []

    has_spf = bool(_SPF_HINT.search(txt_flat))
    if not has_spf:
        total += 25
        breakdown.append({"factor": "No SPF", "impact": 25, "detail": "Email spoofing risk"})
        findings.append({"severity": "high", "text": "Missing SPF record allows email spoofing", "impact": 25})
        remediation.append(
            {
                "step": len(remediation) + 1,
                "action": "Publish SPF for your outbound mail source.",
                "code": f"v=spf1 include:yourmailserver.com ~all",
            }
        )
    else:
        if "+all" in txt_flat or re.search(r"\+all", txt_flat):
            total += 20
            breakdown.append({"factor": "SPF too permissive", "impact": 20, "detail": "+all allows any sender"})
            findings.append({"severity": "high", "text": "SPF set to +all allows anyone to send as your domain", "impact": 20})
        breakdown.append({"factor": "SPF present", "impact": 0, "detail": "Found v=spf1"})
        findings.append({"severity": "low", "text": "SPF record present", "impact": 0})

    has_dmarc = bool(dmarc_txts) or any(_DMARC_HINT.search(t) for t in (records.get("TXT") or []))
    if not has_dmarc:
        total += 25
        breakdown.append({"factor": "No DMARC", "impact": 25, "detail": "Phishing using domain easier"})
        findings.append({"severity": "high", "text": "Missing DMARC enables phishing attacks using your domain", "impact": 25})
        remediation.append(
            {
                "step": len(remediation) + 1,
                "action": "Add DMARC at _dmarc host.",
                "code": f"_dmarc.{domain} TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}\"",
            }
        )
    else:
        breakdown.append({"factor": "DMARC present", "impact": 0, "detail": "Policy published"})
        findings.append({"severity": "low", "text": "DMARC record found", "impact": 0})

    dkim_found = dns_data.get("dkim_found", False)
    if not dkim_found:
        total += 20
        breakdown.append({"factor": "No DKIM detected", "impact": 20, "detail": "Common selectors not found"})
        findings.append({"severity": "medium", "text": "DKIM missing or not found via common selectors — emails may be unverified", "impact": 20})
        remediation.append(
            {
                "step": len(remediation) + 1,
                "action": "Ask your mail provider for DKIM selector; publish TXT at selector._domainkey",
                "code": "default._domainkey TXT \"v=DKIM1; k=rsa; p=MIIB...\"",
            }
        )
    else:
        breakdown.append({"factor": "DKIM", "impact": 0, "detail": "Selector found"})
        findings.append({"severity": "low", "text": "DKIM record detected", "impact": 0})

    if not mx_list:
        total += 10
        breakdown.append({"factor": "No MX records", "impact": 10, "detail": "No inbound mail configured"})
        findings.append({"severity": "info", "text": "No MX records found for this domain", "impact": 10})

    if not aaaa:
        total += 5
        breakdown.append({"factor": "No AAAA", "impact": 5, "detail": "IPv6 not configured"})
        findings.append({"severity": "info", "text": "No AAAA (IPv6) record", "impact": 5})

    if len(a_list) > 1:
        total += 10
        breakdown.append({"factor": "Multiple A records", "impact": 10, "detail": "Possible misconfiguration"})
        findings.append({"severity": "medium", "text": "Multiple A records may indicate misconfiguration or hijack", "impact": 10})

    if dns_data.get("zone_transfer_exposed"):
        total += 40
        breakdown.append({"factor": "Zone transfer (AXFR)", "impact": 40, "detail": "Zone exposed"})
        findings.append(
            {"severity": "critical", "text": "DNS zone transfer exposed — full DNS map may be downloadable", "impact": 40}
        )
        remediation.append(
            {
                "step": len(remediation) + 1,
                "action": "Restrict AXFR to secondary nameservers only; disable public zone transfers.",
                "code": "",
            }
        )

    email_score = 100
    if not has_spf:
        email_score -= 35
    if not has_dmarc:
        email_score -= 35
    if not dkim_found:
        email_score -= 30
    email_score = max(0, email_score)
    findings.insert(
        0,
        {
            "severity": "medium" if email_score < 70 else "low",
            "text": f"Email security composite rating (SPF+DMARC+DKIM): {email_score}/100",
            "impact": 0,
        },
    )

    total = _cap(total)
    return _result(total, breakdown, findings, remediation)


# ── Tool 4: WHOIS ─────────────────────────────────────────────────────────────

_HIGH_RISK_REGISTRARS = (
    "namecheap",
    "namesilo",
    "godaddy",
    "pdr",
    "alibaba",
    "chengdu west",
    "nicenic",
    "xin net",
)

_HIGH_RISK_CC = ("CN", "RU", "KP", "IR")  # illustrative TI-style grouping


def _parse_whois_date(val: Any) -> Optional[datetime.datetime]:
    if val is None:
        return None
    if isinstance(val, datetime.datetime):
        return val
    if isinstance(val, list) and val:
        return _parse_whois_date(val[0])
    s = str(val).strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y"):
        try:
            return datetime.datetime.strptime(s[:19], fmt)
        except ValueError:
            continue
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")[:19])
    except ValueError:
        return None


def analyze_whois(whois_data: Dict[str, Any]) -> Dict[str, Any]:
    total = 0
    breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    remediation: List[Dict[str, Any]] = []

    now = datetime.datetime.utcnow()
    exp = _parse_whois_date(whois_data.get("expiration_date"))
    cre = _parse_whois_date(whois_data.get("creation_date"))

    if exp:
        days = (exp - now).days
        if days < 0:
            total += 55
            breakdown.append({"factor": "Domain expired", "impact": 55, "detail": "Renew or lose domain"})
            findings.append({"severity": "critical", "text": "Domain appears expired — renew immediately", "impact": 55})
        elif days < 30:
            total += 50
            breakdown.append({"factor": "Expires < 30d", "impact": 50, "detail": f"{days} days"})
            findings.append({"severity": "critical", "text": "Domain expiring soon — risk of losing your domain", "impact": 50})
        elif days < 90:
            total += 25
            breakdown.append({"factor": "Expires < 90d", "impact": 25, "detail": f"{days} days"})
            findings.append({"severity": "high", "text": "Domain renewal needed within 90 days", "impact": 25})
        elif days < 180:
            total += 10
            breakdown.append({"factor": "Expires < 180d", "impact": 10, "detail": f"{days} days"})
            findings.append({"severity": "medium", "text": "Renew domain within 6 months", "impact": 10})
        else:
            findings.append({"severity": "low", "text": f"Domain expiry in {days} days — healthy window", "impact": 0})

    if cre:
        age_days = (now - cre).days
        if age_days < 30:
            total += 30
            breakdown.append({"factor": "Very new domain", "impact": 30, "detail": f"{age_days} days old"})
            findings.append(
                {"severity": "high", "text": "Very new domain — commonly associated with phishing campaigns", "impact": 30}
            )
        else:
            findings.append({"severity": "low", "text": f"Domain age ~{age_days // 30} months", "impact": 0})

    reg = str(whois_data.get("registrar") or "").lower()
    if reg and any(x in reg for x in _HIGH_RISK_REGISTRARS):
        total += 20
        breakdown.append({"factor": "Registrar reputation", "impact": 20, "detail": reg})
        findings.append({"severity": "medium", "text": "Registrar often seen on bulk/abuse registrations — verify legitimacy", "impact": 20})

    if whois_data.get("privacy_disabled"):
        total += 15
        breakdown.append({"factor": "WHOIS privacy off", "impact": 15, "detail": "Contact data exposed"})
        findings.append(
            {
                "severity": "medium",
                "text": "Registrant details publicly exposed — phishing and social engineering risk",
                "impact": 15,
            }
        )
        remediation.append(
            {
                "step": 1,
                "action": "Enable WHOIS privacy / redaction at your registrar if appropriate for your org policy.",
                "code": "",
            }
        )

    if whois_data.get("recent_transfer"):
        total += 15
        breakdown.append({"factor": "Recent transfer", "impact": 15, "detail": "Ownership change"})
        findings.append({"severity": "medium", "text": "Recent domain transfer detected", "impact": 15})

    cc = (whois_data.get("country") or "").upper()[:2]
    if len(cc) == 2 and cc in _HIGH_RISK_CC:
        total += 10
        breakdown.append({"factor": "Registrant country", "impact": 10, "detail": cc})
        findings.append({"severity": "info", "text": f"Registrant country {cc} — review in business context", "impact": 10})

    total = _cap(total)
    return _result(total, breakdown, findings, remediation)


# ── Tool 5: Ping ──────────────────────────────────────────────────────────────


def analyze_ping(ping_data: Dict[str, Any]) -> Dict[str, Any]:
    total = 0
    breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    remediation: List[Dict[str, Any]] = []

    reachable = bool(ping_data.get("reachable"))
    loss = float(ping_data.get("packet_loss_pct") if ping_data.get("packet_loss_pct") is not None else -1.0)
    avg_ms = ping_data.get("avg_latency_ms")
    if avg_ms is not None:
        avg_ms = float(avg_ms)

    if not reachable or loss >= 99.9:
        total += 20
        breakdown.append({"factor": "Host unreachable / loss", "impact": 20, "detail": "No ICMP replies or 100% loss"})
        findings.append(
            {
                "severity": "medium",
                "text": "Host is offline or blocking ICMP — may indicate firewall or outage",
                "impact": 20,
            }
        )
    elif loss >= 0:
        if loss > 50:
            total += 25
            breakdown.append({"factor": "Packet loss >50%", "impact": 25, "detail": f"{loss:.0f}%"})
            findings.append({"severity": "high", "text": "High packet loss detected — network instability or rate limiting", "impact": 25})
        elif loss >= 10:
            total += 15
            breakdown.append({"factor": "Packet loss 10–50%", "impact": 15, "detail": f"{loss:.0f}%"})
            findings.append({"severity": "medium", "text": "Moderate packet loss — investigate network path", "impact": 15})
        else:
            breakdown.append({"factor": "Packet loss", "impact": 0, "detail": f"{loss:.0f}% — acceptable"})
            findings.append({"severity": "low", "text": f"Packet loss under 10% ({loss:.0f}%)", "impact": 0})

    if reachable and avg_ms is not None:
        if avg_ms > 300:
            total += 25
            breakdown.append({"factor": "Latency >300ms", "impact": 25, "detail": f"{avg_ms:.0f} ms"})
            findings.append(
                {"severity": "high", "text": "Very high latency — serious performance concern", "impact": 25}
            )
        elif avg_ms > 100:
            total += 15
            breakdown.append({"factor": "Latency 100–300ms", "impact": 15, "detail": f"{avg_ms:.0f} ms"})
            findings.append({"severity": "medium", "text": "High latency — performance impact", "impact": 15})
        elif avg_ms > 20:
            total += 5
            breakdown.append({"factor": "Latency 20–100ms", "impact": 5, "detail": f"{avg_ms:.0f} ms"})
            findings.append({"severity": "low", "text": "Good response time", "impact": 5})
        else:
            breakdown.append({"factor": "Latency <20ms", "impact": 0, "detail": f"{avg_ms:.0f} ms"})
            findings.append({"severity": "low", "text": "Excellent response time", "impact": 0})

    if reachable:
        findings.append({"severity": "low", "text": "Host is reachable via ICMP", "impact": 0})
    else:
        findings.append({"severity": "info", "text": "ICMP not successful — host may be firewalled or down (covered in unreachable score)", "impact": 0})

    total = _cap(total)
    remediation.append(
        {
            "step": 1,
            "action": "If loss/latency is high, trace route, check Wi‑Fi, VPN, and provider SLA; compare from another network.",
            "code": "mtr -rwzc 100 target.host",
        }
    )
    return _result(total, breakdown, findings, remediation)


# ── Tool 6: HTTP headers ─────────────────────────────────────────────────────

_HEADER_CHECKS = [
    ("content-security-policy", 20, "CSP missing — XSS attacks possible"),
    ("strict-transport-security", 20, "HSTS missing — allows HTTP downgrade attacks"),
    ("x-frame-options", 15, "Clickjacking protection missing"),
    ("x-content-type-options", 10, "MIME sniffing attacks possible"),
    ("referrer-policy", 10, "Referrer data leaking to third parties"),
    ("permissions-policy", 10, "Browser feature access uncontrolled"),
    ("x-xss-protection", 10, "Legacy XSS filter not configured"),
]


def analyze_headers(headers_data: Dict[str, Any]) -> Dict[str, Any]:
    headers = {k.lower(): v for k, v in (headers_data.get("headers") or {}).items()}
    total = 0
    breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    remediation: List[Dict[str, Any]] = []

    if headers_data.get("error"):
        return _result(
            40,
            [{"factor": "Fetch failed", "impact": 40, "detail": headers_data["error"]}],
            [{"severity": "high", "text": headers_data["error"], "impact": 40}],
            [{"step": 1, "action": "Verify URL is reachable over HTTPS and try again.", "code": ""}],
        )

    sec_score = 100
    for name, impact, msg in _HEADER_CHECKS:
        if name not in headers:
            total += impact
            sec_score -= impact
            breakdown.append({"factor": f"Missing {name}", "impact": impact, "detail": msg})
            findings.append({"severity": "high" if impact >= 15 else "medium", "text": msg, "impact": impact})

    server = headers.get("server", "")
    if server and re.search(r"\d", server):
        total += 15
        breakdown.append({"factor": "Server header version leak", "impact": 15, "detail": server})
        findings.append(
            {
                "severity": "medium",
                "text": "Server software version exposed — helps attackers target known CVEs",
                "impact": 15,
            }
        )
        remediation.append(
            {
                "step": len(remediation) + 1,
                "action": "Remove or genericize Server tokens.",
                "code": "server_tokens off;  # nginx\nServerSignature Off\nServerTokens Prod  # apache",
            }
        )

    if "x-powered-by" in headers:
        total += 10
        breakdown.append({"factor": "X-Powered-By", "impact": 10, "detail": headers["x-powered-by"]})
        findings.append({"severity": "medium", "text": "Technology stack fingerprinting possible", "impact": 10})

    findings.insert(
        0,
        {
            "severity": "low" if sec_score >= 70 else "high",
            "text": f"Security headers score: {max(0, sec_score)}/100",
            "impact": 0,
        },
    )

    for name, impact, msg in _HEADER_CHECKS:
        if name not in headers:
            hname = "-".join(p.title() for p in name.split("-"))
            remediation.append(
                {
                    "step": len(remediation) + 1,
                    "action": f"Add {hname}",
                    "code": f"# nginx\nadd_header {hname} \"...always;\"\n\n# Apache\nHeader always set {hname} \"...\"",
                }
            )

    total = _cap(total)
    return _result(total, breakdown, findings, remediation)


# ── Tool 7: Subdomains ────────────────────────────────────────────────────────

_SENSITIVE_SUBS = frozenset(
    {
        "admin",
        "administrator",
        "cpanel",
        "webmail",
        "mail",
        "vpn",
        "remote",
        "dev",
        "staging",
        "test",
        "beta",
        "api",
        "dashboard",
        "portal",
        "ftp",
        "backup",
        "old",
        "legacy",
        "internal",
        "intranet",
        "jenkins",
        "gitlab",
        "jira",
    }
)


def analyze_subdomains(subdomains: List[Dict[str, Any]]) -> Dict[str, Any]:
    """subdomains: [{name, dead: bool}, ...]"""
    total = 0
    breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    remediation: List[Dict[str, Any]] = []

    n = len(subdomains or [])
    if n <= 0:
        bucket = (0, "No subdomains discovered in scan")
    elif n <= 5:
        bucket = (10, "1–5 subdomains")
    elif n <= 15:
        bucket = (20, "6–15 subdomains")
    else:
        bucket = (35, "16+ subdomains — large attack surface")

    if bucket[0]:
        total += bucket[0]
        breakdown.append({"factor": "Subdomain count", "impact": bucket[0], "detail": bucket[1]})

    sensitive = []
    dead_count = 0
    for item in subdomains or []:
        name = (item.get("name") or "").lower().split(".")[0]
        if name in _SENSITIVE_SUBS:
            sensitive.append(item.get("name"))
        if item.get("dead"):
            dead_count += 1

    if sensitive:
        add = 15 * len(set(sensitive))
        total += add
        breakdown.append({"factor": "Sensitive hostnames", "impact": add, "detail": ", ".join(sorted(set(sensitive))[:10])})
        for s in sorted(set(sensitive)):
            findings.append({"severity": "critical", "text": f"Sensitive subdomain: {s}", "impact": 15})

    if dead_count:
        add_d = 5 * dead_count
        total += add_d
        breakdown.append({"factor": "Dead / no-HTTP subdomains", "impact": add_d, "detail": f"{dead_count} hosts"})
        findings.append(
            {
                "severity": "high",
                "text": f"{dead_count} subdomain(s) resolve but did not respond to HTTP — takeover risk on abandoned names",
                "impact": add_d,
            }
        )

    if not findings:
        findings.append({"severity": "low", "text": "No high-risk patterns in discovered subdomains", "impact": 0})

    findings.insert(0, {"severity": "medium", "text": f"Attack surface: {n} subdomain(s) discovered", "impact": 0})

    total = _cap(total)
    remediation.append(
        {
            "step": 1,
            "action": "Remove unused DNS names; monitor certificate transparency; protect admin/dev hosts with VPN and SSO.",
            "code": "",
        }
    )
    return _result(total, breakdown, findings, remediation)


# ── Tool 8: Geolocation (informational) ───────────────────────────────────────

_VPN_ISP_KEYWORDS = ("vpn", "nordvpn", "expressvpn", "surfshark", "proton", "mullvad", "private internet access", "cyberghost")
_CLOUD_ISP_KEYWORDS = (
    "amazon",
    "aws",
    "google cloud",
    "gcp",
    "microsoft corporation",
    "azure",
    "digitalocean",
    "vultr",
    "linode",
    "akamai",
    "oracle cloud",
    "hetzner",
)
_TOR_HINT = ("tor", "tor exit")

_HIGH_RISK_COUNTRIES = ("RU", "CN", "KP", "IR", "BY")  # illustrative


def analyze_geolocation(geo_data: Dict[str, Any]) -> Dict[str, Any]:
    breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    remediation: List[Dict[str, Any]] = []

    isp = (geo_data.get("isp") or geo_data.get("org") or "").lower()
    country = (geo_data.get("country_code") or "").upper()
    city = geo_data.get("city") or ""
    client_cc = (geo_data.get("client_country_code") or "").upper()

    if any(k in isp for k in _VPN_ISP_KEYWORDS):
        findings.append(
            {"severity": "medium", "text": "This IP routes through a VPN or proxy service (ISP heuristic)", "impact": 0}
        )
        breakdown.append({"factor": "Hosting / ISP", "impact": 0, "detail": "VPN/proxy-like ISP name"})
    elif any(k in isp for k in _CLOUD_ISP_KEYWORDS):
        findings.append(
            {"severity": "info", "text": "Cloud-hosted IP — may be ephemeral infrastructure", "impact": 0}
        )
        breakdown.append({"factor": "Hosting / ISP", "impact": 0, "detail": "Known cloud provider pattern"})
    elif any(k in isp for k in _TOR_HINT):
        findings.append({"severity": "high", "text": "Potential Tor-related network path (name heuristic)", "impact": 0})
        breakdown.append({"factor": "Hosting / ISP", "impact": 0, "detail": "Tor keyword in ISP/org"})
    else:
        findings.append({"severity": "info", "text": f"ISP / org: {geo_data.get('isp') or geo_data.get('org') or 'Unknown'}", "impact": 0})

    if country:
        if country in _HIGH_RISK_COUNTRIES:
            findings.append(
                {
                    "severity": "medium",
                    "text": f"Country {country} is often flagged in generic threat intel categories — validate contextually",
                    "impact": 0,
                }
            )
        else:
            findings.append({"severity": "low", "text": f"Geolocated country: {country} ({city or 'unknown city'})", "impact": 0})

    if client_cc and country and client_cc != country:
        # crude anomaly: different country from scanner
        findings.append(
            {
                "severity": "medium",
                "text": "Geographic anomaly — IP location differs from scanner egress country",
                "impact": 0,
            }
        )
        breakdown.append({"factor": "Geo mismatch", "impact": 0, "detail": f"Scanner {client_cc} vs target {country}"})

    remediation.append(
        {
            "step": 1,
            "action": "Use this data as context only; combine with auth logs and threat feeds for decisions.",
            "code": "",
        }
    )

    return _result(None, breakdown, findings, remediation, informational=True)


# ── Tool 9: CVE ───────────────────────────────────────────────────────────────


def analyze_cve(cve_data: Dict[str, Any]) -> Dict[str, Any]:
    crit = int(cve_data.get("critical_count") or 0)
    high = int(cve_data.get("high_count") or 0)
    max_cvss = float(cve_data.get("max_cvss") or 0.0)

    total = 0
    breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    remediation: List[Dict[str, Any]] = []

    if crit <= 0:
        cpts = 0
    elif crit <= 2:
        cpts = 40
    else:
        cpts = 70
    if cpts:
        total += cpts
        breakdown.append({"factor": "Critical CVE count", "impact": cpts, "detail": f"{crit} critical"})
        findings.append({"severity": "critical", "text": f"{crit} critical CVE(s) in results", "impact": cpts})

    if high <= 0:
        hpts = 0
    elif high <= 3:
        hpts = 20
    else:
        hpts = 35
    if hpts:
        total += hpts
        breakdown.append({"factor": "High CVE count", "impact": hpts, "detail": f"{high} high"})
        findings.append({"severity": "high", "text": f"{high} high-severity CVE(s)", "impact": hpts})

    cvss_pts = 0
    if max_cvss >= 9.0:
        cvss_pts = 30
        msg = "Maximum severity vulnerability exists"
    elif max_cvss >= 7.0:
        cvss_pts = 20
        msg = "High severity vulnerability found"
    elif max_cvss >= 4.0:
        cvss_pts = 10
        msg = "Medium severity vulnerability found"
    elif max_cvss > 0:
        cvss_pts = 5
        msg = "Low severity vulnerability found"
    else:
        msg = ""

    if cvss_pts:
        total += cvss_pts
        breakdown.append({"factor": "Peak CVSS", "impact": cvss_pts, "detail": f"{max_cvss:.1f}"})
        findings.append({"severity": "critical" if cvss_pts >= 30 else "high", "text": msg, "impact": cvss_pts})

    total = _cap(total)

    if crit == 0 and high == 0 and max_cvss == 0:
        findings.insert(0, {"severity": "low", "text": "No CVEs matched this query in NVD results", "impact": 0})

    urgency = "Low"
    if crit >= 1 or max_cvss >= 9:
        urgency = "Immediate"
    elif high >= 4 or max_cvss >= 7:
        urgency = "High"
    elif high >= 1 or max_cvss >= 4:
        urgency = "Medium"

    findings.insert(0, {"severity": "high", "text": f"Patch urgency: {urgency}", "impact": 0})

    remediation.append(
        {
            "step": 1,
            "action": "Apply vendor patches immediately for all Critical and High severity CVEs; test in staging first.",
            "code": "",
        }
    )
    return _result(total, breakdown, findings, remediation)
