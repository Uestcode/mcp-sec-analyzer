"""Network surface, HTTP security headers, TLS posture, and DNS/Email hygiene analysis."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
import re
import socket
import ssl
from typing import Any
import urllib.parse
import urllib.request

SECURITY_HEADERS = {
    "strict-transport-security": "Enforces HTTPS connections (HSTS)",
    "content-security-policy": "Restricts sources of executable scripts and resources (CSP)",
    "x-frame-options": "Protects against clickjacking attacks",
    "x-content-type-options": "Prevents MIME-type sniffing (nosniff)",
    "referrer-policy": "Controls referrer information leakage",
    "permissions-policy": "Restricts browser feature APIs (camera, geolocation, etc.)",
}

INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]


def inspect_http_headers(
    target_url: str,
    use_tor: bool = False,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Inspect HTTP security headers and identify missing browser protections or info leaks.
    Supports Stealth Mode via Tor / Onion SOCKS5 proxy to conceal investigator IP address.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    from mcp_sec_analyzer.core.stealth import get_active_proxy
    active_proxy = get_active_proxy(force_tor=use_tor, custom_proxy=proxy)

    try:
        if active_proxy:
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            proxies = {"http": active_proxy, "https": active_proxy}
            resp = requests.get(
                target_url,
                proxies=proxies,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) mcp-sec-recon/1.0"},
                timeout=12.0,
                verify=False,
            )
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status_code = resp.status_code
        else:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) mcp-sec-recon/1.0"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                status_code = resp.status
    except Exception as e:
        return {"error": f"Failed to connect to {target_url}: {e}"}

    present_security_headers = {}
    missing_security_headers = []

    for h, desc in SECURITY_HEADERS.items():
        if h in headers:
            present_security_headers[h] = {"value": headers[h], "purpose": desc}
        else:
            missing_security_headers.append({"header": h, "purpose": desc})

    info_disclosures = {h: headers[h] for h in INFO_LEAK_HEADERS if h in headers}

    score = round((len(present_security_headers) / len(SECURITY_HEADERS)) * 100)

    return {
        "url": target_url,
        "status_code": status_code,
        "security_score_percentage": score,
        "stealth_mode": bool(active_proxy),
        "proxy_gateway": active_proxy,
        "present_security_headers": present_security_headers,
        "missing_security_headers": missing_security_headers,
        "information_disclosure_headers": info_disclosures,
        "recommendation": (
            "Well hardened"
            if score >= 80
            else "Moderate posture" if score >= 50 else "High exposure: multiple basic defenses missing"
        ),
    }


def inspect_tls_certificate(hostname: str, port: int = 443) -> dict[str, Any]:
    """Inspect SSL/TLS certificate validity, issuer, SANs, and protocol versions."""
    clean_host = hostname.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((clean_host, port), timeout=6.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol_version = ssock.version()
    except Exception as e:
        return {"error": f"TLS handshake failed for {clean_host}:{port}: {e}"}

    if not cert:
        return {"error": "No peer certificate returned"}

    # Parse expiration
    not_after_str = cert.get("notAfter", "")
    not_before_str = cert.get("notBefore", "")
    days_remaining = None
    try:
        # Format: 'May  5 23:59:59 2026 GMT'
        expires_dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tz=datetime.timezone.utc)
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        days_remaining = (expires_dt - now_dt).days
    except Exception:
        pass

    # Extract SANs
    sans = [val for key, val in cert.get("subjectAltName", []) if key == "DNS"]

    # Subject & Issuer
    subject_dict = {item[0][0]: item[0][1] for item in cert.get("subject", []) if item and len(item[0]) >= 2}
    issuer_dict = {item[0][0]: item[0][1] for item in cert.get("issuer", []) if item and len(item[0]) >= 2}

    return {
        "hostname": clean_host,
        "port": port,
        "tls_version": protocol_version,
        "cipher_suite": cipher[0] if cipher else "Unknown",
        "cipher_bits": cipher[2] if cipher else None,
        "valid_from": not_before_str,
        "expires_on": not_after_str,
        "days_until_expiration": days_remaining,
        "expiration_warning": days_remaining is not None and days_remaining < 30,
        "subject": subject_dict.get("commonName", clean_host),
        "issuer": issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown")),
        "subject_alternative_names_count": len(sans),
        "sample_sans": sans[:15],
    }


def _query_doh(name: str, record_type: str = "TXT") -> list[str]:
    """Helper to query DNS records via DNS over HTTPS."""
    url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type={record_type}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "mcp-doh/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            data = json.loads(resp.read().decode())
            answers = data.get("Answer", [])
            results = []
            for a in answers:
                data_val = a.get("data", "").strip('"')
                if data_val:
                    results.append(data_val)
            return results
    except Exception:
        return []


def lookup_dns_records(domain: str) -> dict[str, Any]:
    """Lookup DNS records, mail servers, and inspect SPF/DMARC email security posture."""
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    # Resolve IP addresses via socket
    ipv4_addresses = []
    ipv6_addresses = []
    try:
        addr_info = socket.getaddrinfo(clean_domain, None)
        for item in addr_info:
            ip = item[4][0]
            if ":" in ip and ip not in ipv6_addresses:
                ipv6_addresses.append(ip)
            elif "." in ip and ip not in ipv4_addresses:
                ipv4_addresses.append(ip)
    except Exception:
        pass

    # Query MX and TXT records via DoH
    mx_records = _query_doh(clean_domain, "MX")
    txt_records = _query_doh(clean_domain, "TXT")
    dmarc_records = _query_doh(f"_dmarc.{clean_domain}", "TXT")

    # Analyze SPF
    spf_record = next((r for r in txt_records if r.startswith("v=spf1")), None)
    spf_policy = "Missing (Spoofing risk)"
    if spf_record:
        if "-all" in spf_record:
            spf_policy = "Hardfail (-all) - Strict Protection"
        elif "~all" in spf_record:
            spf_policy = "Softfail (~all) - Moderate Protection"
        elif "?all" in spf_record or "+all" in spf_record:
            spf_policy = "Permissive (?all/+all) - Ineffective"

    # Analyze DMARC
    dmarc_record = next((r for r in dmarc_records if r.startswith("v=DMARC1")), None)
    dmarc_policy = "Missing (Spoofing risk)"
    if dmarc_record:
        p_match = re.search(r"p=([a-zA-Z]+)", dmarc_record)
        if p_match:
            dmarc_policy = f"Policy: {p_match.group(1).upper()}"

    return {
        "domain": clean_domain,
        "ipv4_addresses": ipv4_addresses,
        "ipv6_addresses": ipv6_addresses,
        "mail_exchangers_mx": mx_records,
        "email_security_posture": {
            "has_spf": spf_record is not None,
            "spf_record": spf_record,
            "spf_assessment": spf_policy,
            "has_dmarc": dmarc_record is not None,
            "dmarc_record": dmarc_record,
            "dmarc_assessment": dmarc_policy,
        },
        "txt_records_sample": txt_records[:10],
    }
