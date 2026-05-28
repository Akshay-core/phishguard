"""
Local URL investigation engine for PhishGuard.

This module intentionally uses the Python standard library plus httpx so the
core investigation flow stays free, local-first, and easy to run. Optional
heavy engines such as Playwright, YARA, Tesseract, and local LLMs can plug into
the same report shape later.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import ipaddress
import json
import re
import socket
import sqlite3
import ssl
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import httpx
from pydantic import BaseModel, Field


DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DB_PATH = DATA_DIR / "phishguard-intel.sqlite3"

BRANDS: dict[str, set[str]] = {
    "google": {"google.com", "gmail.com", "youtube.com"},
    "github": {"github.com", "github.io"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "office365.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "cloudflare": {"cloudflare.com"},
    "coinbase": {"coinbase.com"},
}

SUSPICIOUS_TLDS = {
    "xyz", "tk", "pw", "ml", "gq", "cf", "ga", "top", "work", "click",
    "loan", "download", "racing", "date", "win", "review", "science",
    "party", "stream", "gdn", "bid", "trade", "link",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
    "rebrand.ly", "buff.ly", "shorturl.at", "lnkd.in",
}

LOGIN_WORDS = {
    "login", "signin", "sign-in", "password", "credential", "verify",
    "account", "secure", "wallet", "seed phrase", "recovery phrase",
}

SCAM_PHRASES = {
    "account suspended", "verify your account", "wallet expired",
    "security alert", "unusual activity", "limited access", "press win+r",
    "allow notifications", "your computer is infected", "call support",
}

IOC_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IOC_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
IOC_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IOC_WALLET_RE = re.compile(r"\b(?:0x[a-fA-F0-9]{40}|bc1[a-zA-HJ-NP-Z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
FORM_RE = re.compile(r"<form\b", re.IGNORECASE)
PASSWORD_RE = re.compile(r"<input\b[^>]*type=[\"']?password", re.IGNORECASE)
IFRAME_RE = re.compile(r"<iframe\b([^>]*)>", re.IGNORECASE)
META_REFRESH_RE = re.compile(
    r"<meta\b[^>]*http-equiv=[\"']?refresh[\"']?[^>]*content=[\"']?([^\"'>]+)",
    re.IGNORECASE,
)
FAVICON_RE = re.compile(
    r"<link\b[^>]*rel=[\"'][^\"']*(?:icon|shortcut icon)[^\"']*[\"'][^>]*>",
    re.IGNORECASE,
)
HREF_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.IGNORECASE)


class Finding(BaseModel):
    id: str
    category: str
    severity: str
    title: str
    detail: str
    score: int = Field(ge=-100, le=100)


class InvestigationReport(BaseModel):
    url: str
    final_url: str | None
    hostname: str
    registrable_domain: str
    risk_score: int
    confidence: int
    level: str
    findings: list[Finding]
    engines: dict[str, Any]
    timeline: list[dict[str, Any]]
    iocs: dict[str, list[str]]
    graph: dict[str, list[dict[str, Any]]]
    duration_ms: int
    generated_at: str


@dataclass
class PageFetch:
    final_url: str | None
    redirects: list[dict[str, Any]]
    status_code: int | None
    headers: dict[str, str]
    body: str
    body_hash: str | None
    error: str | None = None


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if re.match(r"^[a-z][a-z0-9+.-]*://", raw_url, re.IGNORECASE):
        return raw_url
    return f"https://{raw_url}"


async def investigate_url(raw_url: str, deep: bool = False) -> InvestigationReport:
    start = time.perf_counter()
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    registrable_domain = get_registrable_domain(hostname)
    timeline: list[dict[str, Any]] = []
    findings: list[Finding] = []

    init_local_db()
    timeline.append(event("input", "URL normalized", {"url": url}))

    fetch_task = fetch_page(url, deep=deep)
    dns_task = asyncio.to_thread(resolve_dns, hostname)
    tls_task = asyncio.to_thread(inspect_tls, hostname)
    history_task = asyncio.to_thread(load_domain_history, hostname)

    page, dns_info, tls_info, history = await asyncio.gather(
        fetch_task, dns_task, tls_task, history_task
    )

    timeline.append(event("network", "Page fetch completed", {
        "finalUrl": page.final_url,
        "statusCode": page.status_code,
        "redirects": len(page.redirects),
    }))
    timeline.append(event("dns", "DNS resolution completed", dns_info))
    timeline.append(event("tls", "TLS inspection completed", tls_info))

    domain_engine = analyze_domain(url, hostname, registrable_domain)
    redirect_engine = analyze_redirects(page.redirects, hostname)
    html_engine = analyze_html(page.body, page.final_url or url, registrable_domain)
    js_engine = analyze_javascript(page.body)
    behavior_engine = analyze_behavior(page.body)
    iocs = extract_iocs(page.body, url)
    favicon = await fetch_favicon(page.body, page.final_url or url)
    graph = build_graph(hostname, registrable_domain, dns_info, tls_info, favicon, iocs)

    engines = {
        "domain": domain_engine,
        "dns": dns_info,
        "tls": tls_info,
        "redirects": redirect_engine,
        "html": html_engine,
        "javascript": js_engine,
        "behavior": behavior_engine,
        "ioc": {k: len(v) for k, v in iocs.items()},
        "favicon": favicon,
        "history": history,
        "capabilities": capability_status(),
    }

    for engine in (domain_engine, redirect_engine, html_engine, js_engine, behavior_engine):
        findings.extend(engine.get("findings", []))

    findings.extend(findings_from_dns(dns_info))
    findings.extend(findings_from_tls(tls_info))
    findings.extend(findings_from_iocs(iocs))
    findings.extend(findings_from_history(history))

    risk_score, confidence, level = score_findings(findings)
    store_scan(hostname, registrable_domain, page.final_url or url, risk_score, level, dns_info, tls_info, favicon)

    return InvestigationReport(
        url=url,
        final_url=page.final_url,
        hostname=hostname,
        registrable_domain=registrable_domain,
        risk_score=risk_score,
        confidence=confidence,
        level=level,
        findings=sorted(findings, key=lambda item: item.score, reverse=True),
        engines=engines,
        timeline=timeline,
        iocs=iocs,
        graph=graph,
        duration_ms=round((time.perf_counter() - start) * 1000),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


async def fetch_page(url: str, deep: bool = False) -> PageFetch:
    redirects: list[dict[str, Any]] = []
    current = url
    headers: dict[str, str] = {
        "User-Agent": "PhishGuard-LocalAnalyzer/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    timeout = httpx.Timeout(8.0 if deep else 5.0, connect=4.0)

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=True, follow_redirects=False) as client:
            for hop in range(0, 8):
                response = await client.get(current, headers=headers)
                location = response.headers.get("location")
                redirects.append({
                    "hop": hop,
                    "url": current,
                    "statusCode": response.status_code,
                    "location": urljoin(current, location) if location else None,
                    "type": "http" if location else "final",
                })
                if response.status_code in {301, 302, 303, 307, 308} and location:
                    current = urljoin(current, location)
                    continue

                body = response.text[:1_000_000]
                meta_url = find_meta_refresh(body, current)
                if meta_url and deep:
                    redirects.append({
                        "hop": hop + 1,
                        "url": current,
                        "statusCode": response.status_code,
                        "location": meta_url,
                        "type": "meta_refresh",
                    })
                    current = meta_url
                    continue

                return PageFetch(
                    final_url=str(response.url),
                    redirects=redirects,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=body,
                    body_hash=hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest(),
                )
        return PageFetch(current, redirects, None, {}, "", None, "Too many redirects")
    except Exception as exc:
        return PageFetch(None, redirects, None, {}, "", None, str(exc))


def resolve_dns(hostname: str) -> dict[str, Any]:
    result: dict[str, Any] = {"ips": [], "errors": []}
    if not hostname:
        result["errors"].append("Missing hostname")
        return result

    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = sorted({info[4][0] for info in infos})
        result["ips"] = ips
        result["ipClasses"] = [classify_ip(ip) for ip in ips]
    except Exception as exc:
        result["errors"].append(str(exc))
    return result


def inspect_tls(hostname: str) -> dict[str, Any]:
    result: dict[str, Any] = {"enabled": False, "errors": []}
    if not hostname:
        result["errors"].append("Missing hostname")
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["enabled"] = True
                result["version"] = ssock.version()
                result["issuer"] = name_tuple_to_dict(cert.get("issuer", []))
                result["subject"] = name_tuple_to_dict(cert.get("subject", []))
                result["notBefore"] = cert.get("notBefore")
                result["notAfter"] = cert.get("notAfter")
                result["san"] = [value for key, value in cert.get("subjectAltName", []) if key == "DNS"][:25]
                result["sha256"] = hashlib.sha256(ssock.getpeercert(binary_form=True)).hexdigest()
                result["expiresInDays"] = cert_days_until_expiry(cert.get("notAfter"))
    except Exception as exc:
        result["errors"].append(str(exc))
    return result


def analyze_domain(url: str, hostname: str, registrable_domain: str) -> dict[str, Any]:
    parsed = urlparse(url)
    findings: list[Finding] = []
    tld = registrable_domain.rsplit(".", 1)[-1] if "." in registrable_domain else ""
    brand = find_brand(hostname + parsed.path)
    brand_owned = bool(brand and registrable_domain in BRANDS.get(brand, set()))

    if parsed.scheme != "https":
        findings.append(finding("no_https", "network", "medium", "No HTTPS", "URL does not use HTTPS.", 12))
    if is_ip_hostname(hostname):
        findings.append(finding("ip_host", "domain", "high", "IP address host", "URL uses an IP address instead of a domain.", 22))
    if tld in SUSPICIOUS_TLDS:
        findings.append(finding("suspicious_tld", "domain", "medium", "Suspicious TLD", f".{tld} is commonly abused.", 14))
    if brand and not brand_owned:
        findings.append(finding("brand_impersonation", "brand", "high", "Possible brand impersonation", f"Mentions {brand} outside known {brand} domains.", 28))
    if has_mixed_scripts(hostname):
        findings.append(finding("homograph", "url", "high", "Possible homograph domain", "Hostname mixes Unicode scripts or contains confusable characters.", 30))
    typo = closest_brand_distance(registrable_domain)
    if typo and typo["distance"] <= 2 and not brand_owned:
        findings.append(finding("typosquat", "url", "high", "Possible typosquatting", f"Domain is close to {typo['brandDomain']}.", 24))
    if parsed.query:
        query = parse_qs(parsed.query)
        if {"url", "redirect", "next", "return", "returnurl"} & {k.lower() for k in query}:
            findings.append(finding("redirect_param", "url", "medium", "Redirect parameter", "URL contains a parameter often used in redirect chains.", 12))

    return {
        "hostname": hostname,
        "registrableDomain": registrable_domain,
        "brand": brand,
        "brandOwned": brand_owned,
        "homograph": has_mixed_scripts(hostname),
        "findings": findings,
    }


def analyze_redirects(redirects: list[dict[str, Any]], original_hostname: str) -> dict[str, Any]:
    findings: list[Finding] = []
    hosts = [urlparse(item["url"]).hostname for item in redirects if item.get("url")]
    unique_hosts = {host for host in hosts if host}
    shorteners = unique_hosts & SHORTENER_DOMAINS

    if len(redirects) >= 4:
        findings.append(finding("long_redirect_chain", "redirect", "medium", "Long redirect chain", f"{len(redirects)} redirect hops observed.", 16))
    if len(unique_hosts) >= 3:
        findings.append(finding("multi_host_redirect", "redirect", "medium", "Cross-domain redirect chain", f"Redirect crossed {len(unique_hosts)} hosts.", 14))
    if shorteners:
        findings.append(finding("url_shortener", "redirect", "medium", "URL shortener used", f"Shortener host(s): {', '.join(sorted(shorteners))}.", 12))
    if redirects and redirects[-1].get("location"):
        final_host = urlparse(redirects[-1]["location"]).hostname
        if final_host and original_hostname and final_host != original_hostname:
            findings.append(finding("final_host_change", "redirect", "medium", "Final host changed", f"Redirect ends on {final_host}.", 13))

    return {"hopCount": len(redirects), "hosts": sorted(unique_hosts), "chain": redirects, "findings": findings}


def analyze_html(body: str, base_url: str, registrable_domain: str) -> dict[str, Any]:
    findings: list[Finding] = []
    lowered = body.lower()
    password_fields = len(PASSWORD_RE.findall(body))
    forms = len(FORM_RE.findall(body))
    iframes = IFRAME_RE.findall(body)
    hidden_iframes = [tag for tag in iframes if "display:none" in tag.lower() or "width=\"0\"" in tag.lower() or "height=\"0\"" in tag.lower()]
    brand = find_brand(strip_tags(body[:200_000]))
    brand_owned = bool(brand and registrable_domain in BRANDS.get(brand, set()))

    if password_fields:
        findings.append(finding("password_form", "html", "high", "Password field detected", f"{password_fields} password field(s) found.", 24))
    if forms >= 3:
        findings.append(finding("many_forms", "html", "medium", "Multiple forms", f"{forms} forms found.", 8))
    if hidden_iframes:
        findings.append(finding("hidden_iframe", "html", "high", "Hidden iframe", f"{len(hidden_iframes)} hidden iframe(s) found.", 22))
    if brand and not brand_owned and password_fields:
        findings.append(finding("fake_login", "visual", "critical", "Fake login risk", f"Page mentions {brand} and asks for credentials on another domain.", 38))
    for phrase in SCAM_PHRASES:
        if phrase in lowered:
            findings.append(finding("scam_phrase", "content", "medium", "Scam wording detected", f"Found phrase: {phrase}.", 10))
            break
    if "qrcode" in lowered or "qr code" in lowered:
        findings.append(finding("qr_present", "visual", "info", "QR code wording", "Page references a QR code; QR extraction can inspect targets.", 4))

    return {
        "forms": forms,
        "passwordFields": password_fields,
        "iframes": len(iframes),
        "hiddenIframes": len(hidden_iframes),
        "textBrand": brand,
        "metaRefresh": find_meta_refresh(body, base_url),
        "findings": findings,
    }


def analyze_javascript(body: str) -> dict[str, Any]:
    scripts = SCRIPT_RE.findall(body)
    combined = "\n".join(scripts)
    lowered = combined.lower()
    findings: list[Finding] = []

    eval_count = lowered.count("eval(")
    atob_count = lowered.count("atob(")
    websocket_count = lowered.count("new websocket")
    clipboard_count = lowered.count("clipboard")
    fingerprint_hits = sum(token in lowered for token in [
        "getimagedata", "webglrenderingcontext", "audiocontext", "navigator.webdriver",
        "canvas.todataurl", "plugins.length",
    ])
    runtime_hooks = sum(token in lowered for token in ["fetch(", "xmlhttprequest", "localstorage", "document.cookie"])
    base64_blobs = re.findall(r"[A-Za-z0-9+/]{120,}={0,2}", combined)

    if eval_count:
        findings.append(finding("js_eval", "javascript", "high", "eval usage", f"`eval()` appears {eval_count} time(s).", 18))
    if atob_count or base64_blobs:
        findings.append(finding("js_obfuscation", "javascript", "high", "Possible JavaScript obfuscation", "Base64 decoding or large encoded blobs found.", 20))
    if websocket_count:
        findings.append(finding("websocket", "behavior", "medium", "WebSocket usage", "Page opens WebSocket connections.", 12))
    if clipboard_count:
        findings.append(finding("clipboard", "behavior", "high", "Clipboard access", "Page references clipboard APIs.", 20))
    if fingerprint_hits >= 2:
        findings.append(finding("fingerprinting", "behavior", "high", "Fingerprinting behavior", f"{fingerprint_hits} fingerprinting indicators found.", 24))

    return {
        "scriptBlocks": len(scripts),
        "evalCount": eval_count,
        "atobCount": atob_count,
        "largeBase64Blobs": len(base64_blobs),
        "webSocketReferences": websocket_count,
        "clipboardReferences": clipboard_count,
        "fingerprintingSignals": fingerprint_hits,
        "runtimeApiReferences": runtime_hooks,
        "findings": findings,
    }


def analyze_behavior(body: str) -> dict[str, Any]:
    lowered = body.lower()
    findings: list[Finding] = []
    signals = {
        "fullscreen": "requestfullscreen" in lowered,
        "backButtonTrap": "pushstate" in lowered and "popstate" in lowered,
        "notificationPrompt": "notification.requestpermission" in lowered or "allow notifications" in lowered,
        "fakeCaptcha": "captcha" in lowered and ("press win+r" in lowered or "verify you are human" in lowered),
        "walletScam": any(token in lowered for token in ["seed phrase", "walletconnect", "airdrop", "connect wallet"]),
        "forcedDownload": any(token in lowered for token in [".exe", ".apk", ".docm", ".scr", ".bat"]),
    }
    weights = {
        "fullscreen": 10,
        "backButtonTrap": 14,
        "notificationPrompt": 12,
        "fakeCaptcha": 30,
        "walletScam": 26,
        "forcedDownload": 24,
    }
    for key, present in signals.items():
        if present:
            findings.append(finding(key, "behavior", "high" if weights[key] >= 20 else "medium", behavior_title(key), behavior_detail(key), weights[key]))
    return {"signals": signals, "findings": findings}


async def fetch_favicon(body: str, base_url: str) -> dict[str, Any]:
    favicon_url = urljoin(base_url, "/favicon.ico")
    match = FAVICON_RE.search(body)
    if match:
        href = HREF_RE.search(match.group(0))
        if href:
            favicon_url = urljoin(base_url, html.unescape(href.group(1)))
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
            response = await client.get(favicon_url)
            if not response.is_success or len(response.content) > 512_000:
                return {"url": favicon_url, "sha256": None, "mmh3": None, "error": f"HTTP {response.status_code}"}
            data = response.content
            return {
                "url": favicon_url,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "dataUriPrefix": "data:image/x-icon;base64," + base64.b64encode(data[:64]).decode("ascii"),
            }
    except Exception as exc:
        return {"url": favicon_url, "sha256": None, "error": str(exc)}


def extract_iocs(body: str, source_url: str) -> dict[str, list[str]]:
    urls = {clean_ioc(item) for item in IOC_URL_RE.findall(body)}
    urls.add(source_url)
    domains = {urlparse(item).hostname or "" for item in urls}
    emails = set(IOC_EMAIL_RE.findall(body))
    ips = set(IOC_IPV4_RE.findall(body))
    wallets = set(IOC_WALLET_RE.findall(body))
    return {
        "urls": sorted(item for item in urls if item)[:100],
        "domains": sorted(item for item in domains if item)[:100],
        "ips": sorted(ips)[:100],
        "emails": sorted(emails)[:100],
        "wallets": sorted(wallets)[:100],
    }


def findings_from_dns(dns_info: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    ips = dns_info.get("ips", [])
    classes = dns_info.get("ipClasses", [])
    if len(ips) >= 8:
        findings.append(finding("fast_flux", "dns", "high", "Possible fast-flux DNS", f"{len(ips)} IPs resolved.", 24))
    if any(item.get("isPrivate") for item in classes):
        findings.append(finding("private_ip", "dns", "medium", "Private IP resolved", "Domain resolves to private/reserved address space.", 16))
    return findings


def findings_from_tls(tls_info: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if not tls_info.get("enabled"):
        findings.append(finding("tls_missing", "tls", "medium", "TLS unavailable", "Could not establish a valid TLS connection.", 12))
        return findings
    expires = tls_info.get("expiresInDays")
    if isinstance(expires, int) and expires <= 7:
        findings.append(finding("tls_expiring", "tls", "medium", "Certificate expires soon", f"Certificate expires in {expires} day(s).", 10))
    return findings


def findings_from_iocs(iocs: dict[str, list[str]]) -> list[Finding]:
    findings: list[Finding] = []
    if iocs.get("wallets"):
        findings.append(finding("wallet_ioc", "ioc", "high", "Wallet address found", "Page contains cryptocurrency wallet indicators.", 18))
    if len(iocs.get("urls", [])) >= 20:
        findings.append(finding("many_urls", "ioc", "medium", "Many URLs extracted", "Page contains many embedded URLs.", 8))
    return findings


def findings_from_history(history: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    previous_high = history.get("previousHighRiskScans", 0)
    if previous_high:
        findings.append(finding("history_high_risk", "history", "high", "Historical high risk", f"{previous_high} previous high-risk scan(s) for this host.", 18))
    return findings


def score_findings(findings: list[Finding]) -> tuple[int, int, str]:
    positive = sum(max(0, item.score) for item in findings)
    negative = sum(min(0, item.score) for item in findings)
    score = max(0, min(100, positive + negative))
    severe = sum(1 for item in findings if item.severity in {"high", "critical"})
    confidence = max(35, min(98, 45 + len(findings) * 4 + severe * 8))
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 35:
        level = "medium"
    elif score >= 15:
        level = "low"
    else:
        level = "safe"
    return score, confidence, level


def build_graph(
    hostname: str,
    registrable_domain: str,
    dns_info: dict[str, Any],
    tls_info: dict[str, Any],
    favicon: dict[str, Any],
    iocs: dict[str, list[str]],
) -> dict[str, list[dict[str, Any]]]:
    nodes = [
        {"id": registrable_domain, "type": "domain", "label": registrable_domain},
        {"id": hostname, "type": "hostname", "label": hostname},
    ]
    edges = [{"source": registrable_domain, "target": hostname, "type": "has_host"}]
    for ip in dns_info.get("ips", []):
        nodes.append({"id": ip, "type": "ip", "label": ip})
        edges.append({"source": hostname, "target": ip, "type": "resolves_to"})
    cert_hash = tls_info.get("sha256")
    if cert_hash:
        cert_id = f"cert:{cert_hash[:16]}"
        nodes.append({"id": cert_id, "type": "certificate", "label": cert_hash[:16]})
        edges.append({"source": hostname, "target": cert_id, "type": "uses_cert"})
    fav_hash = favicon.get("sha256")
    if fav_hash:
        fav_id = f"favicon:{fav_hash[:16]}"
        nodes.append({"id": fav_id, "type": "favicon", "label": fav_hash[:16]})
        edges.append({"source": hostname, "target": fav_id, "type": "uses_favicon"})
    for wallet in iocs.get("wallets", [])[:10]:
        nodes.append({"id": wallet, "type": "wallet", "label": wallet[:16]})
        edges.append({"source": hostname, "target": wallet, "type": "contains_wallet"})
    return {"nodes": nodes, "edges": edges}


def init_local_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                registrable_domain TEXT NOT NULL,
                final_url TEXT,
                risk_score INTEGER NOT NULL,
                level TEXT NOT NULL,
                ips_json TEXT NOT NULL,
                tls_sha256 TEXT,
                favicon_sha256 TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(registrable_domain)")


def store_scan(
    hostname: str,
    registrable_domain: str,
    final_url: str,
    risk_score: int,
    level: str,
    dns_info: dict[str, Any],
    tls_info: dict[str, Any],
    favicon: dict[str, Any],
) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO scans (
                hostname, registrable_domain, final_url, risk_score, level,
                ips_json, tls_sha256, favicon_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hostname,
                registrable_domain,
                final_url,
                risk_score,
                level,
                json.dumps(dns_info.get("ips", [])),
                tls_info.get("sha256"),
                favicon.get("sha256"),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def load_domain_history(hostname: str) -> dict[str, Any]:
    init_local_db()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT risk_score, level, ips_json, tls_sha256, favicon_sha256, created_at
            FROM scans
            WHERE hostname = ?
            ORDER BY id DESC
            LIMIT 25
            """,
            (hostname,),
        ).fetchall()
    previous_high = sum(1 for row in rows if row[1] in {"high", "critical"})
    ips = sorted({ip for row in rows for ip in json.loads(row[2] or "[]")})
    return {
        "previousScans": len(rows),
        "previousHighRiskScans": previous_high,
        "previousIps": ips,
        "lastSeen": rows[0][5] if rows else None,
    }


def capability_status() -> dict[str, Any]:
    return {
        "implementedLocal": [
            "redirect_chain_tracing",
            "dns_resolution",
            "tls_certificate_inspection",
            "html_login_detection",
            "hidden_iframe_mapping",
            "javascript_obfuscation_heuristics",
            "websocket_reference_detection",
            "clipboard_reference_detection",
            "fingerprinting_reference_detection",
            "homograph_detection",
            "typosquatting_detection",
            "ioc_extraction",
            "favicon_hashing",
            "local_history_sqlite",
            "threat_graph_generation",
            "timeline_generation",
            "multi_signal_scoring",
        ],
        "optionalEngines": {
            "playwrightSandbox": "Install Playwright to execute pages and observe runtime behavior.",
            "yara": "Install yara-python and rulesets for payload and JS signatures.",
            "ocr": "Install Tesseract/OpenCV for screenshot text and logo analysis.",
            "apk": "Install Androguard for APK inspection.",
            "packetCapture": "Install tshark/Scapy for packet analysis.",
            "localLlm": "Install Ollama or llama.cpp for offline analyst summaries.",
        },
    }


def get_registrable_domain(hostname: str) -> str:
    parts = hostname.strip(".").lower().split(".")
    if len(parts) <= 2:
        return hostname.lower()
    suffix2 = ".".join(parts[-2:])
    if suffix2 in {"co.uk", "org.uk", "com.au", "co.in", "com.br", "co.jp"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def find_brand(text: str) -> str | None:
    lowered = text.lower()
    return next((brand for brand in BRANDS if brand in lowered), None)


def has_mixed_scripts(hostname: str) -> bool:
    scripts = set()
    for char in hostname:
        if char in ".-" or char.isdigit():
            continue
        name = unicodedata.name(char, "")
        if "LATIN" in name:
            scripts.add("latin")
        elif name:
            scripts.add(name.split(" ")[0].lower())
    return len(scripts) > 1 or hostname.startswith("xn--")


def closest_brand_distance(domain: str) -> dict[str, Any] | None:
    label = domain.split(".")[0].lower()
    best: dict[str, Any] | None = None
    for domains in BRANDS.values():
        for brand_domain in domains:
            brand_label = brand_domain.split(".")[0]
            distance = levenshtein(label, brand_label)
            if best is None or distance < best["distance"]:
                best = {"brandDomain": brand_domain, "distance": distance}
    return best


def levenshtein(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def is_ip_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def classify_ip(ip: str) -> dict[str, Any]:
    obj = ipaddress.ip_address(ip)
    return {
        "ip": ip,
        "version": obj.version,
        "isPrivate": obj.is_private,
        "isGlobal": obj.is_global,
        "isLoopback": obj.is_loopback,
        "isReserved": obj.is_reserved,
    }


def find_meta_refresh(body: str, base_url: str) -> str | None:
    match = META_REFRESH_RE.search(body)
    if not match:
        return None
    content = html.unescape(match.group(1))
    url_match = re.search(r"url\s*=\s*([^;]+)", content, re.IGNORECASE)
    if not url_match:
        return None
    return urljoin(base_url, url_match.group(1).strip("\"' "))


def name_tuple_to_dict(items: Any) -> dict[str, str]:
    output: dict[str, str] = {}
    for group in items:
        for key, value in group:
            output[key] = value
    return output


def cert_days_until_expiry(not_after: str | None) -> int | None:
    if not not_after:
        return None
    try:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (expires - datetime.now(timezone.utc)).days
    except ValueError:
        return None


def strip_tags(markup: str) -> str:
    return re.sub(r"<[^>]+>", " ", html.unescape(markup))


def clean_ioc(value: str) -> str:
    return unquote(value).rstrip(".,);]'\"")


def finding(id_: str, category: str, severity: str, title: str, detail: str, score: int) -> Finding:
    return Finding(id=id_, category=category, severity=severity, title=title, detail=detail, score=score)


def event(category: str, title: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "title": title,
        "data": data,
    }


def behavior_title(key: str) -> str:
    return {
        "fullscreen": "Fullscreen trap reference",
        "backButtonTrap": "Back-button trap reference",
        "notificationPrompt": "Notification abuse indicator",
        "fakeCaptcha": "Fake CAPTCHA scam indicator",
        "walletScam": "Crypto wallet scam indicator",
        "forcedDownload": "Suspicious download reference",
    }[key]


def behavior_detail(key: str) -> str:
    return {
        "fullscreen": "Page references fullscreen APIs.",
        "backButtonTrap": "Page appears to manipulate history navigation.",
        "notificationPrompt": "Page asks for or references notification permission.",
        "fakeCaptcha": "Page contains fake human-verification scam wording.",
        "walletScam": "Page contains wallet, airdrop, or seed phrase indicators.",
        "forcedDownload": "Page references executable or macro-capable payloads.",
    }[key]
