import ipaddress
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

HEADERS = {"User-Agent": "Verivex/2.0 (+local tool)"}
MAX_URLS = 50
MAX_REDIRECTS = 5
TIMEOUT = 8 # seconds per request

# - Safety-check data
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"}
PROGRAM_EXT = {".exe", ".msi", ".scr", ".bat", ".cmd", ".apk", ".jar", ".vbs", ".ps1", ".dmg", ".iso"}
ARCHIVE_EXT = {".zip", ".rar", ".7z"}
BRANDS = {"paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
          "google": "google.com", "amazon": "amazon.com", "netflix": "netflix.com",
          "facebook": "facebook.com", "instagram": "instagram.com"}

SB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_NAMES = {"MALWARE": "malware", "SOCIAL_ENGINEERING": "phishing",
                "UNWANTED_SOFTWARE": "unwanted software",
                "POTENTIALLY_HARMFUL_APPLICATION": "harmful apps"}


def is_public(url: str) -> bool:
    """
    Only allow http(s) URLs that resolve 
    to public IPs (prevents the checker 
    from being used to probe your local network)."""
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    port = parts.port or (443 if parts.scheme == "https" else 80)
    infos = socket.getaddrinfo(parts.hostname, port)
    return all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


def check_link(raw: str) -> dict:
    url = raw.strip()
    if "://" not in url:
        url = "https://" + url

    result = {"input":raw, "url": url, "final_url": url, "status": None, "state": "broken", "detail": "", "redirects": 0, "ms": 0}
    start = time.time()
    current = url

    try:
        for hop in range(MAX_REDIRECTS + 1):
            if not is_public(current):
                result.update(state="blocked", 
                              detail="Only public http(s) addresses are checked.")
                break

            r = requests.head(current, headers=HEADERS, timeout=TIMEOUT,
                              allow_redirects=False)
            # servers reject HEAD, retry with GET
            if r.status_code in (400, 403, 405, 501):
                r = requests.get(current, headers=HEADERS, timeout=TIMEOUT,
                                 allow_redirects=False, stream=True)
                r.close()

            if r.is_redirect and r.headers.get("Location"):
                current = urljoin(current, r.headers["Location"])
                result["redirects"] = hop + 1
                result["final_url"] = current
                continue

            code = r.status_code
            result.update(status=code, final_url=current)
            if code < 400:
                result["state"] = "redirected" if result["redirects"] else "ok"
                result["detail"] = (f"Redirects {result['redirects']}x to the final address."
                                    if result["redirects"] else "Link works.")

            elif code in (401, 403, 429):
                result["state"] = "restricted"
                result["detail"] = "The site refused an automated check. It may still open in a browser."

            else:
                result["detail"] = f"The server returned HTTP {code}."
            break
        else:
            result["detail"] = f"More than {MAX_REDIRECTS} redirects."
    except requests.exceptions.SSLError:
        result["detail"] = "Security certificate problem."
    except requests.exceptions.Timeout:
        result["detail"] = f"No response within {TIMEOUT} seconds."
    except (socket.gaierror, requests.exceptions.ConnectionError):
        result["detail"] = "Could not connect. Check the domain name."
    except Exception as exc: # malformed URLs
        result["detail"] = f"Could not check this link ({type(exc).__name__})."

    result["ms"] = int((time.time() - start) * 1000)
    return result


def analyze_url(*urls) -> dict:
    """
    Static red-flag checks. Returns {warning text: risk points}.
    """
    findings = {}
    hosts = []
    try:
        for u in dict.fromkeys(x for x in urls if x):
            p = urlparse(u)
            host = (p.hostname or "").lower()
            labels = host.split(".")
            hosts.append(host.removeprefix("www."))

            if p.scheme == "http":
                findings["Uses unencrypted HTTP"] = 15
            try:
                ipaddress.ip_address(host)
                findings["Address is a raw IP, not a domain name"] = 25
            except ValueError:
                pass
            if "xn--" in host:
                findings["Domain uses lookalike (punycode) characters"] = 25
            if p.username:
                findings["Has a username in the address, a trick that disguises the real site"] = 30
            if len(labels) >= 5:
                findings["Unusually many subdomains"] = 10
            if labels[-1] in SUSPICIOUS_TLDS:
                findings["Uses a domain ending often seen in abuse"] = 10
            if host in SHORTENERS:
                findings["Shortened link that hides its real destination"] = 10

            ext = os.path.splitext(p.path.lower())[1]
            if ext in PROGRAM_EXT:
                findings["Links directly to a program file"] = 25
            elif ext in ARCHIVE_EXT:
                findings["Links directly to a compressed download"] = 10

            for brand, legit in BRANDS.items():
                named = any(l == brand or l.startswith(brand + "-") or l.endswith("-" + brand)
                            for l in labels)
                if named and host != legit and not host.endswith("." + legit):
                    findings[f"Name resembles {brand.title()} but is not {legit}"] = 25

    except ValueError:
        findings["Address is malformed"] = 20

    if len(set(hosts)) > 1:
        findings["Redirects to a different website"] = 10
    return findings


def safe_browsing_lookup(urls):
    """
    Ask Google Safe Browsing about each URL.
    Returns {url: set(threat names)}, or None if no API key / lookup failed.
    """
    key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
    if not key or not urls:
        return None
    body = {
        "client": {"clientId": "verifex", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": list(THREAT_NAMES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    try:
        r = requests.post(SB_URL, params={"key": key}, json=body, timeout=10)
        r.raise_for_status()
        hits = {}
        for m in r.json().get("matches", []):
            name = THREAT_NAMES.get(m["threatType"], m["threatType"].lower())
            hits.setdefault(m["threat"]["url"], set()).add(name)
        return hits
    except Exception:
        return None



@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/check")
def api_check():
    data = request.get_json(silent=True) or {}
    urls = [u.strip() for u in data.get("urls", []) if isinstance(u, str) and u.strip()]
    urls = list(dict.fromkeys(urls))[:MAX_URLS] # de-duplicate, cap count
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(check_link, urls))

    hits = safe_browsing_lookup(list({u for r in results for u in (r["url"], r["final_url"])}))
    
    for r in results:
        findings = analyze_url(r["url"], r["final_url"])
        if hits:
            for u in (r["url"], r["final_url"]):
                for threat in hits.get(u, ()):
                    findings[f"Google Safe Browsing lists this site for {threat}"] = 100
        score = sum(findings.values())
        r["risk"] = "high" if score >= 50 else "caution" if score >= 20 else "low"
        r["flags"] = sorted(findings, key=findings.get, reverse=True)

    return jsonify({"results": results, "reputation_checked": hits is not None})


if __name__ == "__main__":
    # Debug is off by default. To turn it on locally: $env:FLASK_DEBUG = "1"
    app.run()