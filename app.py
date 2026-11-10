import ipaddress
import socket
import time

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

HEADERS = {"User-Agent": "Verivex/1.0 (+local tool)"}
MAX_URLS = 50
MAX_REDIRECTS = 5
TIMEOUT = 8 # seconds per request


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

    result = {"input":raw, "final_url": url, "status": None, "state": "broken", "detail": "", "redirects": 0, "ms": 0}
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
    return jsonify(results)


if __name__ == "__main__":
    app.run(debug=True)