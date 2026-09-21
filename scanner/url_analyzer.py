from urllib.parse import urlparse
import ipaddress

def analyze_url(url: str) -> dict:
    parsed_url = urlparse(url)

    findings = []

    # 1. Check the URL scheme
    if parsed_url.scheme not in ("http", "https"):
        findings.append({
            "type": "invalid_scheme",
            "severity": "high",
            "title": "Unsupported URL scheme",
            "description": "The URL does not use HTTP or HTTPS."
        })


    # 2. Check HTTPS
    if parsed_url.scheme != "https":
        findings.append({
            "type": "no_https",
            "severity": "medium",
            "title": "Connection is not using HTTPS",
            "description": "The URL uses HTTP instead of HTTPS."
        })

    hostname = parsed_url.hostname

    # 3. Make sure a hostname exists
    if not hostname:
        findings.append({
            "type": "missing_hostname",
            "severity": "high",
            "title": "Missing hostname",
            "description": "The URL does not contain a valid hostname."
        })

        return {
            "url": url,
            "domain": None,
            "findings": findings,
            "indicator_count": len(findings)
        }


    # 4. Check whether hostname is an IP address
    try:
        ipaddress.ip_address(hostname)

        findings.append({
            "type": "ip_hostname",
            "severity": "medium",
            "title": "Hostname is an IP address",
            "description": "The URL uses an IP address instead of a domain name."
        })

    except ValueError:
        pass


    # 5. Check for @ symbol
    if "@" in url:
        findings.append({
            "type": "at_symbol",
            "severity": "medium",
            "title": "URL contains an @ symbol",
            "description": "The URL contains an @ symbol, which can make URLs harder to interpret."
        })

    # 6. Check for punycode
    if any(part.lower().startswith("xn--") for part in hostname.split(".")):
        findings.append({
            "type": "punycode",
            "severity": "medium",
            "title": "Hostname uses punycode",
            "description": "Part of the hostname uses IDN punycode."
        })


    # 7. Check URL length
    if len(url) > 200:
        findings.append({
            "type": "long_url",
            "severity": "low",
            "title": "Unusually long URL",
            "description": "The URL is longer than 200 characters."
        })


    # 8. Check number of subdomains
    parts = hostname.split(".")

    if len(parts) > 4:
        findings.append({
            "type": "many_subdomains",
            "severity": "low",
            "title": "Many subdomains",
            "description": "The hostname contains an unusually large number of subdomain levels."
        })

    return {
        "url": url,
        "domain": hostname,
        "findings": findings,
        "indicator_count": len(findings)
    }

