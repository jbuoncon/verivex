# Verivex

A link checker and safety scanner. Paste in a list of URLs and Verivex tells you whether each link still works and whether it shows signs of being risky.

## Features

**Link checking**
- Reports Working, Redirects, Broken, Restricted, or Skipped for each link, with the HTTP status code and response time
- Follows redirect chains (up to 5) and shows the final destination
- Uses lightweight `HEAD` requests and falls back to `GET` for servers that reject them
- Explains failures in plain language: timeouts, bad domains, certificate problems
- Checks up to 10 links at a time with a thread pool

**Safety scanning**
- Local red-flag checks: unencrypted HTTP, raw IP addresses, lookalike (punycode) domains, `user@site` disguises, brand impersonation, shortened links, direct downloads of program files, and cross-site redirects
- Optional Google Safe Browsing lookup for known malware and phishing sites
- Each link gets a verdict (No red flags, Caution, High risk) with the reasons listed

**Security of the tool itself**
- SSRF protection: only public addresses are visited, and the check repeats at every redirect
- Results are rendered with `textContent`, never `innerHTML`, to prevent XSS
- Limits on links per batch, request timeouts, and redirect depth

## Setup

Requires Python 3.9 or newer.

```bash
git clone https://github.com/jbuoncon/verivex.git
cd verivex
python -m venv .venv
```

Activate the environment:

```bash
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Mac/Linux
source .venv/bin/activate
```

Install and run:

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 and paste some links. Results start automatically after you paste.

### Optional: Google Safe Browsing

Without a key, only the local red-flag checks run, and the page says so. To also check links against Google's malware and phishing lists:

1. Create a Google Cloud project, enable the **Safe Browsing API**, and create an API key.
2. Set it before starting the app:

```powershell
# Windows (PowerShell)
$env:GOOGLE_SAFE_BROWSING_KEY = "your-key-here"
```
```bash
# Mac/Linux
export GOOGLE_SAFE_BROWSING_KEY = "your-key-here"
```

Never commit your key. Note that links are sent to Google when this is enabled.

## How it works

| File | Role |
|---|---|
| `app.py` | Flask server: link checking, safety analysis, `/api/check` endpoint |
| `templates/index.html` | Single-page interface and the JavaScript that calls the API |
| `requirements.txt` | Python dependencies (Flask, requests) |

1. The page sends the pasted links to `POST /api/check`.
2. The server checks each link concurrently, then scores it with `analyze_url` and, if configured, Safe Browsing.
3. The server returns JSON, and the page renders it as a table.

## Limitations

- "No red flags" does not mean "safe." It means nothing suspicious was found. New malicious sites may not appear on any list yet.
- The red-flag checks are heuristics and can produce false alarms. For example, legitimate shortened links are marked Caution.
- Verivex never downloads or executes page content and does not scan files for viruses.
- Some sites block automated requests and show as Restricted even when they work in a browser.

## License

Copyright (c) 2026 John Buonconsiglio. All rights reserved.