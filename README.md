# 🔍 Subdomain Takeover Checker

> Detect dangling CNAMEs and subdomain takeover vulnerabilities across 80+ services — instantly.

🔗 **Live tool: [subdomainchecker.com](https://www.subdomainchecker.com)**
📦 **Public API: [RapidAPI](https://rapidapi.com/mikaww1/api/subdomain-takeover-checker)**

---

## What is a subdomain takeover?

When a subdomain like `shop.example.com` points to an external service via a CNAME record, but that service is no longer configured, an attacker can register the unclaimed service and take full control of the subdomain — serving phishing pages, stealing cookies, or damaging the brand.

```
shop.example.com  →  CNAME  →  old-store.myshopify.com  →  ❌ unclaimed
```

This tool detects that automatically.

---

## Features

- 🔗 **Follows full CNAME chains** — not just the first hop
- 🧠 **80+ service fingerprints** — GitHub Pages, Heroku, Vercel, Netlify, AWS S3, Azure, Shopify, Zendesk and more
- 🌐 **Subdomain enumeration** — enter a root domain, discovers subdomains via certificate transparency logs (crt.sh) and checks them all automatically
- 🛡️ **Wildcard DNS detection** — avoids false positives
- 🤝 **Same-owner detection** — skips CNAMEs that point to services owned by the same organization (e.g. `*.github.com` → `*.github.io`)
- ⚡ **Bulk mode** — check up to 10 subdomains at once
- 🔒 No data stored, no logging
- 🖥️ Works as a web app, CLI tool, or API

---

## Live Demo

👉 **[subdomainchecker.com](https://www.subdomainchecker.com)**

---

## Quick Start

### Web
Visit **[subdomainchecker.com](https://www.subdomainchecker.com)** — no install needed.

### CLI

```bash
git clone https://github.com/mikaww1/Subdomain-Takeover-Checker.git
cd Subdomain-Takeover-Checker
pip install -r requirements.txt
python main.py shop.example.com
```

**Options:**
```
python main.py <subdomain> [--timeout SECONDS] [--no-wildcard-check]
```

### Run locally as a web app

```bash
pip install -r requirements.txt
python api.py
```

Open http://127.0.0.1:5000

---

## Example output

```
[*] Checking: shop.example.com
[*] CNAME chain: shop.example.com → mystore.myshopify.com
[*] Matched service: myshopify.com
[*] Fetching page (timeout: 5s)...
[!!!] VULNERABLE — Unconfigured fingerprint found for myshopify.com

────────────────────────────────────────────────
  Subdomain  : shop.example.com
  Vulnerable : YES 🔴
  Confidence : Confirmed ✓
  Service    : myshopify.com
  CNAME chain: mystore.myshopify.com
  HTTP status: 200
────────────────────────────────────────────────
```

---

## Public API

Available on RapidAPI with a free tier — integrate subdomain takeover detection into your own recon pipeline.

**Endpoints:**
- `GET /check?subdomain=shop.example.com` — single subdomain check
- `POST /bulk_check` — check up to 25 subdomains at once

📦 **[View on RapidAPI](https://rapidapi.com/mikaww1/api/subdomain-takeover-checker)**

---

## Supported Services

AWS S3, Azure, Cloudfront, Elastic Beanstalk, GitHub Pages, Heroku, Vercel, Netlify, Cloudflare Pages, Render, Railway, Fly.io, Surge, Bitbucket, Pantheon, WP Engine, Kinsta, Webflow, Ghost, Squarespace, Wix, Shopify, BigCartel, HubSpot, Instapage, Unbounce, Zendesk, Freshdesk, Help Scout, Intercom, Statuspage, Readme.io, Tumblr, Supabase, Bubble, Gitbook, Notion, Fastly, Mailchimp, Pingdom, and more.

---

## Tech Stack

- **Backend:** Python, Flask, dnspython, requests
- **Frontend:** Vanilla HTML/CSS/JS
- **Deployment:** Railway + Gunicorn

---

## Legal

Only use this tool on domains you own or have explicit permission to test. The authors are not responsible for misuse.