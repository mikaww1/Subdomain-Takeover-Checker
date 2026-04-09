# Subdomain Takeover Checker

A fast, lightweight tool to detect subdomain takeover vulnerabilities. Built for bug bounty hunters, CTF players, and developers who want to audit their own domains.

🔗 **Live tool: [subdomainchecker.com](https://www.subdomainchecker.com)**
---

## What is a subdomain takeover?

When a subdomain (e.g. `shop.example.com`) points to an external service via a CNAME record, but that service is no longer configured, an attacker can register the unclaimed service and take control of the subdomain. This tool detects that.

## Features

- Follows full CNAME chains
- Fingerprint matching for 40+ services (GitHub Pages, Heroku, Vercel, Netlify, AWS S3, Shopify, Zendesk, and more)
- Wildcard DNS detection to flag unreliable results
- Works as a CLI tool or web app
- No data stored, no logging

## Supported Services

GitHub Pages, Heroku, AWS S3, Fastly, Netlify, Vercel, Cloudflare Pages, Azure, Elastic Beanstalk, Ghost, Surge, Shopify, Zendesk, Freshdesk, HubSpot, Webflow, Squarespace, Tumblr, and more.

## Usage

### Web
Visit the live tool at [subdomainchecker.com](https://subdomainchecker.com) and enter a subdomain.

### CLI

```bash
git clone https://github.com/mikaww1/Subdomain-Takeover-Checker.git
cd SubdomChecker
pip install -r requirements.txt
python main.py shop.example.com
```

Options:
```
python main.py <subdomain> [--timeout SECONDS] [--no-wildcard-check]
```

### Run locally as a web app

```bash
pip install -r requirements.txt
python api.py
```

Then open http://127.0.0.1:5000

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

## Tech stack

- Python, Flask, dnspython, requests
- Vanilla HTML/CSS/JS frontend

## Legal

Only use this tool on domains you own or have explicit permission to test.
