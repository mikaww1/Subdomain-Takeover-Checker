#!/usr/bin/env python3
"""
SubdomainChecker — Subdomain Takeover Checker
Usage:
    python main.py <subdomain>
    python main.py shop.example.com
    python main.py --help
"""

from __future__ import annotations
import sys
import uuid
import argparse
import dns.resolver
import requests

# ──────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────

TIMEOUT = 5  # seconds

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; subtake/1.0)"
}

FINGERPRINTS = {

    # ── GitHub ──────────────────────────────────────────────────────────
    "github.io":                    "There isn't a GitHub Pages site here",

    # ── Heroku ──────────────────────────────────────────────────────────
    "herokuapp.com":                "No such app",
    "herokussl.com":                "No such app",
    "herokudns.com":                "No such app",

    # ── AWS ─────────────────────────────────────────────────────────────
    "amazonaws.com":                "NoSuchBucket",
    "s3.amazonaws.com":             "NoSuchBucket",
    "s3-website":                   "NoSuchBucket",           # covers all s3-website-*.amazonaws.com
    "elasticbeanstalk.com":         "404 Not Found",
    "cloudfront.net":               "ERROR: The request could not be satisfied",

    # ── Azure ────────────────────────────────────────────────────────────
    "azurewebsites.net":            "404 Web Site not found",
    "azurefd.net":                  "404 Not Found",          # Azure Front Door
    "azure-api.net":                "BadGateway",             # Azure API Management
    "cloudapp.azure.com":           "404 Web Site not found",
    "cloudapp.net":                 "404 Not Found",
    "trafficmanager.net":           "404 Web Site not found",
    "blob.core.windows.net":        "BlobServiceProperties",
    "servicebus.windows.net":       "404 Not Found",
    "azureedge.net":                "404 Not Found",          # Azure CDN

    # ── Google Cloud ─────────────────────────────────────────────────────
    "storage.googleapis.com":       "NoSuchBucket",
    "c.storage.googleapis.com":     "NoSuchBucket",
    "appspot.com":                  "404 Not Found",
    "googleusercontent.com":        "404 Not Found",

    # ── Fastly ───────────────────────────────────────────────────────────
    "fastly.net":                   "Fastly error: unknown domain",

    # ── Vercel ───────────────────────────────────────────────────────────
    "vercel.app":                   "The deployment could not be found",
    "vercel.sh":                    "The deployment could not be found",
    "now.sh":                       "The deployment could not be found",

    # ── Netlify ──────────────────────────────────────────────────────────
    "netlify.app":                  "Not Found - Request ID",
    "netlify.com":                  "Not Found - Request ID",

    # ── Cloudflare Pages ─────────────────────────────────────────────────
    "pages.dev":                    "not found",

    # ── Render ───────────────────────────────────────────────────────────
    "onrender.com":                 "not found",

    # ── Railway ──────────────────────────────────────────────────────────
    "railway.app":                  "Application not found",
    "up.railway.app":               "Application not found",

    # ── Fly.io ───────────────────────────────────────────────────────────
    "fly.dev":                      "404 Not Found",
    "fly.io":                       "404 Not Found",
    "flycast":                      "404 Not Found",

    # ── Surge ────────────────────────────────────────────────────────────
    "surge.sh":                     "project not found",

    # ── Bitbucket ────────────────────────────────────────────────────────
    "bitbucket.io":                 "Repository not found",

    # ── Pantheon ─────────────────────────────────────────────────────────
    "pantheonsite.io":              "The gods are wise",
    "getpantheon.com":              "The gods are wise",

    # ── WP Engine ────────────────────────────────────────────────────────
    "wpengine.com":                 "The site you were looking for couldn't be found",

    # ── Kinsta ───────────────────────────────────────────────────────────
    "kinsta.cloud":                 "No Site For This Domain",
    "kinsta.com":                   "No Site For This Domain",

    # ── Webflow ──────────────────────────────────────────────────────────
    "webflow.io":                   "The page you are looking for doesn't exist",

    # ── Ghost ────────────────────────────────────────────────────────────
    "ghost.io":                     "Domain not configured",
    "ghost.org":                    "Domain not configured",

    # ── Squarespace ──────────────────────────────────────────────────────
    "squarespace.com":              "No Such Account",
    "sqsp.net":                     "No Such Account",

    # ── Wix ──────────────────────────────────────────────────────────────
    "wix.com":                      "Error ConnectYourDomain",
    "wixsite.com":                  "Error ConnectYourDomain",

    # ── Cargo / CargoCollective ───────────────────────────────────────────
    "cargo.site":                   "If you're the site owner",
    "cargocollective.com":          "If you're the site owner",

    # ── Shopify ──────────────────────────────────────────────────────────
    "shopify.com":                  "Sorry, this shop is currently unavailable",
    "myshopify.com":                "Sorry, this shop is currently unavailable",

    # ── BigCartel ────────────────────────────────────────────────────────
    "bigcartel.com":                "Oops! You've stumbled upon a shop that is no longer around",

    # ── HubSpot ──────────────────────────────────────────────────────────
    "hubspot.net":                  "This page isn't available",
    "hubspotpagebuilder.com":       "This page isn't available",
    "hs-sites.com":                 "This page isn't available",

    # ── Instapage ────────────────────────────────────────────────────────
    "instapage.com":                "Looks Like You're Lost",
    "pageserve.co":                 "Looks Like You're Lost",

    # ── Unbounce ─────────────────────────────────────────────────────────
    "unbounce.com":                 "The requested URL was not found on this server",
    "ubembed.com":                  "The requested URL was not found on this server",

    # ── Strikingly ───────────────────────────────────────────────────────
    "strikingly.com":               "page not found",

    # ── Tilda ────────────────────────────────────────────────────────────
    "tilda.ws":                     "Domain is not connected",
    "tildacdn.com":                 "Domain is not connected",

    # ── Mailchimp ────────────────────────────────────────────────────────
    "mailchimpsites.com":           "There is no site here",
    "mcsv.net":                     "There is no site here",

    # ── Campaign Monitor ─────────────────────────────────────────────────
    "campaignmonitor.com":          "Double-check the URL",

    # ── Zendesk ──────────────────────────────────────────────────────────
    "zendesk.com":                  "Help Center Closed",
    "zendeskgarden.com":            "Help Center Closed",

    # ── Freshdesk ────────────────────────────────────────────────────────
    "freshdesk.com":                "There is no such account",
    "freshservice.com":             "There is no such account",

    # ── Help Scout ───────────────────────────────────────────────────────
    "helpscoutdocs.com":            "No settings were found",
    "helpscout.net":                "No settings were found",

    # ── HelpJuice ────────────────────────────────────────────────────────
    "helpjuice.com":                "We could not find what you're looking for",

    # ── UserVoice ────────────────────────────────────────────────────────
    "uservoice.com":                "This UserVoice subdomain is currently available",

    # ── Intercom ─────────────────────────────────────────────────────────
    "intercom.help":                "Uh oh. That page doesn't exist.",
    "custom.intercom.help":         "Uh oh. That page doesn't exist.",

    # ── Statuspage / Atlassian ───────────────────────────────────────────
    "statuspage.io":                "You are being redirected",
    "atlassian.net":                "Page not found",

    # ── Readme.io ────────────────────────────────────────────────────────
    "readme.io":                    "Project doesnt exist... yet!",
    "readme.com":                   "Project doesnt exist... yet!",

    # ── AfterShip ────────────────────────────────────────────────────────
    "aftership.com":                "Oops.",

    # ── Pingdom ──────────────────────────────────────────────────────────
    "pingdom.com":                  "Sorry, couldn't find the status page",

    # ── Tumblr ───────────────────────────────────────────────────────────
    "tumblr.com":                   "Whatever you were looking for doesn't currently exist",

    # ── LaunchRock ───────────────────────────────────────────────────────
    "launchrock.com":               "It looks like you may have taken a wrong turn",

    # ── Desk.com ─────────────────────────────────────────────────────────
    "desk.com":                     "Please try again or try Desk.com free for 14 days",

    # ── Format ───────────────────────────────────────────────────────────
    "format.com":                   "Sorry, this page is no longer available",

    # ── Agile CRM ────────────────────────────────────────────────────────
    "agilecrm.com":                 "Sorry, this page is no longer available",

    # ── Supabase ─────────────────────────────────────────────────────────
    "supabase.co":                  "Project not found",
    "supabase.in":                  "Project not found",

    # ── Bubble ───────────────────────────────────────────────────────────
    "bubbleapps.io":                "404 Not Found",
    "bubble.io":                    "404 Not Found",

    # ── Glitch ───────────────────────────────────────────────────────────
    "glitch.me":                    "No such app",

    # ── Gitbook ──────────────────────────────────────────────────────────
    "gitbook.io":                   "If you need help",
    "gitbook.com":                  "If you need help",

    # ── Notion ───────────────────────────────────────────────────────────
    "notion.site":                  "page not found",

    # ── Leadpages ────────────────────────────────────────────────────────
    "leadpages.net":                "Your 404 page here",
    "lpages.co":                    "Your 404 page here",
    "lp.co":                        "Your 404 page here",

    # ── Kajabi ───────────────────────────────────────────────────────────
    "kajabi.com":                   "This page is no longer available",
    "kajabipages.com":              "This page is no longer available",

    # ── Podia ────────────────────────────────────────────────────────────
    "podia.com":                    "404 — We can't find that page",

    # ── Teachable ────────────────────────────────────────────────────────
    "teachable.com":                "This course is no longer available",
    "teachablecdn.com":             "This course is no longer available",

    # ── Thinkific ────────────────────────────────────────────────────────
    "thinkific.com":                "Something went wrong",

    # ── Acquia ───────────────────────────────────────────────────────────
    "acquia-sites.com":             "If you are an Acquia Cloud customer",
    "acquia.com":                   "If you are an Acquia Cloud customer",

    # ── Smugmug ──────────────────────────────────────────────────────────
    "smugmug.com":                  "Page Not Found",

    # ── BunnyCDN ─────────────────────────────────────────────────────────
    "b-cdn.net":                    "No such app",
    "bunnycdn.com":                 "No such app",

    # ── Fastmail ─────────────────────────────────────────────────────────
    "fastmail.com":                 "This domain is not hosted here",
    "fastmail.fm":                  "This domain is not hosted here",

    # ── SendGrid ─────────────────────────────────────────────────────────
    "sendgrid.net":                 "The page you are looking for does not exist",

    # ── Mailgun ──────────────────────────────────────────────────────────
    "mailgun.org":                  "The page you are looking for does not exist",
}

# ──────────────────────────────────────────────
#  Same-owner pairs
#  Subdomains of X pointing to Y are not exploitable
#  because the same organization controls both sides.
# ──────────────────────────────────────────────

SAME_OWNER_PAIRS = [
    ("github.com",      "github.io"),
    ("google.com",      "googleusercontent.com"),
    ("google.com",      "appspot.com"),
    ("amazonaws.com",   "amazonaws.com"),
    ("microsoft.com",   "azurewebsites.net"),
    ("microsoft.com",   "azure.com"),
]


# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

def normalize(domain: str) -> str:
    """Strip protocol, path, port, and trailing dots. Preserves all subdomains."""
    domain = domain.lower().strip()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    domain = domain.rstrip(".")
    return domain


def get_registrable_domain(subdomain: str) -> str:
    """
    Returns a best-effort registrable domain (last two labels).
    e.g. shop.example.com → example.com
    """
    parts = subdomain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else subdomain


def same_owner(subdomain: str, cname_chain: list[str]) -> bool:
    """
    Returns True if the CNAME target is owned by the same organization
    as the subdomain. e.g. brandguide.github.com → *.github.io is not
    exploitable because GitHub controls both sides.
    """
    subdomain_root = get_registrable_domain(subdomain)
    for cname in cname_chain:
        cname_root = get_registrable_domain(cname)
        for owner_domain, service_domain in SAME_OWNER_PAIRS:
            if subdomain_root == owner_domain and cname_root == service_domain:
                return True
    return False


# ──────────────────────────────────────────────
#  DNS
# ──────────────────────────────────────────────

def resolve_cname_chain(subdomain: str) -> tuple[list[str], bool]:
    """
    Follows the full CNAME chain and returns (chain, ended_in_nxdomain).
    ended_in_nxdomain=True means the final target doesn't exist in DNS —
    a strong signal of a dangling CNAME regardless of service fingerprint.
    """
    chain: list[str] = []
    current = subdomain
    visited: set[str] = set()

    while True:
        if current in visited:
            _warn("Circular CNAME chain detected — stopping.")
            return chain, False
        visited.add(current)

        try:
            result = dns.resolver.resolve(current, "CNAME")
            target = str(result[0].target).rstrip(".")
            chain.append(target)
            current = target

        except dns.resolver.NoAnswer:
            return chain, False

        except dns.resolver.NXDOMAIN:
            return chain, True

        except Exception as e:
            _warn(f"DNS error resolving '{current}': {e}")
            return chain, False


def has_a_record(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except Exception:
        return False


def is_wildcard_domain(subdomain: str) -> bool:
    """
    Detects wildcard DNS on the parent domain by resolving a random subdomain.
    Wildcard DNS makes CNAME-dangling checks unreliable (false positives).
    """
    parent = get_registrable_domain(subdomain)
    probe = f"{uuid.uuid4().hex[:12]}.{parent}"
    if has_a_record(probe):
        _warn(f"Wildcard DNS on '{parent}' — results may be unreliable.")
        return True
    return False


# ──────────────────────────────────────────────
#  Service matching & HTTP check
# ──────────────────────────────────────────────

def match_service(cname_chain: list[str]) -> tuple[str | None, str | None, str | None]:
    """
    Checks each CNAME in the chain against known vulnerable services.
    Returns (service, fingerprint, matched_cname) or (None, None, None).
    """
    for cname in cname_chain:
        for service, fingerprint in FINGERPRINTS.items():
            if service in cname:
                return service, fingerprint, cname
    return None, None, None


def http_check(subdomain: str, fingerprint: str) -> tuple[bool, str | int]:
    """
    Tries HTTPS then HTTP. Returns (fingerprint_found, status_or_error).
    """
    last_error: str | int = "Could not connect"

    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{subdomain}"
            resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=True)
            if fingerprint.lower() in resp.text.lower():
                return True, resp.status_code
            return False, resp.status_code
        except requests.exceptions.Timeout:
            last_error = "Request timed out"
        except requests.exceptions.ConnectionError:
            last_error = "Connection error"
        except requests.RequestException as e:
            last_error = str(e)

    return False, last_error


# ──────────────────────────────────────────────
#  Result schema
# ──────────────────────────────────────────────

def make_result(
    subdomain: str,
    cname_chain: list[str],
    vulnerable: bool,
    reason: str,
    confidence: str = "confirmed",
    service: str | None = None,
    matched_cname: str | None = None,
    fingerprint: str | None = None,
    http_status: str | int | None = None,
    wildcard: bool = False,
) -> dict:
    """
    confidence:
      "confirmed" — service recognised, fingerprint checked → reliable answer
      "unknown"   — CNAME points to unrecognised service → manual review needed
      "n/a"       — no CNAME or A record to evaluate
    """
    return {
        "subdomain":         subdomain,
        "cname_chain":       cname_chain,
        "vulnerable":        vulnerable,
        "confidence":        confidence,
        "reason":            reason,
        "service":           service,
        "matched_cname":     matched_cname,
        "fingerprint":       fingerprint,
        "http_status":       http_status,
        "wildcard_detected": wildcard,
    }


# ──────────────────────────────────────────────
#  Core check
# ──────────────────────────────────────────────

def check_subdomain(subdomain: str, skip_wildcard: bool = False) -> dict:
    subdomain = normalize(subdomain)
    _info(f"Checking: {subdomain}")

    wildcard = False if skip_wildcard else is_wildcard_domain(subdomain)

    cname_chain, ended_in_nxdomain = resolve_cname_chain(subdomain)

    if not cname_chain:
        if has_a_record(subdomain):
            reason = "Points directly to an IP (A record) — not an external service"
        else:
            reason = "No DNS records found. This subdomain likely does not exist."
        _info(reason)
        return make_result(subdomain, [], False, reason, confidence="n/a", wildcard=wildcard)

    chain_display = " → ".join([subdomain] + cname_chain)
    _info(f"CNAME chain: {chain_display}")

    # ── Same-owner check ─────────────────────────────────────────────────
    if same_owner(subdomain, cname_chain):
        reason = "CNAME points to a service owned by the same organization — not exploitable"
        _info(f"? {reason}")
        return make_result(subdomain, cname_chain, False, reason, confidence="unknown", wildcard=wildcard)

    # ── NXDOMAIN check (dangling CNAME) ──────────────────────────────────
    if ended_in_nxdomain and not wildcard:
        last = cname_chain[-1]
        reason = f"Dangling CNAME — '{last}' does not exist in DNS (NXDOMAIN)"
        _info(f"VULNERABLE — {reason}")
        service, _, _ = match_service(cname_chain)
        return make_result(
            subdomain=subdomain,
            cname_chain=cname_chain,
            vulnerable=True,
            confidence="confirmed",
            reason=reason,
            service=service,
            wildcard=wildcard,
        )

    # ── Service fingerprint + HTTP check ─────────────────────────────────
    service, fingerprint, matched_cname = match_service(cname_chain)

    if not service:
        last = cname_chain[-1]
        reason = f"CNAME points to unrecognised service ({last}) — manual review recommended"
        _info(f"? {reason}")
        return make_result(subdomain, cname_chain, False, reason, confidence="unknown", wildcard=wildcard)

    _info(f"Matched service: {service} (via {matched_cname})")
    _info(f"Fetching page (timeout: {TIMEOUT}s)...")

    vulnerable, status = http_check(subdomain, fingerprint)

    if vulnerable:
        reason = f"Unconfigured fingerprint found for {service}"
    else:
        reason = f"Service is configured — fingerprint not present (HTTP {status})"

    _info(("VULNERABLE — " if vulnerable else "") + reason)

    return make_result(
        subdomain=subdomain,
        cname_chain=cname_chain,
        vulnerable=vulnerable,
        confidence="confirmed",
        reason=reason,
        service=service,
        matched_cname=matched_cname,
        fingerprint=fingerprint,
        http_status=status,
        wildcard=wildcard,
    )


# ──────────────────────────────────────────────
#  Output helpers
# ──────────────────────────────────────────────

CONFIDENCE_LABEL = {
    "confirmed": "Confirmed ✓",
    "unknown":   "Unknown — manual review needed ⚠️",
    "n/a":       "N/A",
}

def _info(msg: str): print(f"[*] {msg}")
def _warn(msg: str): print(f"[!] {msg}", file=sys.stderr)


def print_result(r: dict):
    vuln_str = "YES 🔴" if r["vulnerable"] else "No  ✅"
    conf_str = CONFIDENCE_LABEL.get(r["confidence"], r["confidence"])

    print()
    print("─" * 48)
    print(f"  Subdomain  : {r['subdomain']}")
    print(f"  Vulnerable : {vuln_str}")
    print(f"  Confidence : {conf_str}")
    print(f"  Reason     : {r['reason']}")
    if r["service"]:
        print(f"  Service    : {r['service']}")
    if r["cname_chain"]:
        print(f"  CNAME chain: {' → '.join(r['cname_chain'])}")
    if r["http_status"]:
        print(f"  HTTP status: {r['http_status']}")
    if r["wildcard_detected"]:
        print(f"  ⚠️  Wildcard DNS — treat results with caution")
    print("─" * 48)


# ──────────────────────────────────────────────
#  CLI entry point
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main",
        description="Check whether a subdomain is vulnerable to takeover.",
        epilog="Examples:\n"
               "  python main.py shop.example.com\n"
               "  python main.py https://blog.example.com\n"
               "  python main.py dev.example.com --no-wildcard-check\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "subdomain",
        help="Subdomain to check (e.g. shop.example.com)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=TIMEOUT,
        metavar="SECONDS",
        help=f"HTTP request timeout in seconds (default: {TIMEOUT})",
    )
    parser.add_argument(
        "--no-wildcard-check",
        action="store_true",
        help="Skip wildcard DNS detection (faster, but may produce false positives)",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    global TIMEOUT
    TIMEOUT = args.timeout

    subdomain = normalize(args.subdomain)
    if not subdomain:
        parser.error("No subdomain provided.")

    result = check_subdomain(subdomain, skip_wildcard=args.no_wildcard_check)
    print_result(result)

    sys.exit(1 if result["vulnerable"] else 0)


if __name__ == "__main__":
    main()