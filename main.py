#!/usr/bin/env python3
"""
subtake — Subdomain Takeover Checker
Usage:
    python subtake.py <subdomain>
    python subtake.py shop.example.com
    python subtake.py --help
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
    # Cloud / hosting
    "github.io":              "There isn't a GitHub Pages site here",
    "herokuapp.com":          "No such app",
    "amazonaws.com":          "NoSuchBucket",
    "s3.amazonaws.com":       "NoSuchBucket",
    "fastly.net":             "Fastly error: unknown domain",
    "pantheonsite.io":        "The gods are wise",
    "ghost.io":               "Domain not configured",
    "surge.sh":               "project not found",
    "bitbucket.io":           "Repository not found",
    "netlify.app":            "Not Found - Request ID",
    "fly.dev":                "404 Not Found",
    "vercel.app":             "The deployment could not be found",
    "pages.dev":              "not found",
    "azurewebsites.net":      "404 Web Site not found",
    "cloudapp.azure.com":     "404 Web Site not found",
    "trafficmanager.net":     "404 Web Site not found",
    "blob.core.windows.net":  "BlobServiceProperties",
    "cloudapp.net":           "404 Not Found",
    "elasticbeanstalk.com":   "404 Not Found",
    "cloudfront.net":         "ERROR: The request could not be satisfied",

    # SaaS / support
    "helpscoutdocs.com":      "No settings were found",
    "zendesk.com":            "Help Center Closed",
    "freshdesk.com":          "There is no such account",
    "helpjuice.com":          "We could not find what you're looking for",
    "uservoice.com":          "This UserVoice subdomain is currently available",
    "desk.com":               "Please try again or try Desk.com free for 14 days",
    "intercom.help":          "Uh oh. That page doesn't exist.",
    "statuspage.io":          "You are being redirected",
    "aftership.com":          "Oops.",
    "readme.io":              "Project doesnt exist... yet!",

    # E-commerce
    "shopify.com":            "Sorry, this shop is currently unavailable",
    "myshopify.com":          "Sorry, this shop is currently unavailable",
    "bigcartel.com":          "Oops! You've stumbled upon a shop that is no longer around",

    # Marketing / CMS
    "hubspot.net":            "This page isn't available",
    "hubspotpagebuilder.com": "This page isn't available",
    "wpengine.com":           "The site you were looking for couldn't be found",
    "kinsta.cloud":           "No Site For This Domain",
    "webflow.io":             "The page you are looking for doesn't exist",
    "instapage.com":          "Looks Like You're Lost",
    "unbounce.com":           "The requested URL was not found on this server",
    "strikingly.com":         "page not found",
    "cargo.site":             "If you're the site owner",
    "cargocollective.com":    "If you're the site owner",
    "squarespace.com":        "No Such Account",
    "format.com":             "Sorry, this page is no longer available",
    "tilda.ws":               "Domain is not connected",
    "mailchimpsites.com":     "There is no site here",
    "campaignmonitor.com":    "Double-check the URL",

    # Community / docs
    "tumblr.com":             "Whatever you were looking for doesn't currently exist",
    "launchrock.com":         "It looks like you may have taken a wrong turn",
    "pingdom.com":            "Sorry, couldn't find the status page",
    "agilecrm.com":           "Sorry, this page is no longer available",
}


# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

def normalize(domain: str) -> str:
    """Strip protocol, path, port, and trailing dots. Preserves all subdomains."""
    domain = domain.lower().strip()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0]   # drop path
    domain = domain.split(":")[0]   # drop port
    domain = domain.rstrip(".")
    return domain


def get_registrable_domain(subdomain: str) -> str:
    """
    Returns a best-effort registrable domain (last two labels).
    e.g. shop.example.com → example.com
    Note: naively assumes 2-label TLDs; good enough for CTF/personal use.
    """
    parts = subdomain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else subdomain


# ──────────────────────────────────────────────
#  DNS
# ──────────────────────────────────────────────

def resolve_cname_chain(subdomain: str) -> list[str]:
    """
    Follows the full CNAME chain and returns all targets in order.
    Returns an empty list if there is no CNAME.
    """
    chain: list[str] = []
    current = subdomain
    visited: set[str] = set()

    while True:
        if current in visited:
            _warn("Circular CNAME chain detected — stopping.")
            break
        visited.add(current)

        try:
            result = dns.resolver.resolve(current, "CNAME")
            target = str(result[0].target).rstrip(".")
            chain.append(target)
            current = target

        except dns.resolver.NoAnswer:
            break  # legitimate end of chain
        except dns.resolver.NXDOMAIN:
            _info(f"'{current}' → NXDOMAIN — possibly dangling CNAME.")
            break
        except Exception as e:
            _warn(f"DNS error resolving '{current}': {e}")
            break

    return chain


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
        "subdomain":        subdomain,
        "cname_chain":      cname_chain,
        "vulnerable":       vulnerable,
        "confidence":       confidence,
        "reason":           reason,
        "service":          service,
        "matched_cname":    matched_cname,
        "fingerprint":      fingerprint,
        "http_status":      http_status,
        "wildcard_detected": wildcard,
    }


# ──────────────────────────────────────────────
#  Core check
# ──────────────────────────────────────────────

def check_subdomain(subdomain: str) -> dict:
    # Always normalize input here so callers don't have to
    subdomain = normalize(subdomain)
    _info(f"Checking: {subdomain}")

    wildcard = is_wildcard_domain(subdomain)

    cname_chain = resolve_cname_chain(subdomain)

    if not cname_chain:
        if has_a_record(subdomain):
            reason = "Points directly to an IP (A record) — not an external service"
        else:
            reason = "No DNS records found. This subdomain likely does not exist."
        _info(reason)
        return make_result(subdomain, [], False, reason, confidence="n/a", wildcard=wildcard)

    chain_display = " → ".join([subdomain] + cname_chain)
    _info(f"CNAME chain: {chain_display}")

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

def _info(msg: str):  print(f"[*] {msg}")
def _warn(msg: str):  print(f"[!] {msg}", file=sys.stderr)


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
        prog="subtake",
        description="Check whether a subdomain is vulnerable to takeover.",
        epilog="Examples:\n"
               "  python subtake.py shop.example.com\n"
               "  python subtake.py https://blog.example.com\n",
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
        help="Skip wildcard DNS detection (faster, less safe)",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Allow timeout override
    global TIMEOUT
    TIMEOUT = args.timeout

    subdomain = normalize(args.subdomain)
    if not subdomain:
        parser.error("No subdomain provided.")

    result = check_subdomain(subdomain)
    print_result(result)

    # Exit 1 if vulnerable — useful for scripting
    sys.exit(1 if result["vulnerable"] else 0)


if __name__ == "__main__":
    main()