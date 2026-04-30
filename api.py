from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from main import check_subdomain, normalize
from flask import Response
from datetime import datetime

app = Flask(__name__)
CORS(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)



@app.route("/check", methods=["POST"])
@limiter.limit("10 per minute")
def check():
    data = request.get_json()

    if not data or not data.get("subdomain"):
        return jsonify({"error": "No subdomain provided"}), 400

    subdomain = normalize(data["subdomain"].strip())
    if not subdomain:
        return jsonify({"error": "Invalid subdomain"}), 400

    try:
        result = check_subdomain(subdomain)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/sitemap.xml")
def sitemap():
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://www.subdomainchecker.com/</loc>
    <lastmod>{datetime.today().strftime('%Y-%m-%d')}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://www.subdomainchecker.com/learn</loc>
    <lastmod>{datetime.today().strftime('%Y-%m-%d')}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>"""
    return Response(xml, mimetype="application/xml")

@app.route("/learn")
def learn():
    return render_template("learn.html")

@app.route("/")
def index():
    return render_template("index.html",
        page_title="Subdomain Takeover Checker — Free Online Tool",
        page_description="Free subdomain takeover checker. Detect vulnerable subdomains by following CNAME chains and fingerprinting 80+ services including Heroku, Vercel, AWS S3, Azure, Shopify and more.",
        page_heading='Subdomain<span>Checker</span>',
        page_subtitle="Detect subdomain takeover vulnerabilities instantly."
    )

@app.route("/subdomain-takeover-checker")
def subdomain_takeover_checker():
    return render_template("index.html",
        page_title="Subdomain Takeover Checker — Detect Vulnerable Subdomains",
        page_description="Free subdomain takeover checker. Instantly detect dangling CNAMEs across 80+ services including Heroku, Vercel, AWS S3 and more.",
        page_heading='Subdomain Takeover <span>Checker</span>',
        page_subtitle="Instantly detect subdomain takeover vulnerabilities for free."
    )

@app.route("/cname-vulnerability-checker")
def cname_checker():
    return render_template("index.html",
        page_title="CNAME Vulnerability Checker — Detect Dangling DNS Records",
        page_description="Check any subdomain for dangling CNAME records and takeover vulnerabilities. Free tool, no account required.",
        page_heading='CNAME Vulnerability <span>Checker</span>',
        page_subtitle="Detect dangling CNAME records and takeover vulnerabilities instantly."
    )

@app.route("/dangling-cname-checker")
def dangling_cname_checker():
    return render_template("index.html",
        page_title="Dangling CNAME Checker — Find Unclaimed DNS Records",
        page_description="Detect dangling CNAME records that could lead to subdomain takeover. Free checker for bug bounty hunters and developers.",
        page_heading='Dangling CNAME <span>Checker</span>',
        page_subtitle="Find unclaimed DNS records before attackers do."
    )

@app.route("/subdomain-vulnerability-scanner")
def subdomain_scanner():
    return render_template("index.html",
        page_title="Subdomain Vulnerability Scanner — Free Online Tool",
        page_description="Scan subdomains for takeover vulnerabilities. Follows full CNAME chains and fingerprints 80+ services. Free, no account required.",
        page_heading='Subdomain Vulnerability <span>Scanner</span>',
        page_subtitle="Scan for subdomain takeover vulnerabilities across 80+ services."
    )

@app.route("/subdomain-hijacking-checker")
def subdomain_hijacking_checker():
    return render_template("index.html",
        page_title="Subdomain Hijacking Checker — Detect & Prevent Takeovers",
        page_description="Check if your subdomains are vulnerable to hijacking. Detects dangling CNAMEs across 80+ services including AWS, Azure, Heroku and more.",
        page_heading='Subdomain Hijacking <span>Checker</span>',
        page_subtitle="Detect and prevent subdomain hijacking vulnerabilities."
    )


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"error": "Too many requests — slow down and try again in a minute"}), 429


if __name__ == "__main__":
    app.run(debug=True)