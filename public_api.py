from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from main import check_subdomain, normalize
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
CORS(app)

RAPIDAPI_SECRET = os.environ.get("RAPIDAPI_PROXY_SECRET", "")

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)

def verify_rapidapi(req):
    secret = req.headers.get("X-RapidAPI-Proxy-Secret", "")
    return secret == RAPIDAPI_SECRET


@app.route("/check", methods=["GET"])
@limiter.limit("30 per minute")
def check():
    if RAPIDAPI_SECRET and not verify_rapidapi(request):
        return jsonify({"error": "Forbidden"}), 403

    subdomain = request.args.get("subdomain", "").strip()
    if not subdomain:
        return jsonify({"error": "Missing required parameter: subdomain"}), 400

    subdomain = normalize(subdomain)
    if not subdomain:
        return jsonify({"error": "Invalid subdomain"}), 400

    try:
        result = check_subdomain(subdomain)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/bulk_check", methods=["POST"])
@limiter.limit("10 per minute")
def bulk_check():
    if RAPIDAPI_SECRET and not verify_rapidapi(request):
        return jsonify({"error": "Forbidden"}), 403

    data = request.get_json()
    if not data or "subdomains" not in data:
        return jsonify({"error": "Missing required field: subdomains"}), 400

    subdomains = data["subdomains"]
    if not isinstance(subdomains, list) or len(subdomains) == 0:
        return jsonify({"error": "subdomains must be a non-empty list"}), 400

    if len(subdomains) > 25:
        return jsonify({"error": "Maximum 25 subdomains per request"}), 400

    results = []
    for subdomain in subdomains:
        subdomain = normalize(subdomain.strip())
        if not subdomain:
            continue
        try:
            result = check_subdomain(subdomain)
            results.append(result)
        except Exception as e:
            results.append({"subdomain": subdomain, "error": str(e)})

    return jsonify({
        "total": len(results),
        "vulnerable_count": sum(1 for r in results if r.get("vulnerable")),
        "results": results
    })

@app.route("/enumerate", methods=["GET"])
@limiter.limit("10 per minute")
def enumerate_subdomains():
    if RAPIDAPI_SECRET and not verify_rapidapi(request):
        return jsonify({"error": "Forbidden"}), 403

    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Missing required parameter: domain"}), 400

    domain = normalize(domain)
    if not domain:
        return jsonify({"error": "Invalid domain"}), 400

    try:
        # Query crt.sh
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=15, headers=HEADERS)
        if resp.status_code != 200:
            return jsonify({"error": "crt.sh unavailable, try again later"}), 502

        entries = resp.json()

        # Extract unique subdomains
        subdomains = set()
        for entry in entries:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub and sub.endswith(domain) and sub != domain:
                    subdomains.add(sub.lower())

        subdomains = sorted(subdomains)

        return jsonify({
            "domain": domain,
            "total": len(subdomains),
            "subdomains": subdomains
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"error": "Rate limit exceeded"}), 429


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), debug=False)