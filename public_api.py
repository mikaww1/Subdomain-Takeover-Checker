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


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"error": "Rate limit exceeded"}), 429


if __name__ == "__main__":
    app.run(port=5001, debug=True)