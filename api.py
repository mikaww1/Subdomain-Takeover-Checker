from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from main import check_subdomain, normalize

app = Flask(__name__)
CORS(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)


@app.route("/")
def index():
    return render_template("index.html")


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


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"error": "Too many requests — slow down and try again in a minute"}), 429


if __name__ == "__main__":
    app.run(debug=True)