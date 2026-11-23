from flask import Flask, jsonify, request
import os

from flask import Flask, jsonify, request, send_from_directory
from detector import PhishingDetector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10_000      # reject huge requests
detector = PhishingDetector()


@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")

@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/check", methods=["GET", "POST"])
def check():
    if request.method == "POST":
        url = str((request.get_json(silent=True) or {}).get("url", "")).strip()
    else:
        url = request.args.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL."}), 400
    if len(url) > 2000:
        return jsonify({"error": "That URL is too long."}), 400
    try:
        return jsonify(detector.analyze(url))
    except (ValueError, UnicodeError):
        return jsonify({"error": "That doesn't look like a valid URL."}), 400


if __name__ == "__main__":
    app.run(debug=True)