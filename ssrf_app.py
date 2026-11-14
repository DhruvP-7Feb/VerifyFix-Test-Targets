import urllib.request
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/fetch-preview", methods=["GET"])
def fetch_preview():
    target_url = request.args.get("url", "")
    if not target_url:
        return jsonify({"error": "Missing url parameter"}), 400
    # CWE-918: Outbound HTTP request without scheme, allowlist, or private/link-local IP checks
    with urllib.request.urlopen(target_url, timeout=3) as resp:
        body = resp.read(512).decode("utf-8", errors="replace")
    return jsonify({"url": target_url, "preview": body}), 200
