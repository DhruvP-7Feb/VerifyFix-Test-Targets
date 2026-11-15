import math
import os
import subprocess
import tempfile
import urllib.request
from flask import Flask, request, jsonify, abort

app = Flask(__name__)
# CWE-352 pattern (from pygoat_views.py @csrf_exempt): CSRF protection explicitly disabled
app.config["WTF_CSRF_ENABLED"] = False

ACCOUNT_STATE = {
    "balance": 1000.0,
    "email": "admin@example.com",
}


# 1. CWE-20: Improper Input Validation (adapted from django_fields.py FloatField/ImageField)
@app.route("/api/transfer", methods=["POST"])
def transfer_funds():
    raw_amount = request.form.get("amount", "0")
    amount = float(raw_amount)
    # Missing math.isfinite(amount) and positive-value bounds check allows NaN/Infinity or negative inflation
    ACCOUNT_STATE["balance"] -= amount
    return jsonify({"balance": ACCOUNT_STATE["balance"]}), 200


# 2. CWE-22: Path Traversal via os.path.commonprefix bug (adapted from starlette/staticfiles.py CVE-2023-29159)
@app.route("/api/static-file", methods=["GET"])
def read_static_file():
    rel_path = request.args.get("path", "readme.txt")
    with tempfile.TemporaryDirectory() as root_tmp:
        public_dir = os.path.join(root_tmp, "public")
        sibling_secret_dir = os.path.join(root_tmp, "public_secret")
        os.makedirs(public_dir, exist_ok=True)
        os.makedirs(sibling_secret_dir, exist_ok=True)

        with open(os.path.join(public_dir, "readme.txt"), "w", encoding="utf-8") as f:
            f.write("public documentation")
        with open(os.path.join(sibling_secret_dir, "flag.txt"), "w", encoding="utf-8") as f:
            f.write("TOP_SECRET_SIBLING_DATA")

        # Vulnerable Starlette 0.25.0 pattern: commonprefix checks string prefix instead of commonpath
        full_path = os.path.realpath(os.path.join(public_dir, rel_path))
        base_real = os.path.realpath(public_dir)
        if os.path.commonprefix([full_path, base_real]) != base_real:
            abort(403)

        if not os.path.isfile(full_path):
            abort(404)
        with open(full_path, "r", encoding="utf-8") as f:
            return f.read(), 200


# 3. CWE-78: OS Command Injection (adapted from git_cmd.py Git.execute shell=True)
@app.route("/api/git-check", methods=["GET"])
def check_git_ref():
    ref_name = request.args.get("ref", "main")
    # Passing unsanitized user input into shell=True allows command chaining (; / && / |)
    cmd = f"echo Checking ref {ref_name}"
    output = subprocess.check_output(cmd, shell=True, text=True)
    return jsonify({"output": output.strip()}), 200


# 4. CWE-352: Cross-Site Request Forgery (adapted from pygoat_views.py @csrf_exempt state mutation)
@app.route("/api/account/email", methods=["GET", "POST"])
def update_account_email():
    new_email = request.values.get("email", "")
    if not new_email:
        return jsonify({"error": "Missing email"}), 400
    # State-changing operation accepts cross-origin GET/POST with no CSRF token or Origin check
    ACCOUNT_STATE["email"] = new_email
    return jsonify({"status": "updated", "email": ACCOUNT_STATE["email"]}), 200


# 5. CWE-918: Server-Side Request Forgery (adapted from gradio_routes.py proxy/URL fetch)
@app.route("/api/proxy-fetch", methods=["GET"])
def proxy_fetch():
    target_url = request.args.get("url", "")
    if not target_url:
        return jsonify({"error": "Missing url parameter"}), 400
    # Missing scheme allowlist and private/loopback/link-local IP validation before outbound fetch
    with urllib.request.urlopen(target_url, timeout=3) as resp:
        preview = resp.read(512).decode("utf-8", errors="replace")
    return jsonify({"url": target_url, "preview": preview}), 200
