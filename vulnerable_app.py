"""
Vulnerable Web Application - Flask Demo for VerifyFix
-----------------------------------------------------
Endpoints:
  1. GET /api/users/search?username=...   (Vulnerable to CWE-89 SQL Injection)
  2. GET /search?q=...                    (Vulnerable to CWE-79 Reflected XSS)
  3. GET /                                (API documentation & exploit test guide)
"""

from flask import Flask, request, jsonify, Response
from vulnerable_service import (
    init_sample_database,
    find_user_by_username,
    find_user_by_username_secure,
    render_search_results_page,
    render_search_results_page_secure
)

app = Flask(__name__)
db_conn = init_sample_database()


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "VerifyFix Vulnerability Test Target",
        "endpoints": [
            {
                "path": "/api/users/search?username=<input>",
                "vulnerability": "CWE-89 SQL Injection",
                "test_exploit": "/api/users/search?username=admin' OR '1'='1"
            },
            {
                "path": "/search?q=<input>",
                "vulnerability": "CWE-79 Reflected XSS",
                "test_exploit": "/search?q=<script>alert('XSS')</script>"
            }
        ]
    })


# ----------------------------------------------------------------------------
# 1. SQL Injection Route (CWE-89)
# ----------------------------------------------------------------------------
@app.route("/api/users/search", methods=["GET"])
def search_user_endpoint():
    username = request.args.get("username", "")
    mode = request.args.get("mode", "vulnerable")  # 'vulnerable' or 'secure'
    
    if not username:
        return jsonify({"error": "Missing 'username' query parameter"}), 400
        
    try:
        if mode == "secure":
            records = find_user_by_username_secure(db_conn, username)
        else:
            # ❌ Triggers CWE-89 SQL injection
            records = find_user_by_username(db_conn, username)
            
        return jsonify({
            "mode": mode,
            "query_input": username,
            "count": len(records),
            "users": records
        })
    except Exception as e:
        return jsonify({"error": str(e), "note": "SQL syntax error triggered by injection"}), 500


# ----------------------------------------------------------------------------
# 2. Reflected XSS Route (CWE-79)
# ----------------------------------------------------------------------------
@app.route("/search", methods=["GET"])
def search_page_endpoint():
    query = request.args.get("q", "")
    mode = request.args.get("mode", "vulnerable")
    
    if mode == "secure":
        html_content = render_search_results_page_secure(query, result_count=0)
    else:
        # ❌ Triggers CWE-79 Reflected Cross-Site Scripting
        html_content = render_search_results_page(query, result_count=0)
        
    return Response(html_content, mimetype="text/html")


if __name__ == "__main__":
    print("[*] Starting Vulnerable Test Server on http://127.0.0.1:5050 ...")
    app.run(host="127.0.0.1", port=5050, debug=True)
