from flask import Flask, request, render_template_string

app = Flask(__name__)

FAANG_DATA = {
    "facebook": {"company": "Facebook", "ceo": "Mark Zuckerberg"},
    "amazon": {"company": "Amazon", "ceo": "Andy Jassy"},
    "apple": {"company": "Apple", "ceo": "Tim Cook"},
    "netflix": {"company": "Netflix", "ceo": "Ted Sarandos"},
    "google": {"company": "Google", "ceo": "Sundar Pichai"},
}


@app.route("/lab1", methods=["GET"])
def lab1():
    q = request.args.get("q", "")
    if not q:
        return "<h3>Search FAANG companies using ?q=</h3>"

    q_lower = q.lower()
    if q_lower in FAANG_DATA:
        data = FAANG_DATA[q_lower]
        return f"<h2>{data['company']}</h2><p>CEO: {data['ceo']}</p>"
    else:
        # Direct unescaped interpolation into HTML template string (CWE-79)
        html = f"<h3>No results found for: {q}</h3>"
        return render_template_string(html)


@app.route("/health")
def health_check():
    return "OK", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5006)