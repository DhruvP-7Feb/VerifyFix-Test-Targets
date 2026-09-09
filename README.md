# 🎯 VerifyFix Vulnerability Test Targets

This repository contains standalone test cases and sample vulnerable micro-services for testing **VerifyFix**'s vulnerability discovery, critic triage, sandbox execution, and remediation pipeline.

## 📌 Included Vulnerabilities

1. **CWE-89: SQL Injection** (`vulnerable_service.py`)
   - Direct string interpolation in SQL queries.
   - Includes exploitable vs. parameterized implementations.
   - Exploit: `' OR '1'='1`

2. **CWE-79: Reflected Cross-Site Scripting (XSS)** (`vulnerable_service.py`)
   - Unescaped user parameter reflected in HTML output.
   - Includes exploitable vs. HTML-escaped implementations.
   - Exploit: `<script>alert('XSS')</script>`

## 🧪 Local Testing

Run the exploit verification suite:
```bash
python test_exploits.py
```

Run the interactive web server:
```bash
pip install flask
python vulnerable_app.py
```
