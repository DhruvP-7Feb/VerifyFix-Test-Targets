"""
Vulnerable Service Module - Sample for VerifyFix Testing
-------------------------------------------------------
This module contains two intentional security vulnerabilities designed for testing
VerifyFix's Discovery, Critic, Sandbox Execution, and Remediation pipeline:

1. CWE-89: SQL Injection (in `find_user_by_username`)
2. CWE-79: Reflected Cross-Site Scripting (XSS) (in `render_search_results_page`)
"""

import sqlite3
import html
from typing import List, Dict, Any, Optional


# ============================================================================
# 1. CWE-89: SQL Injection Vulnerability
# ============================================================================

def init_sample_database() -> sqlite3.Connection:
    """Creates an in-memory SQLite database populated with demo accounts."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            api_secret TEXT NOT NULL
        )
    """)
    cursor.executemany(
        "INSERT INTO users (username, email, role, api_secret) VALUES (?, ?, ?, ?)",
        [
            ("admin", "admin@verifyfix.local", "administrator", "sec_token_9941_super_secret"),
            ("alice", "alice@example.com", "developer", "sec_token_1120_alice_key"),
            ("bob", "bob@example.com", "user", "sec_token_5532_bob_key"),
        ]
    )
    conn.commit()
    return conn


def find_user_by_username(db_conn: sqlite3.Connection, username: str) -> List[Dict[str, Any]]:
    """
    [VULNERABLE: CWE-89 SQL Injection]
    Retrieves user profile information by username.
    
    VULNERABILITY DETAILS:
    - User input `username` is directly interpolated into raw SQL via an f-string.
    - An attacker can inject SQL syntax to bypass authentication or dump secrets.
    
    SAMPLE EXPLOIT PAYLOAD:
      username = "admin' OR '1'='1"
      username = "' UNION SELECT id, username, email, role, api_secret FROM users --"
    """
    cursor = db_conn.cursor()
    
    # ❌ VULNERABLE CODE (Direct string concatenation into SQL query):
    query = f"SELECT id, username, email, role, api_secret FROM users WHERE username = '{username}'"
    cursor.execute(query)
    
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def find_user_by_username_secure(db_conn: sqlite3.Connection, username: str) -> List[Dict[str, Any]]:
    """
    [SECURE: Parameterized Query]
    Remediated version using parameter markers to prevent SQL injection.
    """
    cursor = db_conn.cursor()
    # ✅ SECURE CODE:
    query = "SELECT id, username, email, role, api_secret FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


# ============================================================================
# 2. CWE-79: Reflected Cross-Site Scripting (XSS) Vulnerability
# ============================================================================

def render_search_results_page(search_term: str, result_count: int) -> str:
    """
    [VULNERABLE: CWE-79 Reflected Cross-Site Scripting (XSS)]
    Builds an HTML search response banner.
    
    VULNERABILITY DETAILS:
    - User input `search_term` is interpolated into raw HTML without escaping.
    - If rendered by a browser, injected JavaScript tags will execute in the user's session.
    
    SAMPLE EXPLOIT PAYLOAD:
      search_term = "<script>alert('XSS-Exploited-VerifyFix')</script>"
      search_term = "<img src=x onerror=alert(document.cookie)>"
    """
    # ❌ VULNERABLE CODE (Unsanitized parameter concatenated into HTML output):
    html_output = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body>
        <div class="header">
            <h2>Query: {search_term}</h2>
            <p>Found {result_count} matching results for your query: <b>{search_term}</b></p>
        </div>
    </body>
    </html>
    """
    return html_output


def render_search_results_page_secure(search_term: str, result_count: int) -> str:
    """
    [SECURE: HTML-Escaped Output]
    Remediated version encoding HTML special characters (<, >, &, ", ').
    """
    # ✅ SECURE CODE:
    escaped_term = html.escape(search_term)
    html_output = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body>
        <div class="header">
            <h2>Query: {escaped_term}</h2>
            <p>Found {result_count} matching results for your query: <b>{escaped_term}</b></p>
        </div>
    </body>
    </html>
    """
    return html_output
