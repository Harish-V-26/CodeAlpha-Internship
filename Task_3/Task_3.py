"""
╔══════════════════════════════════════════════════════════════════╗
║        TASK 3 — SECURE CODING REVIEW (Flask Login App)          ║
║        CodeAlpha Cyber Security Internship                       ║
╚══════════════════════════════════════════════════════════════════╝

VULNERABILITY AUDIT REPORT
════════════════════════════════════════════════════════════════════

ORIGINAL VULNERABLE CODE (Task3.py) — Issues Found:
────────────────────────────────────────────────────

  [VULN-1] SQL INJECTION (CRITICAL)
    Line 14: cursor.execute(f"SELECT * FROM users WHERE username='{username}'
             AND password='{password}'")
    Impact : Attacker can bypass login with payload: ' OR '1'='1 --
             Can dump/delete entire database. Full authentication bypass.
    Fix    : Use parameterized queries with ? placeholders.

  [VULN-2] PLAINTEXT PASSWORD STORAGE (HIGH)
    Passwords stored as plain strings in the database.
    Impact : If DB is breached, all user passwords are immediately exposed.
             Also enables internal staff to read passwords.
    Fix    : Hash passwords with bcrypt before storing. Verify with
             bcrypt.checkpw() — never compare plaintext.

  [VULN-3] NO CSRF PROTECTION (HIGH)
    No CSRF token in the login form.
    Impact : An attacker can craft a malicious page that submits the login
             form on behalf of a victim (Cross-Site Request Forgery).
    Fix    : Use Flask-WTF or manually inject/validate a CSRF token.

  [VULN-4] MISSING RATE LIMITING / BRUTE FORCE PROTECTION (HIGH)
    No limit on login attempts.
    Impact : Attacker can try millions of password combinations
             (dictionary/brute-force attack) with no throttling.
    Fix    : Implement per-IP attempt counter with lockout after N failures.

  [VULN-5] GENERIC ERROR MESSAGE LEAKS LOGIN STATE (MEDIUM)
    Returning "Login successful!" vs "Login failed." confirms whether
    a username exists, enabling username enumeration.
    Fix    : Use the same generic message for all failure cases.

  [VULN-6] NO INPUT LENGTH VALIDATION (MEDIUM)
    No maximum length enforced on username/password fields.
    Impact : DoS via extremely long inputs; potential buffer issues.
    Fix    : Validate and cap input length server-side.

  [VULN-7] debug=True IN PRODUCTION (MEDIUM)
    app.run(debug=True) exposes an interactive debugger on error pages.
    Impact : Full Python REPL access to anyone who triggers an error.
    Fix    : Set debug=False; use environment variable to control it.

  [VULN-8] NO SECURITY HEADERS (LOW)
    No Content-Security-Policy, X-Frame-Options, X-Content-Type-Options.
    Impact : Allows clickjacking, MIME-sniffing, XSS escalation.
    Fix    : Add security headers via Flask after_request hook.

REMEDIATION SUMMARY TABLE
────────────────────────────────────────────────────
  VULN-1  SQL Injection         → Parameterized queries         ✅ Fixed
  VULN-2  Plaintext Passwords   → bcrypt hashing                ✅ Fixed
  VULN-3  CSRF                  → CSRF token validation         ✅ Fixed
  VULN-4  Brute Force           → Rate limiting + lockout       ✅ Fixed
  VULN-5  Username Enumeration  → Generic error messages        ✅ Fixed
  VULN-6  Input Validation      → Length + character checks     ✅ Fixed
  VULN-7  Debug Mode            → Env-variable controlled       ✅ Fixed
  VULN-8  Security Headers      → after_request headers         ✅ Fixed

INSTALL:
  pip install flask bcrypt
  (Flask-WTF is NOT required — CSRF handled manually below for clarity)

DEMO CREDENTIALS (created at startup):
  admin    / SecurePass@99
  testuser / Hello#World1
"""

import os
import secrets
import sqlite3
import time
from collections import defaultdict
from datetime import datetime
from functools import wraps

import bcrypt
from flask import Flask, request, render_template_string, session, abort

# ══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)

# Secret key for session signing — in production, store in environment variable
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DATABASE  = os.path.join(BASE_DIR, "users_secure.db")

# ══════════════════════════════════════════════════════════════════════════════
# RATE LIMITING — VULN-4 FIX
# ══════════════════════════════════════════════════════════════════════════════

MAX_ATTEMPTS    = 5        # max failed logins before lockout
LOCKOUT_SECONDS = 300      # 5-minute lockout window

# In-memory store: { ip: {"attempts": int, "locked_until": float} }
login_attempts = defaultdict(lambda: {"attempts": 0, "locked_until": 0})

def get_client_ip():
    """Get real client IP, respecting reverse proxy headers."""
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

def is_rate_limited(ip):
    record = login_attempts[ip]
    now    = time.time()
    if record["locked_until"] > now:
        return True, int(record["locked_until"] - now)
    return False, 0

def record_failed_attempt(ip):
    record = login_attempts[ip]
    record["attempts"] += 1
    if record["attempts"] >= MAX_ATTEMPTS:
        record["locked_until"] = time.time() + LOCKOUT_SECONDS
        record["attempts"]     = 0  # reset counter after lockout starts

def reset_attempts(ip):
    login_attempts[ip] = {"attempts": 0, "locked_until": 0}

# ══════════════════════════════════════════════════════════════════════════════
# DATABASE SETUP
# ══════════════════════════════════════════════════════════════════════════════

def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt (auto-salted)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

def init_db():
    """
    Create the users table and insert demo accounts.
    Passwords are stored as bcrypt hashes — NEVER plaintext.
    """
    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
        cur  = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                data          TEXT,
                created_at    TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Demo accounts — passwords stored as bcrypt hashes
        demo_users = [
            ("admin",    "SecurePass@99",  "Admin dashboard access granted."),
            ("testuser", "Hello#World1",   "Welcome back, test user."),
        ]
        for uname, plain, data in demo_users:
            cur.execute(
                "SELECT id FROM users WHERE username = ?", (uname,)
            )
            if not cur.fetchone():
                cur.execute(
                    "INSERT INTO users (username, password_hash, data) VALUES (?, ?, ?)",
                    (uname, hash_password(plain), data)
                )
        conn.commit()
        print("[DB] Initialized with hashed demo accounts.")
    except sqlite3.Error as e:
        print(f"[DB ERROR] {e}")
    finally:
        if conn:
            conn.close()

with app.app_context():
    init_db()

# ══════════════════════════════════════════════════════════════════════════════
# SECURITY HEADERS — VULN-8 FIX
# ══════════════════════════════════════════════════════════════════════════════

@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'none';"
    )
    return response

# ══════════════════════════════════════════════════════════════════════════════
# INPUT VALIDATION — VULN-6 FIX
# ══════════════════════════════════════════════════════════════════════════════

def validate_input(username: str, password: str):
    """
    Returns (is_valid: bool, error_message: str).
    Enforces length limits and basic character rules.
    """
    if not username or not password:
        return False, "Both fields are required."
    if len(username) > 64 or len(password) > 128:
        return False, "Input exceeds maximum allowed length."
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    # Restrict username to alphanumeric + underscore (no SQL-special chars)
    import re
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username may only contain letters, digits, and underscores."
    return True, ""

# ══════════════════════════════════════════════════════════════════════════════
# HTML TEMPLATE
# ══════════════════════════════════════════════════════════════════════════════

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure Login — CodeAlpha</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; }
    .input-field {
      box-shadow: none;
      appearance: none;
      border: 1px solid #d1d5db;
      border-radius: 0.5rem;
      width: 100%;
      padding: 0.5rem 0.75rem;
      color: #374151;
      line-height: 1.25;
    }
    .input-field:focus {
      outline: none;
      box-shadow: 0 0 0 3px rgba(59,130,246,0.3);
      border-color: #3b82f6;
    }
  </style>
</head>
<body class="bg-gray-50 min-h-screen flex items-center justify-center p-4">
  <div class="bg-white p-8 rounded-2xl shadow-xl w-full max-w-md">

    <!-- Header -->
    <div class="text-center mb-8">
      <div class="inline-flex items-center justify-center w-14 h-14 bg-blue-600 rounded-2xl mb-4">
        <svg class="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
        </svg>
      </div>
      <h1 class="text-2xl font-bold text-gray-800">Secure Login</h1>
      <p class="text-sm text-gray-500 mt-1">CodeAlpha — SQL Injection Demo</p>
    </div>

    <!-- Security badges -->
    <div class="grid grid-cols-2 gap-2 mb-6">
      {% for badge in [
        ("🔒", "Parameterized SQL"),
        ("🔑", "bcrypt Hashed"),
        ("🛡", "CSRF Protected"),
        ("⏱", "Rate Limited")
      ] %}
      <div class="flex items-center gap-2 bg-green-50 border border-green-200 rounded-lg px-3 py-2">
        <span class="text-base">{{ badge[0] }}</span>
        <span class="text-xs font-medium text-green-700">{{ badge[1] }}</span>
      </div>
      {% endfor %}
    </div>

    <!-- Form -->
    <form method="POST" action="/" novalidate>
      <!-- CSRF token — hidden field, validated server-side (VULN-3 FIX) -->
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">

      <div class="space-y-4">
        <div>
          <label for="username" class="block text-sm font-semibold text-gray-700 mb-1">
            Username
          </label>
          <input type="text" id="username" name="username"
                 class="input-field" required maxlength="64"
                 autocomplete="username" spellcheck="false">
        </div>
        <div>
          <label for="password" class="block text-sm font-semibold text-gray-700 mb-1">
            Password
          </label>
          <input type="password" id="password" name="password"
                 class="input-field" required maxlength="128"
                 autocomplete="current-password">
        </div>
      </div>

      <button type="submit"
              class="mt-6 w-full bg-blue-600 hover:bg-blue-700 text-white font-bold
                     py-2.5 px-4 rounded-xl transition duration-200 ease-in-out">
        Sign In
      </button>
    </form>

    <!-- Status message -->
    {% if message %}
    <div class="mt-5 p-3 rounded-xl text-center text-sm font-medium
                {% if success %}bg-green-50 border border-green-200 text-green-700
                {% else %}bg-red-50 border border-red-200 text-red-700{% endif %}">
      {{ message }}
    </div>
    {% endif %}

    <!-- User data (post-login) -->
    {% if user_data %}
    <div class="mt-3 p-3 rounded-xl bg-blue-50 border border-blue-200 text-sm text-blue-800">
      <span class="font-semibold">Your data:</span> {{ user_data }}
    </div>
    {% endif %}

    <!-- Demo hint -->
    <div class="mt-6 p-3 bg-gray-50 rounded-xl border border-gray-200 text-xs text-gray-500 text-center">
      Demo: <code>admin / SecurePass@99</code> &nbsp;|&nbsp;
      <code>testuser / Hello#World1</code>
    </div>
  </div>
</body>
</html>
"""

# ══════════════════════════════════════════════════════════════════════════════
# CSRF HELPERS — VULN-3 FIX
# ══════════════════════════════════════════════════════════════════════════════

def generate_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def validate_csrf_token(submitted: str) -> bool:
    stored = session.get("csrf_token")
    if not stored or not submitted:
        return False
    # Use secrets.compare_digest to prevent timing attacks
    return secrets.compare_digest(stored, submitted)

# ══════════════════════════════════════════════════════════════════════════════
# LOGIN ROUTE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET", "POST"])
def login():
    message   = None
    user_data = None
    success   = False

    # Always generate a CSRF token for the page
    csrf_token = generate_csrf_token()

    if request.method == "POST":
        ip = get_client_ip()

        # ── VULN-4: Rate limiting check ──────────────────────────────────────
        limited, wait_seconds = is_rate_limited(ip)
        if limited:
            message = f"Too many failed attempts. Please wait {wait_seconds} seconds."
            return render_template_string(
                LOGIN_HTML, message=message, success=False,
                user_data=None, csrf_token=csrf_token
            )

        # ── VULN-3: CSRF token validation ────────────────────────────────────
        submitted_token = request.form.get("csrf_token", "")
        if not validate_csrf_token(submitted_token):
            abort(403)  # Forbidden — CSRF mismatch

        # ── VULN-6: Input validation ─────────────────────────────────────────
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        valid, val_error = validate_input(username, password)
        if not valid:
            message = val_error
            return render_template_string(
                LOGIN_HTML, message=message, success=False,
                user_data=None, csrf_token=csrf_token
            )

        # ── Database lookup ──────────────────────────────────────────────────
        conn = None
        try:
            conn = sqlite3.connect(DATABASE)
            cur  = conn.cursor()

            # ── VULN-1 FIX: Parameterized query — user input NEVER touches SQL string
            cur.execute(
                "SELECT password_hash, data FROM users WHERE username = ?",
                (username,)
            )
            row = cur.fetchone()

            # ── VULN-2 FIX: bcrypt verification — never compare plaintext
            # ── VULN-5 FIX: Same generic message whether username or password is wrong
            if row and verify_password(password, row[0]):
                # Success
                reset_attempts(ip)
                user_data = row[1]
                success   = True
                message   = f"Login successful! Welcome, {username}."
                # Regenerate CSRF token after successful login (session fixation defense)
                session.pop("csrf_token", None)
                csrf_token = generate_csrf_token()
            else:
                # Failure — record attempt; use identical message for both cases
                record_failed_attempt(ip)
                attempts_left = MAX_ATTEMPTS - login_attempts[ip]["attempts"]
                message = f"Invalid username or password. ({max(attempts_left, 0)} attempt(s) remaining)"

        except sqlite3.Error as e:
            # ── VULN-1: Never expose DB error details to client
            print(f"[DB ERROR] {datetime.now()} — {e}")
            message = "A server error occurred. Please try again later."

        finally:
            if conn:
                conn.close()

    return render_template_string(
        LOGIN_HTML,
        message=message,
        success=success,
        user_data=user_data,
        csrf_token=csrf_token
    )

# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # ── VULN-7 FIX: Debug mode controlled by environment variable
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    print(f"[APP] Starting on http://127.0.0.1:5000  (debug={debug_mode})")
    app.run(debug=debug_mode, port=5000)
