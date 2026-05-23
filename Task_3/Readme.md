# 🔐 Task 3 — Secure Coding Review (Flask Login App)

> **CodeAlpha Cyber Security Internship**  
> A secure Flask login application demonstrating identification and remediation of 8 real-world web security vulnerabilities.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Demo Credentials](#demo-credentials)
- [Vulnerability Audit](#vulnerability-audit)
- [Security Features](#security-features)
- [API & Routes](#api--routes)
- [Project Structure](#project-structure)
- [Environment Variables](#environment-variables)
- [Testing the Fixes](#testing-the-fixes)
- [What Was Fixed vs Original](#what-was-fixed-vs-original)
- [OWASP Coverage](#owasp-coverage)

---

## Overview

`Task3_Perfect_SecureCoding.py` is a **before/after security demonstration** built around a Flask login web application.

The original vulnerable code (`Task3.py`) contained a critically insecure login endpoint. This file fixes **8 distinct vulnerabilities** identified through code review — ranging from a Critical SQL Injection to missing HTTP security headers — and documents every fix with inline comments explaining the attack, the impact, and the exact code change that prevents it.

---

## Requirements

| Package | Version | Purpose |
|---|---|---|
| `flask` | ≥ 2.0 | Web framework |
| `bcrypt` | ≥ 4.0 | Password hashing |

**System requirements:**
- Python 3.7+
- SQLite (built into Python — no install needed)

---

## Installation

### Step 1 — Install dependencies

```bash
pip install flask bcrypt
```

### Step 2 — Run the application

```bash
python Task3_Perfect_SecureCoding.py
```

### Step 3 — Open in browser

```
http://127.0.0.1:5000
```

The database (`users_secure.db`) is created automatically on first run with two demo accounts.

---

## Usage

1. Open `http://127.0.0.1:5000` in your browser
2. Log in using the demo credentials below
3. Try the SQL injection payload in the username field to confirm it is blocked
4. Try entering the wrong password 5 times to trigger the rate-limit lockout

---

## Demo Credentials

| Username | Password | Data |
|---|---|---|
| `admin` | `SecurePass@99` | Admin dashboard access granted. |
| `testuser` | `Hello#World1` | Welcome back, test user. |

> Passwords are stored as **bcrypt hashes** — they are never visible in the database, even to the developer.

---

## Vulnerability Audit

Eight vulnerabilities were identified in the original `Task3.py` and fixed in this version:

---

### VULN-1 — SQL Injection `CRITICAL`

**Original vulnerable code:**
```python
cursor.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
```

**Attack payload that bypasses login:**
```
Username:  ' OR '1'='1
Password:  anything
```
The query becomes:
```sql
SELECT * FROM users WHERE username='' OR '1'='1' AND password='anything'
-- '1'='1' is always TRUE → attacker logs in as the first user (admin)
```

**Fix — parameterized query:**
```python
cursor.execute(
    "SELECT password_hash, data FROM users WHERE username = ?",
    (username,)
)
# The '?' placeholder is handled by the database driver
# User input is NEVER interpreted as SQL
```

---

### VULN-2 — Plaintext Password Storage `HIGH`

**Original:**
```python
INSERT INTO users (username, password) VALUES ('admin', 'password123')
# Passwords visible as plain text in the database file
```

**Fix — bcrypt hashing:**
```python
import bcrypt

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

# Stored as: $2b$12$eW5TE... (irreversible hash)
# Even if the DB is stolen, passwords cannot be recovered
```

---

### VULN-3 — No CSRF Protection `HIGH`

**Attack scenario:**  
An attacker hosts a malicious page that auto-submits a form to `http://yoursite.com/login`. When a logged-in victim visits that page, their browser sends the request with their session cookies — the attacker hijacks the action.

**Fix — CSRF token:**
```python
# Generate token and store in session
session["csrf_token"] = secrets.token_hex(32)

# Embed in HTML form (hidden field)
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">

# Validate on every POST
submitted = request.form.get("csrf_token")
stored    = session.get("csrf_token")
if not secrets.compare_digest(submitted, stored):
    abort(403)
```

---

### VULN-4 — No Brute Force Protection `HIGH`

**Attack scenario:**  
An automated tool tries millions of password combinations at thousands per second. Without rate limiting, the only limit is network speed.

**Fix — IP-based rate limiting:**
```python
MAX_ATTEMPTS    = 5       # failed attempts before lockout
LOCKOUT_SECONDS = 300     # 5-minute lockout

login_attempts = defaultdict(lambda: {"attempts": 0, "locked_until": 0})

def is_rate_limited(ip):
    record = login_attempts[ip]
    if record["locked_until"] > time.time():
        return True, int(record["locked_until"] - time.time())
    return False, 0

def record_failed_attempt(ip):
    record = login_attempts[ip]
    record["attempts"] += 1
    if record["attempts"] >= MAX_ATTEMPTS:
        record["locked_until"] = time.time() + LOCKOUT_SECONDS
```

---

### VULN-5 — Username Enumeration `MEDIUM`

**Problem:**  
Different error messages for "user not found" vs "wrong password" tell the attacker which usernames exist.

**Fix — generic message for all failures:**
```python
# Same message whether username OR password is wrong
message = "Invalid username or password."

# Never say:
#   "User not found"       ← reveals username doesn't exist
#   "Wrong password"       ← reveals username DOES exist
```

---

### VULN-6 — No Input Validation `MEDIUM`

**Fix — server-side validation:**
```python
import re

def validate_input(username: str, password: str):
    if not username or not password:
        return False, "Both fields are required."
    if len(username) > 64 or len(password) > 128:
        return False, "Input exceeds maximum allowed length."
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username may only contain letters, digits, and underscores."
    return True, ""
```

---

### VULN-7 — Debug Mode Enabled in Production `MEDIUM`

**Original:**
```python
app.run(debug=True, port=5000)
# With debug=True, any unhandled exception shows an interactive Python shell
# in the browser — full code execution for anyone who triggers an error
```

**Fix — environment variable control:**
```python
debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
app.run(debug=debug_mode, port=5000)

# Development:  FLASK_DEBUG=true python Task3_Perfect_SecureCoding.py
# Production:   python Task3_Perfect_SecureCoding.py   (debug=False by default)
```

---

### VULN-8 — Missing Security Headers `LOW`

**Fix — added via `after_request` hook:**
```python
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"]        = "DENY"           # Prevents clickjacking
    response.headers["X-Content-Type-Options"] = "nosniff"        # Prevents MIME sniffing
    response.headers["X-XSS-Protection"]       = "1; mode=block"  # Enables browser XSS filter
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'none';"
    )
    return response
```

---

## Security Features

| Feature | Implementation | Benefit |
|---|---|---|
| **Parameterized SQL** | `cursor.execute("... WHERE username = ?", (username,))` | SQL injection impossible |
| **bcrypt hashing** | `bcrypt.hashpw(plain, bcrypt.gensalt())` | Passwords irrecoverable even if DB stolen |
| **CSRF tokens** | `secrets.token_hex(32)` in session + form field | Prevents cross-site request forgery |
| **Rate limiting** | 5 attempts → 5-minute IP lockout | Blocks brute-force attacks |
| **Generic errors** | Same message for all login failures | No username enumeration |
| **Input validation** | Length caps + regex whitelist | Prevents DoS and injection via input |
| **Debug disabled** | `FLASK_DEBUG` env var, defaults `False` | No Python REPL exposed on errors |
| **Security headers** | `after_request` hook | Blocks clickjacking, XSS, MIME attacks |
| **Timing-safe compare** | `secrets.compare_digest()` for CSRF | Prevents timing side-channel on tokens |
| **DB connection cleanup** | `finally: conn.close()` | No resource leaks |

---

## API & Routes

### `GET /`
Renders the login form with a fresh CSRF token.

**Response:** HTML login page

---

### `POST /`
Processes login credentials.

**Form fields:**

| Field | Type | Validation |
|---|---|---|
| `username` | `text` | 3–64 chars, `[a-zA-Z0-9_]` only |
| `password` | `password` | 1–128 chars |
| `csrf_token` | `hidden` | Must match session token |

**Responses:**

| Condition | Message |
|---|---|
| Rate limited | `Too many failed attempts. Please wait N seconds.` |
| Invalid CSRF | HTTP 403 Forbidden |
| Empty fields | `Both fields are required.` |
| Input too long | `Input exceeds maximum allowed length.` |
| Invalid chars in username | `Username may only contain letters, digits, and underscores.` |
| Wrong credentials | `Invalid username or password. (N attempt(s) remaining)` |
| Correct credentials | `Login successful! Welcome, <username>.` |

---

## Project Structure

```
Task3_Perfect_SecureCoding.py     ← Main application (this file)
users_secure.db                   ← SQLite database (auto-created on first run)
README_Task3_SecureCoding.md      ← This file
```

### Database Schema

```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,        -- bcrypt hash, never plaintext
    data          TEXT,                    -- user-specific data shown after login
    created_at    TEXT    DEFAULT CURRENT_TIMESTAMP
);
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FLASK_DEBUG` | `false` | Set to `true` to enable debug mode (development only) |
| `FLASK_SECRET_KEY` | random hex | Override the session signing key (set this in production) |

### Setting environment variables

**Linux / macOS:**
```bash
export FLASK_SECRET_KEY="your-long-random-secret-key-here"
export FLASK_DEBUG=false
python Task3_Perfect_SecureCoding.py
```

**Windows (Command Prompt):**
```cmd
set FLASK_SECRET_KEY=your-long-random-secret-key-here
set FLASK_DEBUG=false
python Task3_Perfect_SecureCoding.py
```

**Windows (PowerShell):**
```powershell
$env:FLASK_SECRET_KEY = "your-long-random-secret-key-here"
$env:FLASK_DEBUG = "false"
python Task3_Perfect_SecureCoding.py
```

---

## Testing the Fixes

### Test 1 — SQL Injection (should be BLOCKED)
1. Open `http://127.0.0.1:5000`
2. Enter username: `' OR '1'='1`
3. Enter any password
4. Click Login
5. **Expected result:** `Invalid username or password.` — NOT a successful login

### Test 2 — Valid Login (should SUCCEED)
1. Enter username: `admin`
2. Enter password: `SecurePass@99`
3. **Expected result:** `Login successful! Welcome, admin.`

### Test 3 — Rate Limiting (should LOCK after 5 failures)
1. Enter wrong credentials 5 times in a row
2. **Expected result:** `Too many failed attempts. Please wait 300 seconds.`
3. Subsequent attempts from the same IP are blocked for 5 minutes

### Test 4 — CSRF Protection (should return 403)
```bash
# Attempt a POST request without a valid CSRF token
curl -X POST http://127.0.0.1:5000/ \
     -d "username=admin&password=SecurePass@99"
# Expected: HTTP 403 Forbidden
```

### Test 5 — Security Headers (should be present)
```bash
curl -I http://127.0.0.1:5000/
# Expected headers in response:
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Content-Security-Policy: default-src 'self'; ...
```

### Test 6 — Input Length Validation (should be REJECTED)
1. Enter a username longer than 64 characters
2. **Expected result:** `Input exceeds maximum allowed length.`

---

## What Was Fixed vs Original

| Vulnerability | Severity | `Task3.py` (Original) | `Task3_Perfect_SecureCoding.py` (Fixed) |
|---|---|---|---|
| SQL Injection | 🔴 CRITICAL | `f"...WHERE username='{username}'"` | Parameterized `?` query |
| Password storage | 🟠 HIGH | Plaintext in DB | bcrypt hash |
| CSRF | 🟠 HIGH | No token | `secrets.token_hex(32)` in session + form |
| Brute force | 🟠 HIGH | Unlimited attempts | 5 attempts → 5-min IP lockout |
| Username enumeration | 🟡 MEDIUM | N/A (avoided by accident) | Explicitly enforced generic message |
| Input validation | 🟡 MEDIUM | None | Length + regex whitelist |
| Debug mode | 🟡 MEDIUM | `debug=True` hardcoded | `FLASK_DEBUG` env var, default `False` |
| Security headers | 🟢 LOW | None | 5 headers via `after_request` |

---

## OWASP Coverage

This fix addresses items from the [OWASP Top 10](https://owasp.org/www-project-top-ten/):

| OWASP Category | Vulnerability Fixed |
|---|---|
| A01 — Broken Access Control | CSRF token prevents unauthorized actions |
| A02 — Cryptographic Failures | bcrypt replaces plaintext password storage |
| A03 — Injection | Parameterized queries prevent SQL injection |
| A05 — Security Misconfiguration | Debug mode disabled; security headers added |
| A07 — Identification & Auth Failures | Rate limiting + bcrypt + generic errors |
| A09 — Security Logging & Monitoring | DB errors logged server-side, not exposed to user |

---

## Troubleshooting

| Problem | Cause | Solution |
|---|---|---|
| `ModuleNotFoundError: flask` | Flask not installed | `pip install flask` |
| `ModuleNotFoundError: bcrypt` | bcrypt not installed | `pip install bcrypt` |
| Port 5000 already in use | Another process on port 5000 | Change `port=5000` to `port=5001` in the script |
| `OperationalError: no such table` | DB corrupted | Delete `users_secure.db` and restart |
| Login always fails | Wrong demo credentials | Use `admin` / `SecurePass@99` exactly |
| Rate limit not resetting | In-memory store cleared on restart | Restart the server to reset all lockouts |

---

*CodeAlpha Cyber Security Internship — Task 3*  
*Secure Coding Review — Flask Login Application*
