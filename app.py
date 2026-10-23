
import os
import sqlite3
import hashlib
import secrets
import boto3
import subprocess
import tempfile
from pathlib import Path
from botocore.exceptions import ClientError
from cloudwatch_security import emit_security_event
from io import BytesIO
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, session,
    send_file, flash, abort, render_template_string
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "trustvault.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "private_uploads")
S3_BUCKET = os.environ.get("TRUSTVAULT_S3_BUCKET", "trustvault-3")
S3_BUCKET = os.environ.get("TRUSTVAULT_S3_BUCKET", "trustvault-3")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

SOFFICE_PATH = r"C:\Program Files\LibreOffice\program\soffice.com"

s3_client = boto3.client(
    "s3",
    region_name=AWS_REGION
)
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

s3_client = boto3.client(
    "s3",
    region_name=AWS_REGION
)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
S3_BUCKET = "trustvault-3"
AWS_REGION = "us-east-1"
s3 = boto3.client("s3", region_name=AWS_REGION)

app = Flask(__name__)
app.secret_key = os.environ.get(
    "TRUSTVAULT_SECRET_KEY",
    "local-development-secret-change-before-deployment"
)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    "pdf", "txt", "png", "jpg", "jpeg", "docx", "csv"
}

# --------------------------------------------------
# PREMIUM TRUSTVAULT LAYOUT
# --------------------------------------------------

BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} | TrustVault</title>
<style>
:root {
  --bg:#050b16;
  --panel:#0b1628;
  --panel2:#101f35;
  --line:#1c3350;
  --text:#edf5ff;
  --muted:#8ea5c2;
  --blue:#29b9ff;
  --purple:#8260ff;
  --green:#37e5b0;
  --red:#ff647c;
  --amber:#ffc66d;
}
* { box-sizing:border-box; }
body {
  margin:0;
  color:var(--text);
  background:
    radial-gradient(ellipse at 75% -10%,#13345a 0,transparent 42%),
    var(--bg);
  font-family:Inter,"Segoe UI",Arial,sans-serif;
  font-size:14px;
}
a { color:inherit; text-decoration:none; }
button,input,select { font:inherit; }
.layout { display:flex; min-height:100vh; }
.sidebar {
  width:245px; flex-shrink:0; padding:25px 16px;
  border-right:1px solid var(--line);
  background:#071120;
  display:flex; flex-direction:column;
}
.brand {
  display:flex; align-items:center; gap:11px;
  font-size:22px; font-weight:800; margin:0 10px 35px;
}
.brand-icon {
  width:39px;height:39px;border-radius:12px;
  display:grid;place-items:center;font-size:22px;
  background:linear-gradient(135deg,#12b9ff,#7653ff);
  box-shadow:0 0 25px #298cff35;
}
.brand span:last-child { color:var(--blue); }
.nav-label {
  color:#617a99;font-size:10px;font-weight:800;
  letter-spacing:2px;margin:12px 12px;
}
.nav {
  display:flex;align-items:center;gap:12px;
  padding:12px 13px;margin:3px 0;border-radius:9px;
  color:#a6bad4;transition:.2s;
}
.nav:hover { background:#10233c;color:white; }
.nav.active {
  background:linear-gradient(100deg,#174d85,#202b61);
  color:white;border:1px solid #245b91;
}
.nav-icon { width:22px;text-align:center;font-size:17px; }
.sidebar-bottom { margin-top:auto;padding-top:30px; }
.cloud-status {
  margin:18px 2px;padding:13px;border:1px solid var(--line);
  border-radius:12px;background:#0a192b;
}
.dot {
  display:inline-block;width:8px;height:8px;border-radius:50%;
  background:var(--green);margin-right:7px;
  box-shadow:0 0 10px #37e5b080;
}
.main { flex:1;min-width:0;padding:28px 34px 45px; }
.topbar {
  display:flex;align-items:center;justify-content:space-between;
  gap:16px;margin-bottom:30px;
}
.eyebrow {
  color:var(--blue);font-size:10px;letter-spacing:2px;
  font-weight:800;text-transform:uppercase;
}
h1 { font-size:29px;letter-spacing:-.7px;margin:5px 0; }
h2 { font-size:17px;margin:0 0 8px; }
h3 { font-size:14px;margin:0 0 8px; }
p { color:var(--muted);line-height:1.65; }
.muted { color:var(--muted); }
.small { font-size:12px; }
.user-chip {
  display:flex;align-items:center;gap:10px;
  border:1px solid var(--line);padding:9px 13px;
  border-radius:12px;background:#0b1829;
}
.avatar {
  width:34px;height:34px;border-radius:50%;
  background:linear-gradient(135deg,#29b9ff,#8260ff);
  display:grid;place-items:center;font-weight:800;
}
.grid { display:grid;gap:16px; }
.stats { grid-template-columns:repeat(4,minmax(0,1fr)); }
.stat,.card,.quick-card {
  border:1px solid var(--line);
  border-radius:15px;
  background:linear-gradient(145deg,#0d1d32,#091424);
}
.stat { padding:18px;min-width:0; }
.stat-top { display:flex;align-items:center;justify-content:space-between;gap:8px; }
.stat-icon {
  width:42px;height:42px;border-radius:12px;
  display:grid;place-items:center;font-size:21px;
  background:#12304c;color:var(--blue);
}
.stat-icon.green { background:#10352f;color:var(--green); }
.stat-icon.purple { background:#292047;color:#b9a4ff; }
.stat-icon.amber { background:#35291b;color:var(--amber); }
.stat-icon.red { background:#3a1d2b;color:var(--red); }
.stat-number { font-size:27px;font-weight:800;margin-top:14px; }
.stat-label { color:var(--muted);font-size:12px; }
.section { margin-top:27px; }
.section-head {
  display:flex;align-items:center;justify-content:space-between;
  gap:12px;margin-bottom:14px;
}
.quick-grid { grid-template-columns:repeat(4,minmax(0,1fr)); }
.quick-card { padding:20px;transition:.2s;display:block; }
.quick-card:hover {
  transform:translateY(-3px);border-color:#3676a9;
  box-shadow:0 10px 30px #0003;
}
.quick-icon { font-size:26px;margin-bottom:13px; }
.card { padding:20px; }
.table-wrap {
  overflow-x:auto;border:1px solid var(--line);
  border-radius:13px;background:#091525;
}
table { width:100%;border-collapse:collapse;min-width:650px; }
th {
  text-align:left;padding:14px 16px;
  color:#83a9d3;background:#102139;
  font-size:11px;letter-spacing:.5px;
}
td {
  padding:15px 16px;border-top:1px solid #182b42;
  color:#dce9f8;vertical-align:middle;
}
tr:hover td { background:#102139; }
.file-icon {
  display:inline-grid;place-items:center;
  width:34px;height:38px;border-radius:8px;
  background:#15395c;color:#75d7ff;
  margin-right:10px;font-size:18px;
}
.file-name { display:inline-flex;align-items:center; }
.btn {
  display:inline-flex;align-items:center;justify-content:center;
  gap:8px;padding:10px 15px;border-radius:9px;
  border:1px solid #2d547b;background:#10243a;
  color:#e8f3ff;cursor:pointer;font-weight:700;
}
.btn:hover { filter:brightness(1.2); }
.btn-primary {
  border:0;background:linear-gradient(100deg,#08a9ef,#7050f5);
  color:white;
}
.btn-danger { background:#411b2a;border-color:#773347;color:#ffb5c1; }
.btn-small {
  padding: 9px 13px;
  font-size: 13px;
  font-weight: 600;
  white-space: nowrap;
  cursor: pointer;
}form.inline { display:inline; }
input,select {
  display:block;width:100%;padding:12px 13px;
  margin:7px 0 16px;background:#061222;
  color:var(--text);border:1px solid #29425f;border-radius:9px;
}
label { color:#b7c9e0;font-size:12px;font-weight:700; }
.badge {
  display:inline-flex;align-items:center;gap:6px;
  padding:5px 9px;border-radius:20px;font-size:11px;
  font-weight:700;background:#16302e;color:var(--green);
}
.badge.red { background:#3c202b;color:#ff9eae; }
.badge.amber { background:#3b2e1b;color:#ffd18a; }
.badge.blue { background:#152d49;color:#8fd8ff; }
.notice {
  padding:13px 16px;border:1px solid var(--line);
  background:#102139;border-radius:10px;margin:12px 0;
}
.empty { text-align:center;padding:45px 15px;color:var(--muted); }
.empty-icon { font-size:36px;margin-bottom:10px; }
.footer { margin-top:35px;color:#536b89;font-size:11px; }
.login-wrap {
  min-height:100vh;display:grid;
  grid-template-columns:1fr 1fr;align-items:center;
  gap:35px;max-width:1150px;margin:auto;padding:35px;
}
.login-brand { text-align:center; }
.hero-shield {
  font-size:100px;margin:20px auto;
  filter:drop-shadow(0 0 25px #278fff55);
}
.login-card {
  border:1px solid var(--line);border-radius:20px;
  background:linear-gradient(145deg,#102139,#091424);
  padding:35px;box-shadow:0 25px 80px #0004;
}
.flash { padding:12px 15px;border-radius:9px;background:#182d43;margin:12px 0; }
.error-hero { font-size:58px;color:var(--red); }
@media(max-width:1050px) {
  .sidebar { width:205px; }
  .main { padding:24px 20px; }
  .stats,.quick-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
}
@media(max-width:700px) {
  .layout { display:block; }
  .sidebar { width:100%;padding:15px; }
  .brand { margin:0 8px 15px; }
  .sidebar .nav-label,.sidebar-bottom,.cloud-status { display:none; }
  .sidebar nav { display:flex;flex-wrap:wrap;gap:4px; }
  .nav { padding:9px;font-size:12px; }
  .main { padding:20px 13px; }
  .stats,.quick-grid { grid-template-columns:1fr 1fr; }
  .login-wrap { grid-template-columns:1fr;padding:18px; }
  .login-brand { display:none; }
  h1 { font-size:24px; }
}
/* Admin Security Center styling */
#admin-access form {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

#admin-access select {
  min-width: 170px;
  max-width: 260px;
}

#admin-access button {
  min-height: 36px;
  margin: 2px;
}

#admin-access table th,
#admin-access table td {
  padding: 12px;
  vertical-align: middle;
}
</style>
</head>
<body>
{% if login_page %}
  <div class="login-wrap">
    <div class="login-brand">
      <div class="brand" style="justify-content:center">
        <span class="brand-icon">⛨</span>
        <span style="color:white">Trust<span>Vault</span></span>
      </div>
      <div class="hero-shield">🛡️</div>
      <h1>Your Documents. Our Priority.</h1>
      <p>Secure storage · Controlled access · Full audit trail</p>
      <p>☁ Private storage &nbsp; ◈ Access control &nbsp; ◷ Audit trail</p>
    </div>
    <main>
      {{ content|safe }}
    </main>
  </div>
{% else %}
  <div class="layout">
    <aside class="sidebar">
      <a class="brand" href="{{ url_for('home') }}">
        <span class="brand-icon">⛨</span>
        <span style="color:white">Trust<span>Vault</span></span>
      </a>
      <div class="nav-label">WORKSPACE</div>
      <nav>
        <a class="nav {{ 'active' if active=='home' else '' }}" href="{{ url_for('home') }}"><span class="nav-icon">⌂</span>Dashboard</a>
        <a class="nav {{ 'active' if active=='mydocs' else '' }}" href="{{ url_for('my_documents') }}"><span class="nav-icon">▤</span>My Documents</a>
        <a class="nav {{ 'active' if active=='upload' else '' }}" href="{{ url_for('upload_document') }}"><span class="nav-icon">⇧</span>Upload Document</a>
        <a class="nav {{ 'active' if active=='shared' else '' }}" href="{{ url_for('shared_documents') }}"><span class="nav-icon">◉</span>Shared With Me</a>
        <a class="nav {{ 'active' if active=='audit' else '' }}" href="{{ url_for('audit_logs') }}"><span class="nav-icon">◷</span>Audit Trail</a>
      </nav>
      <div class="nav-label">SECURITY</div>
      <nav>
        <a class="nav {{ 'active' if active=='security' else '' }}" href="{{ url_for('home') }}{{ '#admin-access' if session.get('role') == 'admin' else '#security' }}"><span class="nav-icon">🛡</span>Security Center</a>
      </nav>
      <div class="sidebar-bottom">
        <div class="cloud-status">
          <div><span class="dot"></span><b>Local app active</b></div>
          <p class="small" style="margin-bottom:0">AWS status is not verified yet.</p>
        </div>
        <a class="nav" href="{{ url_for('logout') }}"><span class="nav-icon">⇥</span>Sign out</a>
      </div>
    </aside>
    <main class="main">
      <header class="topbar">
        <div>
          <div class="eyebrow">SECURE DOCUMENT WORKSPACE</div>
          <h1>{{ title }}</h1>
          <div class="muted small">{{ subtitle }}</div>
        </div>
        <div class="user-chip">
          <div class="avatar">{{ username[:1]|upper }}</div>
          <div><b>{{ username }}</b><div class="muted small">{{ role|capitalize }}</div></div>
        </div>
      </header>
      {% for message in get_flashed_messages() %}
        <div class="flash">{{ message }}</div>
      {% endfor %}
      {{ content|safe }}
      <div class="footer">TRUSTVAULT · PRIVATE BY DESIGN · ACCESS IS ALWAYS CHECKED</div>
    </main>
  </div>
{% endif %}
</body>
</html>
"""


def render_page(title, content_template, active="home",
                subtitle="Access your documents securely",
                login_page=False, **context):
    rendered_content = render_template_string(
        content_template, **context
    )
    return render_template_string(
        BASE_TEMPLATE,
        title=title,
        subtitle=subtitle,
        content=rendered_content,
        active=active,
        login_page=login_page,
        username=session.get("username", ""),
        role=session.get("role", "guest"),
    )


# --------------------------------------------------
# DATABASE AND SECURITY HELPERS
# --------------------------------------------------

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    conn = get_db_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                owner TEXT NOT NULL,
                category TEXT NOT NULL,
                sha256 TEXT,
                stored_filename TEXT,
                owner_id INTEGER,
                uploaded_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS document_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                permission TEXT NOT NULL DEFAULT 'read',
                user_id INTEGER,
                UNIQUE(document_id, username)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                document_id INTEGER,
                details TEXT,
                result TEXT NOT NULL
            )
        """)

        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(documents)")
        }
        for name, definition in [
            ("sha256", "TEXT"),
            ("stored_filename", "TEXT"),
            ("owner_id", "INTEGER"),
            ("uploaded_at", "TEXT"),
            ("storage_backend", "TEXT NOT NULL DEFAULT 'local'"),
        ]:
            if name not in columns:
                conn.execute(
                    f"ALTER TABLE documents ADD COLUMN {name} {definition}"
                )

        pcols = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(document_permissions)"
            )
        }
        if "user_id" not in pcols:
            conn.execute(
                "ALTER TABLE document_permissions ADD COLUMN user_id INTEGER"
            )

        conn.execute("""
            UPDATE documents
            SET owner_id = (
                SELECT id FROM users WHERE users.username = documents.owner
            )
            WHERE owner_id IS NULL
        """)
        conn.execute("""
            UPDATE documents
            SET stored_filename = filename
            WHERE stored_filename IS NULL
        """)
        conn.execute("""
            UPDATE document_permissions
            SET user_id = (
                SELECT id FROM users
                WHERE users.username = document_permissions.username
            )
            WHERE user_id IS NULL
        """)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def log_event(username, action, document_id=None,
              details="", result="SUCCESS"):
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO audit_logs
            (timestamp, username, action, document_id, details, result)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            utc_now(), username, action, document_id, details, result
        ))
        conn.commit()
    finally:
        conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user_id = session.get("user_id")

        if not user_id:
            return redirect(url_for("login"))

        conn = get_db_connection()
        try:
            user = conn.execute(
                """
                SELECT id, username, role, account_status
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
        finally:
            conn.close()

        # User no longer exists: invalidate the session.
        if not user:
            session.clear()
            return redirect(url_for("login"))

        # Reject accounts that are pending, suspended, or otherwise
        # not approved, even if they logged in previously.
        if (
            "account_status" in user.keys()
            and user["account_status"] != "approved"
        ):
            session.clear()
            return redirect(url_for("login"))

        # Refresh the identity and role from the current database record.
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]

        return view(*args, **kwargs)

    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def document_path(stored_filename):
    if not stored_filename or os.path.basename(stored_filename) != stored_filename:
        abort(404)
    return os.path.join(UPLOAD_FOLDER, stored_filename)


def calculate_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_document(document_id):
    conn = get_db_connection()
    try:
        return conn.execute(
            "SELECT * FROM documents WHERE id=?",
            (document_id,)
        ).fetchone()
    finally:
        conn.close()


def can_manage_document(doc):
    return (
        session.get("role") == "admin"
        or (
            session.get("role") == "owner"
            and doc["owner_id"] == session.get("user_id")
        )
    )

# --------------------------------------------------
# PART 2: LOGIN, DASHBOARD, AND DOCUMENT LIST
# --------------------------------------------------



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password:
            flash("Please enter a username and password.")
        elif len(username) < 3:
            flash("Username must contain at least 3 characters.")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.")
        elif password != confirm_password:
            flash("Passwords do not match.")
        else:
            conn = get_db_connection()
            try:
                existing = conn.execute(
                    "SELECT id FROM users WHERE username = ?",
                    (username,)
                ).fetchone()

                if existing:
                    flash("That username is already registered.")
                else:
                    conn.execute(
                        """
                        INSERT INTO users
                            (username, password_hash, role, account_status)
                        VALUES (?, ?, 'viewer', 'pending')
                        """,
                        (username, generate_password_hash(password))
                    )
                    conn.commit()
                    log_event(
                        username,
                        "REGISTER",
                        details="New account awaiting admin approval"
                    )
                    return render_page(
                        "Registration Submitted",
                        """
                        <div class="login-card">
                          <h1>Registration submitted</h1>
                          <p>Your account has been created and is awaiting
                             administrator approval.</p>
                          <a class="btn btn-primary" href="/login">
                            Back to Login
                          </a>
                        </div>
                        """,
                        login_page=True
                    )
            finally:
                conn.close()

    return render_page(
        "Create Account",
        """
        <div class="login-card">
          <div class="eyebrow">TRUSTVAULT REGISTRATION</div>
          <h1>Create account</h1>
          <p>Create your account to request secure vault access.</p>
          {% for message in get_flashed_messages() %}
            <div class="flash">{{ message }}</div>
          {% endfor %}
          <form method="post">
            <label>USERNAME</label>
            <input name="username" minlength="3"
                   placeholder="Choose a username" required>
            <label>PASSWORD</label>
            <input type="password" name="password" minlength="8"
                   placeholder="At least 8 characters" required>
            <label>CONFIRM PASSWORD</label>
            <input type="password" name="confirm_password" minlength="8"
                   placeholder="Enter password again" required>
            <button class="btn btn-primary"
                    style="width:100%;margin-top:10px">
              Create account
            </button>
          </form>
          <p class="small">
            Already registered? <a href="/login">Sign in</a>
          </p>
        </div>
        """,
        login_page=True
    )



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        try:
            user = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            ).fetchone()
        finally:
            conn.close()

        if user and check_password_hash(
            user["password_hash"], password
        ):
            if (
                "account_status" in user.keys()
                and user["account_status"] != "approved"
            ):
                flash("Your account is awaiting admin approval.")
                return render_page(
                    "Welcome Back",
                    """
                    <div class="login-card">
                      <h1>Account Pending</h1>
                      <p>Your account has not been approved by an administrator yet.</p>
                      <a class="btn btn-primary" href="/login">Back to Login</a>
                    </div>
                    """,
                    login_page=True
                )

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            log_event(username, "LOGIN")
            return redirect(url_for("home"))

        log_event(
            username or "unknown",
            "LOGIN",
            details="Invalid login attempt",
            result="DENIED"
        )
        flash("Invalid username or password.")

    return render_page(
        "Welcome Back",
        """
        <div class="login-card">
          <div class="eyebrow">TRUSTVAULT AUTHENTICATION</div>
          <h1>Welcome back</h1>
          <p>Sign in to access your secure document vault.</p>
          {% for message in get_flashed_messages() %}
            <div class="flash">{{ message }}</div>
          {% endfor %}
          <form method="post">
            <label>USERNAME</label>
            <input name="username" placeholder="Enter username" required>
            <label>PASSWORD</label>
            <input type="password" name="password"
                   placeholder="Enter password" required>
            <button class="btn btn-primary"
                    style="width:100%;margin-top:10px">
              🔐 &nbsp; Sign in securely
            </button>
          </form>
          <p class="small">Access is checked for every document request.</p>
          <p class="small" style="margin-top:14px">
  New to TrustVault? <a href="/register">Create an account</a>
</p>
        </div>
        """,
        login_page=True
    )
@app.route("/logout")
@login_required
def logout():
    username = session.get("username", "unknown")
    log_event(username, "LOGOUT")
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/")
@login_required
def home():
    username = session["username"]
    role = session["role"]
    user_id = session["user_id"]
    access_users = []
    access_docs = []
    access_grants = []

    conn = get_db_connection()
    try:
        if role == "admin":
            docs = conn.execute("""
                SELECT * FROM documents ORDER BY id DESC LIMIT 8
            """).fetchall()

            total_docs = conn.execute(
                "SELECT COUNT(*) FROM documents"
            ).fetchone()[0]

            total_users = conn.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()[0]

            total_events = conn.execute(
                "SELECT COUNT(*) FROM audit_logs"
            ).fetchone()[0]

            denied_events = conn.execute("""
                SELECT COUNT(*) FROM audit_logs
                WHERE result='DENIED'
            """).fetchone()[0]
            # Admin dashboard: load users and document permissions
            access_users = conn.execute("""
                SELECT id, username, role, account_status
                FROM users
                ORDER BY username
            """).fetchall()

            access_docs = conn.execute("""
                SELECT id, filename, owner
                FROM documents
                ORDER BY filename
            """).fetchall()

           
            access_grants = conn.execute("""
                SELECT p.document_id, p.username, d.filename
                FROM document_permissions p
                JOIN documents d ON d.id = p.document_id
                ORDER BY d.filename, p.username
            """).fetchall()           

            stats = [
                ("♙", "Total Users", total_users, "blue"),
                ("▤", "Total Documents", total_docs, "green"),
                ("◷", "Audit Events", total_events, "amber"),
                ("⛨", "Denied Events", denied_events, "red"),
            ]

        elif role == "owner":
            docs = conn.execute("""
                SELECT * FROM documents
                WHERE owner_id=?
                ORDER BY id DESC LIMIT 8
            """, (user_id,)).fetchall()

            total_docs = conn.execute("""
                SELECT COUNT(*) FROM documents WHERE owner_id=?
            """, (user_id,)).fetchone()[0]

            shared_count = conn.execute("""
                SELECT COUNT(*) FROM document_permissions p
                JOIN documents d ON d.id=p.document_id
                WHERE d.owner_id=?
            """, (user_id,)).fetchone()[0]

            stats = [
                ("▤", "My Documents", total_docs, "blue"),
                ("♧", "Active Shares", shared_count, "green"),
                ("⇧", "Upload Files", "Ready", "purple"),
                ("⛨", "Access Control", "Active", "amber"),
            ]

        else:
            docs = conn.execute("""
                SELECT d.*
                FROM documents d
                JOIN document_permissions p
                  ON p.document_id=d.id
                WHERE p.username=? AND p.permission IN ('read', 'edit')
                ORDER BY d.id DESC LIMIT 8
            """, (username,)).fetchall()

            shared_count = conn.execute("""
                SELECT COUNT(*) FROM document_permissions
                WHERE username=? AND permission='read'
            """, (username,)).fetchone()[0]

            stats = [
                ("◉", "My Access", shared_count, "blue"),
                ("◷", "Recent Activity", "Tracked", "amber"),
                ("♧", "Shared Files", shared_count, "green"),
                ("⛨", "Security Status", "Protected", "purple"),
            ]

    finally:
        conn.close()

    stat_html = ""
    for symbol, label, value, color in stats:
        stat_html += """
        <div class="stat">
          <div class="stat-top">
            <span class="stat-label">LABEL</span>
            <span class="stat-icon COLOR">SYMBOL</span>
          </div>
          <div class="stat-number">VALUE</div>
          <div class="stat-label">LABEL</div>
        </div>
        """.replace("SYMBOL", str(symbol)).replace(
            "COLOR", str(color)
        ).replace("VALUE", str(value)).replace(
            "LABEL", str(label)
        )

    if role in ("owner", "admin"):
        quick_actions = [
            ("⇧", "Upload Document", "Add a file to your vault",
             "upload_document"),
            ("♧", "Manage Documents", "Review your document access",
             "my_documents"),
            ("◉", "Shared With Me", "View documents shared with you",
             "shared_documents"),
            ("◷", "Audit Trail", "Review recorded activity",
             "audit_logs"),
        ]
    else:
        quick_actions = [
            ("◉", "View Shared Files", "See documents shared with you",
             "shared_documents"),
            ("▤", "My Access", "Review available documents",
             "shared_documents"),
            ("⛨", "Security", "Your access is checked per request",
             "home"),
            ("◷", "Activity", "See your accessible documents",
             "shared_documents"),
        ]

    action_html = ""
    for symbol, label, description, endpoint in quick_actions:
        action_html += """
        <a class="quick-card" href="LINK">
          <div class="quick-icon">SYMBOL</div>
          <h3>LABEL</h3>
          <div class="muted small">DESCRIPTION</div>
        </a>
        """.replace("LINK", url_for(endpoint)).replace(
            "SYMBOL", symbol
        ).replace("LABEL", label).replace(
            "DESCRIPTION", description
        )

    rows = ""
    for doc in docs:
        filename = doc["filename"]
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        symbol = {
            "pdf": "📕",
            "docx": "📘",
            "txt": "📄",
            "csv": "📊",
            "png": "🖼",
            "jpg": "🖼",
            "jpeg": "🖼",
        }.get(ext, "📄")

        rows += """
        <tr>
          <td><span class="file-name">
            <span class="file-icon">ICON</span>NAME
          </span></td>
          <td>CATEGORY</td>
          <td>OWNER</td>
         <td><a class="btn btn-small" href="DOWNLOAD">Download Document</a></td>
        </tr>
        """.replace("ICON", symbol).replace(
            "NAME", filename
        ).replace("CATEGORY", doc["category"]).replace(
            "OWNER", doc["owner"]
        ).replace(
            "DOWNLOAD",
            url_for("download_document", document_id=doc["id"])
        )

    if not rows:
        rows = """
        <tr><td colspan="4">
          <div class="empty">
            <div class="empty-icon">▤</div>
            <h3>Your vault is ready</h3>
            <p>Documents you can access will appear here.</p>
          </div>
        </td></tr>
        """


    access_panel_html = ""

    if role == "admin":
        from markupsafe import escape

        user_rows = ""
        for item in access_users:
            uid = item["id"]
            uname = escape(item["username"])
            user_role = escape(item["role"])
            status = escape(item["account_status"])

            user_rows += f"""
            <tr>
              <td>{uname}</td>
              <td>{user_role}</td>
              <td>{status}</td>
              <td>
                <form method="post"
                      action="/admin/users/{uid}/status"
                      style="display:flex;gap:6px;flex-wrap:wrap">
                  <button class="btn btn-small"
                          name="status" value="approved" type="submit">
                    Approve
                  </button>
                  <button class="btn btn-danger btn-small"
                          name="status" value="rejected" type="submit">
                    Reject
                  </button>
                </form>
              </td>
            </tr>
            """

        if not user_rows:
            user_rows = (
                '<tr><td colspan="4">No users found.</td></tr>'
            )

        doc_rows = ""
        for item in access_docs:
            doc_id = item["id"]
            doc_name = escape(item["filename"])
            doc_owner = escape(item["owner"])

            options = ""
            for user in access_users:
                if user["username"] != item["owner"]:
                    safe_username = escape(user["username"])
                    options += (
                        f'<option value="{safe_username}">'
                        f'{safe_username}</option>'
                    )

            doc_rows += f"""
            <tr>
              <td>{doc_name}</td>
              <td>{doc_owner}</td>
              <td>
                <form method="post" action="/share/{doc_id}"
                      style="display:flex;gap:6px;flex-wrap:wrap">
                  <select name="username" required>
                    <option value="">Choose user</option>
                    {options}
                  </select>
                  <button class="btn btn-small" type="submit">
                    Grant read
                  </button>
                </form>
              </td>
            </tr>
            """

        if not doc_rows:
            doc_rows = (
                '<tr><td colspan="3">No documents found.</td></tr>'
            )

        grant_rows = ""
        for grant in access_grants:
            doc_id = grant["document_id"]
            grant_user = escape(grant["username"])
            grant_name = escape(grant["filename"])

            grant_rows += f"""
            <tr>
              <td>{grant_name}</td>
              <td>{grant_user}</td>
              <td>
                <form method="post"
                      action="/revoke/{doc_id}/{grant_user}">
                  <button class="btn btn-danger btn-small" type="submit">
                    Revoke access
                  </button>
                </form>
              </td>
            </tr>
            """

        if not grant_rows:
            grant_rows = (
                '<tr><td colspan="3">No access grants found.</td></tr>'
            )

        access_panel_html = f"""
        <section class="section" id="admin-access">
          <div class="section-head">
            <div>
              <h2>User Approval &amp; Access Management</h2>
              <p class="muted small">
                Approve accounts, grant document access, and revoke access.
              </p>
            </div>
          </div>

          <h3>Manage users</h3>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>USERNAME</th><th>ROLE</th>
                  <th>STATUS</th><th>ACTION</th>
                </tr>
              </thead>
              <tbody>{user_rows}</tbody>
            </table>
          </div>

          <h3 style="margin-top:24px">Grant document access</h3>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>DOCUMENT</th><th>OWNER</th>
                  <th>GRANT READ ACCESS</th>
                </tr>
              </thead>
              <tbody>{doc_rows}</tbody>
            </table>
          </div>

          <h3 style="margin-top:24px">Existing access grants</h3>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>DOCUMENT</th><th>USER</th><th>ACTION</th>
                </tr>
              </thead>
              <tbody>{grant_rows}</tbody>
            </table>
          </div>
        </section>
        """

    content = """
    <div class="grid stats">STATS</div>

    <section class="section" id="security">
      <div class="section-head">
        <h2>Quick Actions</h2>
        <span class="badge">⛨ Role-based access</span>
      </div>
      <div class="grid quick-grid">ACTIONS</div>
    </section>

    ADMIN_ACCESS_PANEL

    <section class="section">
      <div class="section-head">
        <div>
          <h2>Recent Documents</h2>
          <div class="muted small">Files available to your account</div>
        </div>
        <a href="MYDOCS">View all →</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>DOCUMENT</th>
              <th>CATEGORY</th>
              <th>OWNER</th>
              <th>ACTION</th>
            </tr>
          </thead>
          <tbody>ROWS</tbody>
        </table>
      </div>
    </section>
    """.replace("STATS", stat_html).replace(
        "ACTIONS", action_html
    ).replace(
        "ADMIN_ACCESS_PANEL", access_panel_html
    ).replace("ROWS", rows).replace(
        "MYDOCS", url_for(
            "my_documents" if role in ("owner", "admin")
            else "shared_documents"
        )
    )

    return render_page(
        "Admin Security Center" if role == "admin"
        else "Owner Dashboard" if role == "owner"
        else "Viewer Dashboard",
        content,
        active="home",
        subtitle="Monitor your documents, access, and security"
    )


# --------------------------------------------------
# DOCUMENT LIST HELPERS
# --------------------------------------------------

def accessible_documents():
    conn = get_db_connection()
    try:
        if session["role"] == "admin":
            return conn.execute("""
                SELECT * FROM documents ORDER BY id DESC
            """).fetchall()

        if session["role"] == "owner":
            return conn.execute("""
                SELECT * FROM documents
                WHERE owner_id=? ORDER BY id DESC
            """, (session["user_id"],)).fetchall()

        return conn.execute("""
            SELECT d.*
            FROM documents d
            JOIN document_permissions p ON p.document_id=d.id
            WHERE p.username=? AND p.permission='read'
            ORDER BY d.id DESC
        """, (session["username"],)).fetchall()
    finally:
        conn.close()


@app.route("/my-docs")
@role_required("owner", "admin")
def my_documents():
    docs = accessible_documents()
    rows = ""

    for doc in docs:
        rows += """
        <tr>
          <td><span class="file-name">
            <span class="file-icon">▤</span>NAME
          </span></td>
          <td>CATEGORY</td>
          <td><a class="btn btn-small"
                 href="SHARE">♧ Manage Access</a></td>
          <td><a class="btn btn-small"
                 href="DOWNLOAD">↓ Download</a></td>
          <td>
            <form class="inline" method="post" action="DELETE"
                  onsubmit="return confirm('Delete this document?')">
              <button class="btn btn-danger btn-small">Delete</button>
            </form>
          </td>
        </tr>
        """.replace("NAME", doc["filename"]).replace(
            "CATEGORY", doc["category"]
        ).replace("SHARE", url_for(
            "share_document", document_id=doc["id"]
        )).replace("VIEW", url_for(
    "view_document", document_id=doc["id"]
)).replace("DELETE", url_for(
            "delete_document", document_id=doc["id"]
        ))

    if not rows:
        rows = '<tr><td colspan="5">No documents found.</td></tr>'

    content = """
    <div class="section-head">
      <h2>Document Vault</h2>
      <a class="btn btn-primary" href="UPLOAD">＋ Upload Document</a>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>DOCUMENT</th><th>CATEGORY</th>
          <th>ACCESS</th><th>DOWNLOAD</th><th>DELETE</th>
        </tr></thead>
        <tbody>ROWS</tbody>
      </table>
    </div>
    """.replace("ROWS", rows).replace(
        "UPLOAD", url_for("upload_document")
    )

    return render_page(
        "My Documents", content,
        active="mydocs",
        subtitle="Organize documents and manage access"
    )

# --------------------------------------------------
# PART 3: UPLOAD, SHARED FILES, ACCESS CONTROL
# --------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
@role_required("owner", "admin")
def upload_document():
    if request.method == "POST":
        uploaded = request.files.get("file")
        category = request.form.get("category", "General").strip()

        if not uploaded or not uploaded.filename:
            flash("Please select a document.")
            return redirect(url_for("upload_document"))

        filename = secure_filename(uploaded.filename)

        if not filename or not allowed_file(filename):
            flash("This file type is not allowed.")
            return redirect(url_for("upload_document"))


        stored = secrets.token_hex(16) + "_" + filename
        s3_uploaded = False

        try:
            # Read the selected file and calculate its SHA-256 hash.
            file_data = uploaded.stream.read()
            digest = hashlib.sha256(file_data).hexdigest()

            if not file_data:
                flash("The selected document is empty.")
                return redirect(url_for("upload_document"))

            # Upload the document to private S3 with server-side encryption.
            s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=stored,
                Body=file_data,
                ServerSideEncryption="AES256",
                ContentType=uploaded.mimetype or "application/octet-stream"
            )
            s3_uploaded = True

            # Save document metadata in the existing SQLite database.
            conn = get_db_connection()

            try:
                cursor = conn.execute("""
                    INSERT INTO documents
                    (filename, owner, category, sha256,
                     stored_filename, owner_id, uploaded_at,
                     storage_backend)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    filename,
                    session["username"],
                    category or "General",
                    digest,
                    stored,
                    session["user_id"],
                    utc_now(),
                    "s3"
                ))

                document_id = cursor.lastrowid
                conn.commit()

            except Exception:
                conn.rollback()
                raise

            finally:
                conn.close()

            log_event(
                session["username"],
                "UPLOAD",
                document_id,
                "Uploaded " + filename + " to private S3"
            )

            flash("Document uploaded securely to AWS S3.")
            return redirect(url_for("my_documents"))

        except Exception:
            # Remove the S3 object if saving its database record failed.
            if s3_uploaded:
                try:
                    s3_client.delete_object(
                        Bucket=S3_BUCKET,
                        Key=stored
                    )
                except Exception:
                    app.logger.exception(
                        "S3 cleanup failed for key %s", stored
                    )

            app.logger.exception("Upload failed")
            flash("Upload failed. Check the application log.")
            return redirect(url_for("upload_document"))


    content = """
    <div class="grid" style="grid-template-columns:1.2fr 1fr">
      <div class="card">
        <div class="eyebrow">PRIVATE DOCUMENT STORAGE</div>
        <h2>Upload to your vault</h2>
        <p>Choose a document and organize it by category.</p>
        <form method="post" enctype="multipart/form-data">
          <label>SELECT DOCUMENT</label>
          <input type="file" name="file" required>
          <label>DOCUMENT CATEGORY</label>
          <select name="category">
            <option>General</option>
            <option>Business</option>
            <option>Legal</option>
            <option>Technical</option>
            <option>Finance</option>
            <option>Personal</option>
          </select>
          <button class="btn btn-primary">🔐 Upload Securely</button>
        </form>
      </div>
      <div class="card">
        <div class="stat-icon green">⛨</div>
        <h2>Security checks</h2>
        <p>✓ File type allowlist</p>
        <p>✓ 10 MB maximum upload size</p>
        <p>✓ SHA-256 integrity hash</p>
        <p>✓ Private local file storage</p>
        <p class="small">AWS S3 encryption is not configured by this local upload page.</p>
      </div>
    </div>
    """
    return render_page(
        "Upload Document", content, active="upload",
        subtitle="Add a file to your private document vault"
    )


# --------------------------------------------------
# SHARED WITH ME
# --------------------------------------------------

@app.route("/shared")
@role_required("viewer", "owner", "admin")
def shared_documents():
    conn = get_db_connection()
    try:
        docs = conn.execute("""
            SELECT d.*, u.username AS owner_name, p.permission AS shared_permission p.permission AS shared_permission
            FROM documents d
            JOIN document_permissions p ON p.document_id=d.id
            JOIN users u ON u.id=d.owner_id
            WHERE p.username=? AND p.permission='read'
            ORDER BY d.id DESC
        """, (session["username"],)).fetchall()
    finally:
        conn.close()

    rows = ""
    for doc in docs:
        filename = doc["filename"]
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        symbol = {
            "pdf": "📕", "docx": "📘", "txt": "📄",
            "csv": "📊", "png": "🖼", "jpg": "🖼", "jpeg": "🖼"
        }.get(ext, "📄")

        rows += """
        <tr>
          <td><span class="file-name">
            <span class="file-icon">ICON</span>NAME
          </span></td>
          <td>OWNER</td>
          <td><span class="badge blue">PERMISSION_LABEL</span></td>
          <td><a class="btn btn-small" href="DOWNLOAD">Download Document</a></td>
        </tr>
               """.replace("ICON", symbol).replace(
            "NAME", filename
        ).replace(
    "PERMISSION_LABEL",
    "Edit access" if doc["shared_permission"] == "edit"
    else "Read only"
)
    if not rows:
        rows = """
        <tr><td colspan="4">
          <div class="empty">
            <div class="empty-icon">◉</div>
            <h3>No shared documents yet</h3>
            <p>When an owner grants you access, documents will appear here.</p>
          </div>
        </td></tr>
        """

    content = """
    <div class="card">
      <div class="section-head">
        <div>
          <h2>Documents shared with your account</h2>
          <p class="small">Only current read permissions are displayed.</p>
        </div>
        <span class="badge">⛨ Access checked</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>DOCUMENT</th><th>OWNER</th>
            <th>PERMISSION</th><th>ACTION</th>
          </tr></thead>
          <tbody>ROWS</tbody>
        </table>
      </div>
    </div>
    """.replace("ROWS", rows)

    return render_page(
        "Viewer Document Access", content, active="shared",
        subtitle="Browse documents that have been explicitly shared with you"
    )


# --------------------------------------------------
# SECURE DOWNLOAD
# --------------------------------------------------

# --------------------------------------------------
# SECURE VIEW-ONLY PDF PREVIEW
# --------------------------------------------------


@app.route("/view/<int:document_id>")
@login_required
def view_document(document_id):
    doc = get_document(document_id)

    if not doc:
        abort(404)

    username = session["username"]
    is_uploader = doc["owner_id"] == session["user_id"]

    conn = get_db_connection()
    try:
        permission = conn.execute("""
            SELECT id FROM document_permissions
            WHERE document_id = ?
              AND username = ?
              AND permission IN ('read', 'edit')
        """, (document_id, username)).fetchone()
    finally:
        conn.close()

    if not (is_uploader or permission):
        log_event(
            username, "VIEW", document_id,
            "Unauthorized view attempt", "DENIED"
        )
        abort(403)

    extension = os.path.splitext(doc["filename"])[1].lower()

    if extension not in (".pdf", ".docx"):
        return "Preview supports PDF and DOCX files only.", 415

    log_event(username, "VIEW", document_id, "Document preview opened")

    content = """
    <div class="card">
      <div class="section-head">
        <div>
          <h2>Document Preview</h2>
          <p class="small">
            Read-only preview. Saving or copying cannot be fully prevented.
          </p>
        </div>
        <a class="btn btn-small" href="/shared">Back</a>
      </div>
      <iframe
        src="PDF_URL#toolbar=0&navpanes=0"
        title="Document preview"
        style="display:block;width:100%;height:75vh;border:1px solid #ddd;border-radius:8px;"
      ></iframe>
    </div>
    """.replace(
        "PDF_URL",
        url_for("preview_pdf", document_id=document_id)
    )

    return render_page(
        "Document Preview",
        content,
        active="shared",
        subtitle="Secure document viewing"
    )


@app.route("/preview-pdf/<int:document_id>")
@login_required
def preview_pdf(document_id):
    doc = get_document(document_id)

    if not doc:
        abort(404)

    username = session["username"]
    is_uploader = doc["owner_id"] == session["user_id"]

    conn = get_db_connection()
    try:
        permission = conn.execute("""
            SELECT id FROM document_permissions
            WHERE document_id = ?
              AND username = ?
              AND permission = 'read'
        """, (document_id, username)).fetchone()
    finally:
        conn.close()

    if not (is_uploader or permission):
        log_event(
            username, "VIEW", document_id,
            "Unauthorized preview request", "DENIED"
        )
        abort(403)

    extension = os.path.splitext(doc["filename"])[1].lower()

    if extension not in (".pdf", ".docx"):
        abort(415)

    # Read the original document from private storage.
    try:
        if doc["storage_backend"] == "s3":
            result = s3_client.get_object(
                Bucket=S3_BUCKET,
                Key=doc["stored_filename"]
            )
            file_data = result["Body"].read()
        else:
            path = document_path(doc["stored_filename"])

            if not os.path.isfile(path):
                abort(404)

            with open(path, "rb") as file:
                file_data = file.read()

    except ClientError:
        app.logger.exception(
            "S3 preview failed for document %s", document_id
        )
        abort(404)

    # Verify the original file before displaying or converting it.
    if (
        doc["sha256"]
        and hashlib.sha256(file_data).hexdigest() != doc["sha256"]
    ):
        log_event(
            username, "VIEW", document_id,
            "SHA-256 integrity check failed", "DENIED"
        )
        abort(409)

    # PDFs can be previewed directly.
    if extension == ".pdf":
        pdf_data = file_data

    else:
        # Convert DOCX in an isolated temporary directory.
        try:
            with tempfile.TemporaryDirectory(
                prefix="trustvault_preview_"
            ) as temp_dir:
                source_path = os.path.join(temp_dir, "source.docx")
                output_path = os.path.join(temp_dir, "source.pdf")
                profile_path = os.path.join(temp_dir, "lo_profile")

                with open(source_path, "wb") as file:
                    file.write(file_data)

                command = [
                    SOFFICE_PATH,
                    "--headless",
                    "-env:UserInstallation="
                    + Path(profile_path).as_uri(),
                    "--convert-to",
                    "pdf",
                    "--outdir",
                    temp_dir,
                    source_path,
                ]

                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )

                if (
                    completed.returncode != 0
                    or not os.path.isfile(output_path)
                ):
                    app.logger.error(
                        "DOCX preview conversion failed: %s",
                        completed.stderr[-2000:],
                    )
                    abort(500)

                with open(output_path, "rb") as file:
                    pdf_data = file.read()

                # Basic validation that the output is a PDF.
                if not pdf_data.startswith(b"%PDF-"):
                    abort(500)

        except subprocess.TimeoutExpired:
            app.logger.exception("DOCX preview conversion timed out")
            abort(504)
        except OSError:
            app.logger.exception("LibreOffice could not start")
            abort(500)

    response = app.response_class(
        pdf_data,
        mimetype="application/pdf"
    )
    response.headers["Content-Disposition"] = "inline"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "sandbox"
    return response

@app.route("/download/<int:document_id>")
@login_required
def download_document(document_id):

    doc = get_document(document_id)

    if not doc:
        abort(404)

    username = session["username"]
    is_owner = doc["owner_id"] == session["user_id"]
    conn = get_db_connection()
    try:
        permission = conn.execute("""
            SELECT id FROM document_permissions
            WHERE document_id=? AND username=? AND permission IN ('read', 'edit')
        """, (document_id, username)).fetchone()
    finally:
        conn.close()

    # Preserve existing access-control rules.
    if not (is_owner or permission):
        log_event(
            username, "DOWNLOAD", document_id,
            "Unauthorized download attempt", "DENIED"
        )
        abort(403)

    # New documents are stored in private S3.
    if doc["storage_backend"] == "s3":
        try:
            response = s3_client.get_object(
                Bucket=S3_BUCKET,
                Key=doc["stored_filename"]
            )
            file_data = response["Body"].read()

        except ClientError:
            app.logger.exception(
                "S3 download failed for document %s", document_id
            )
            log_event(
                username, "DOWNLOAD", document_id,
                "S3 file unavailable", "DENIED"
            )
            abort(404)

        if (
            doc["sha256"]
            and hashlib.sha256(file_data).hexdigest() != doc["sha256"]
        ):
            log_event(
                username, "DOWNLOAD", document_id,
                "SHA-256 integrity check failed", "DENIED"
            )
            abort(409)

        log_event(
            username, "DOWNLOAD", document_id,
            "S3 download authorized"
        )

        return send_file(
            BytesIO(file_data),
            mimetype=response.get(
                "ContentType", "application/octet-stream"
            ),
            as_attachment=True,
            download_name=doc["filename"]
        )

    # Existing local documents continue to work.
    path = document_path(doc["stored_filename"])

    if not os.path.isfile(path):
        log_event(
            username, "DOWNLOAD", document_id,
            "Stored file not found", "DENIED"
        )
        abort(404)

    if doc["sha256"] and calculate_sha256(path) != doc["sha256"]:
        log_event(
            username, "DOWNLOAD", document_id,
            "SHA-256 integrity check failed", "DENIED"
        )
        abort(409)

    log_event(
        username, "DOWNLOAD", document_id,
        "Download authorized"
    )

    return send_file(
        path,
        as_attachment=True,
        download_name=doc["filename"]
    )
# --------------------------------------------------
# SHARE DOCUMENT
# --------------------------------------------------              

@app.route("/share/<int:document_id>", methods=["GET", "POST"])
@login_required
def share_document(document_id):
    doc = get_document(document_id)

    if not doc:
        abort(404)

    if not can_manage_document(doc):
        log_event(
            session["username"], "SHARE", document_id,
            "Unauthorized sharing attempt", "DENIED"
        )
        abort(403)

    if request.method == "POST":
        
        target_username = request.form.get("username", "").strip()
        app.logger.warning("SHARE DEBUG: document_id=%s username=%r permission=%r",
                   document_id, target_username,
                   request.form.get("permission"))
        requested_permission = request.form.get("permission", "read").strip().lower()

        conn = get_db_connection()
        try:
            target = conn.execute("""
                SELECT id, username FROM users WHERE username=?
            """, (target_username,)).fetchone()

            if requested_permission not in ("read", "edit"):
                flash("Invalid permission selected.")
            elif not target:
                flash("User not found.")
            elif target_username == doc["owner"]:
                flash("The owner already controls this document.")
            else:
                conn.execute("""
                    INSERT INTO document_permissions
                    (document_id, username, permission, user_id)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(document_id, username)
                    DO UPDATE SET
                        permission=excluded.permission,
                        user_id=excluded.user_id
                """, (
                    document_id,
                    target["username"],
                    requested_permission,
                    target["id"],
                ))
                conn.commit()

                log_event(
                    session["username"],
                    "SHARE",
                    document_id,
                    "Granted " + requested_permission
                    + " access to " + target_username,
                )
                flash(
                    requested_permission.capitalize()
                    + " access granted successfully."
                )

        except Exception:
            conn.rollback()
            app.logger.exception("Share failed")
            flash("Could not update access.")
        finally:
            conn.close()

        return redirect(url_for(
            "share_document", document_id=document_id
        ))


        return redirect(url_for(
            "share_document", document_id=document_id
        ))

    conn = get_db_connection()
    try:
        permissions = conn.execute("""
            SELECT username, permission
            FROM document_permissions
            WHERE document_id=?
            ORDER BY username
        """, (document_id,)).fetchall()
    finally:
        conn.close()

        permission_rows = ""
    for item in permissions:
        permission_label = (
            "✎ Edit access"
            if item["permission"] == "edit"
            else "◉ Read only"
        )

        permission_rows += """
        <tr>
          <td>USER</td>
          <td><span class="badge blue">PERMISSION_LABEL</span></td>
          <td>
            <form method="post" action="REVOKE" class="inline">
              <button class="btn btn-danger btn-small">⛨ Revoke</button>
            </form>
          </td>
        </tr>
        """.replace(
            "USER", item["username"]
        ).replace(
            "PERMISSION_LABEL", permission_label
        ).replace(
            "REVOKE", url_for(
                "revoke_document",
                document_id=document_id,
                username=item["username"]
            )
        )

    if not permission_rows:
        permission_rows = '<tr><td colspan="3">No grants yet.</td></tr>'

    content = """
    <div class="grid" style="grid-template-columns:1fr 1.3fr">
      <div class="card">
        <div class="stat-icon purple">♧</div>
        <h2>Grant document access</h2>
        <p>Share this document with an existing account.</p>
        <form method="post">
          <label>DOCUMENT</label>
          <input value="DOCUMENT_NAME" disabled>
          <label>USERNAME</label>
          <input name="username" placeholder="Enter exact username" required>
                    <label>PERMISSION</label>
          <select name="permission" required>
            <option value="read">Read access</option>
            <option value="edit">Edit access</option>
          </select>
          <button class="btn btn-primary">♧ Grant Access</button>
        </form>
        <p class="small">Choose read or edit access for each user.</p>
      </div>
      <div class="card">
        <h2>Access control list</h2>
        <p class="small">Revoke access to block future downloads.</p>
        <div class="table-wrap">
          <table>
            <thead><tr><th>USER</th><th>PERMISSION</th><th>ACTION</th></tr></thead>
            <tbody>PERMISSION_ROWS</tbody>
          </table>
        </div>
      </div>
    </div>
    """.replace("DOCUMENT_NAME", doc["filename"]).replace(
        "PERMISSION_ROWS", permission_rows
    )

    return render_page(
        "Manage Document Access", content, active="mydocs",
        subtitle="Grant or revoke document-level permissions"
    )


# --------------------------------------------------
# REVOKE ACCESS
# --------------------------------------------------

@app.route("/revoke/<int:document_id>/<username>", methods=["POST"])
@login_required
def revoke_document(document_id, username):
    doc = get_document(document_id)

    if not doc:
        abort(404)

    if not can_manage_document(doc):
        log_event(
            session["username"], "REVOKE", document_id,
            "Unauthorized revoke attempt", "DENIED"
        )
        abort(403)

    conn = get_db_connection()
    try:
        cursor = conn.execute("""
            DELETE FROM document_permissions
            WHERE document_id=? AND username=?
        """, (document_id, username))
        conn.commit()

        if cursor.rowcount:
            log_event(
                session["username"], "REVOKE", document_id,
                "Revoked access for " + username
            )
            flash("Access revoked.")
        else:
            flash("Permission not found.")
    except Exception:
        conn.rollback()
        app.logger.exception("Revoke failed")
        flash("Could not revoke access.")
    finally:
        conn.close()

    return redirect(url_for(
        "share_document", document_id=document_id
    ))


# --------------------------------------------------
# DELETE DOCUMENT
# --------------------------------------------------


@app.route("/edit/<int:document_id>", methods=["GET", "POST"])
@role_required("viewer", "owner", "admin")
def edit_document(document_id):
    conn = get_db_connection()

    try:
        doc = conn.execute(
            "SELECT * FROM documents WHERE id = ?",
            (document_id,)
        ).fetchone()

        if doc is None:
            abort(404)

        username = session.get("username")
        role = session.get("role")

        # Only the owner, an admin, or an Edit-permission recipient
        # may edit document metadata.
        is_owner = doc["owner"] == username
        is_admin = role == "admin"

        permission = conn.execute(
            """
            SELECT permission
            FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (document_id, username)
        ).fetchone()

        has_edit_access = (
            permission is not None
            and permission["permission"] == "edit"
        )

        if not (is_owner or is_admin or has_edit_access):
            abort(403)

        if request.method == "POST":
            new_filename = secure_filename(
                request.form.get("filename", "").strip()
            )
            new_category = request.form.get("category", "").strip()

            if not new_filename or not new_category:
                flash("Filename and category are required.", "error")
                return render_template(
                    "edit_document.html", doc=doc
                )

            # Preserve the file type so existing preview behavior
            # continues to work.
            old_ext = os.path.splitext(doc["filename"])[1].lower()
            new_ext = os.path.splitext(new_filename)[1].lower()

            if old_ext != new_ext:
                flash(
                    "Keep the original file extension unchanged.",
                    "error"
                )
                return render_template(
                    "edit_document.html", doc=doc
                )

            conn.execute(
                """
                UPDATE documents
                SET filename = ?, category = ?
                WHERE id = ?
                """,
                (new_filename, new_category, document_id)
            )
            conn.commit()

            log_event(
                username,
                "EDIT",
                document_id,
                "Updated document filename and category",
                "SUCCESS"
            )

            flash("Document details updated successfully!", "success")
            return redirect(url_for("edit_document", document_id=document_id))

        return render_template("edit_document.html", doc=doc)

    finally:
        conn.close()

@app.route("/delete/<int:document_id>", methods=["POST"])
@login_required
def delete_document(document_id):
    doc = get_document(document_id)

    if not doc:
        abort(404)

    if not can_manage_document(doc):
        log_event(
            session["username"], "DELETE", document_id,
            "Unauthorized delete attempt", "DENIED"
        )
        abort(403)

    # Delete the file from its actual storage location.
    try:
        if doc["storage_backend"] == "s3":
            s3_client.delete_object(
                Bucket=S3_BUCKET,
                Key=doc["stored_filename"]
            )
        else:
            path = document_path(doc["stored_filename"])
            if os.path.isfile(path):
                os.remove(path)

        # Remove the database record only after file deletion succeeds.
        conn = get_db_connection()
        try:
            conn.execute(
                "DELETE FROM documents WHERE id=?", (document_id,)
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    except Exception:
        app.logger.exception(
            "Delete failed for document %s", document_id
        )
        flash("Delete failed. Check the application log.")
        return redirect(url_for("my_documents"))

    log_event(
        session["username"], "DELETE", document_id,
        "Document deleted"
    )
    flash("Document deleted.")
    return redirect(url_for("my_documents"))

# --------------------------------------------------
# PART 4: ADMIN AUDIT DASHBOARD
# --------------------------------------------------
@app.route("/admin/audit")
@role_required("admin")
def audit_logs():
    conn = get_db_connection()
    try:
        logs = conn.execute("""
            SELECT id, timestamp, username, action,
                   document_id, details, result
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 500
        """).fetchall()
    finally:
        conn.close()

    rows = ""
    for log in logs:
        result = log["result"] or "UNKNOWN"
        result_class = "badge red" if result == "DENIED" else "badge"

        rows += """
        <tr>
          <td>TIME</td>
          <td>USER</td>
          <td><b>ACTION</b></td>
          <td>DOC_ID</td>
          <td>DETAILS</td>
          <td><span class="RESULT_CLASS">RESULT</span></td>
        </tr>
        """.replace("TIME", str(log["timestamp"])).replace(
            "USER", str(log["username"])
        ).replace("ACTION", str(log["action"])).replace(
            "DOC_ID", str(log["document_id"] or "—")
        ).replace("DETAILS", str(log["details"] or "—")).replace(
            "RESULT_CLASS", result_class
        ).replace("RESULT", result)

    if not rows:
        rows = '<tr><td colspan="6">No audit events recorded yet.</td></tr>'

    conn = get_db_connection()
    try:
        total_events = conn.execute(
            "SELECT COUNT(*) FROM audit_logs"
        ).fetchone()[0]
        denied = conn.execute("""
            SELECT COUNT(*) FROM audit_logs WHERE result='DENIED'
        """).fetchone()[0]
        uploads = conn.execute("""
            SELECT COUNT(*) FROM audit_logs WHERE action='UPLOAD'
        """).fetchone()[0]
        downloads = conn.execute("""
            SELECT COUNT(*) FROM audit_logs WHERE action='DOWNLOAD'
        """).fetchone()[0]
    finally:
        conn.close()

    content = """
    <div class="grid stats">
      <div class="stat">
        <div class="stat-icon">◷</div>
        <div class="stat-number">TOTAL</div>
        <div class="stat-label">Recorded Events</div>
      </div>
      <div class="stat">
        <div class="stat-icon red">⛨</div>
        <div class="stat-number">DENIED</div>
        <div class="stat-label">Denied Attempts</div>
      </div>
      <div class="stat">
        <div class="stat-icon green">⇧</div>
        <div class="stat-number">UPLOADS</div>
        <div class="stat-label">Document Uploads</div>
      </div>
      <div class="stat">
        <div class="stat-icon purple">↓</div>
        <div class="stat-number">DOWNLOADS</div>
        <div class="stat-label">Document Downloads</div>
      </div>
    </div>

    <section class="section">
      <div class="section-head">
        <div>
          <h2>Security Event Stream</h2>
          <p class="small">Latest 500 recorded application events.</p>
        </div>
        <span class="badge">◉ Audit view</span>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>TIMESTAMP</th><th>USER</th><th>ACTION</th>
              <th>DOCUMENT</th><th>DETAILS</th><th>RESULT</th>
            </tr>
          </thead>
          <tbody>ROWS</tbody>
        </table>
      </div>
    </section>
    """.replace("TOTAL", str(total_events)).replace(
        "DENIED", str(denied)
    ).replace("UPLOADS", str(uploads)).replace(
        "DOWNLOADS", str(downloads)
    ).replace("ROWS", rows)

    return render_page(
        "Security Audit Center", content,
        active="audit",
        subtitle="Review recorded access and document events"
    )


# --------------------------------------------------
# CUSTOM ERROR PAGES
# --------------------------------------------------

@app.errorhandler(403)
def forbidden(error):
    content = """
    <div class="card" style="max-width:650px;margin:30px auto;text-align:center">
      <div class="error-hero">⛨</div>
      <h1>Access Denied</h1>
      <p>Your account is not authorized to perform this action.</p>
      <span class="badge red">403 · Permission required</span>
      <p><a class="btn" href="/">Return to dashboard</a></p>
    </div>
    """
    return render_page(
        "Access Denied", content,
        subtitle="TrustVault security protection"
    ), 403


@app.errorhandler(404)
def not_found(error):
    content = """
    <div class="card" style="max-width:650px;margin:30px auto;text-align:center">
      <div class="error-hero">⌕</div>
      <h1>Document Not Found</h1>
      <p>The requested page or document could not be found.</p>
      <p><a class="btn" href="/">Return to dashboard</a></p>
    </div>
    """
    return render_page(
        "Not Found", content,
        subtitle="The requested resource is unavailable"
    ), 404


@app.errorhandler(409)
def integrity_error(error):
    content = """
    <div class="card" style="max-width:650px;margin:30px auto;text-align:center">
      <div class="error-hero">⚠</div>
      <h1>Integrity Check Failed</h1>
      <p>The stored document does not match its recorded SHA-256 hash.</p>
      <span class="badge red">409 · Integrity warning</span>
      <p>Do not download the file until the issue has been investigated.</p>
      <p><a class="btn" href="/">Return to dashboard</a></p>
    </div>
    """
    return render_page(
        "Integrity Warning", content,
        subtitle="Document integrity protection"
    ), 409


@app.errorhandler(413)
def file_too_large(error):
    return (
        "Upload rejected: maximum file size is 10 MB.",
        413
    )


# START APPLICATION
# --------------------------------------------------
init_db()


@app.route("/admin/users/<int:user_id>/status", methods=["POST"])
@login_required
def update_user_status(user_id):    # Only admins can approve or reject accounts.
    if session.get("role") != "admin":
        abort(403)

    status = request.form.get("status", "").strip().lower()

    if status not in ("approved", "rejected"):
        abort(400)

    # Prevent an admin from changing their own account status.
    if user_id == session.get("user_id"):
        flash("You cannot change your own account status.")
        return redirect(url_for("home"))

    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if user is None:
            abort(404)

        conn.execute(
            "UPDATE users SET account_status = ? WHERE id = ?",
            (status, user_id)
        )
        conn.commit()

        log_event(
            session.get("username", "unknown"),
            "USER_STATUS_CHANGED",
            details=f"User {user['username']} status changed to {status}"
        )
    finally:
        conn.close()

    flash(f"Account status updated to {status}.")
    return redirect(url_for("home"))

    return redirect(url_for("home"))
# ============================================================
# TRUSTVAULT - DOCUMENT SEARCH AND FILTERS
# Search by filename, owner, category and upload date
# ============================================================

@app.route("/document-search", methods=["GET"])
@login_required
def document_search():
    import html
    from datetime import datetime

    username = session["username"]
    user_id = session["user_id"]
    role = session.get("role", "viewer")

    name = request.args.get("name", "").strip()
    owner = request.args.get("owner", "").strip()
    category = request.args.get("category", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    error_message = ""

    try:
        if date_from:
            datetime.strptime(date_from, "%Y-%m-%d")
        if date_to:
            datetime.strptime(date_to, "%Y-%m-%d")
        if date_from and date_to and date_from > date_to:
            error_message = "Start date must not be after end date."
    except ValueError:
        error_message = "Enter dates in YYYY-MM-DD format."

    docs = []

    if not error_message:
        conn = get_db_connection()
        try:
            query = """
                SELECT DISTINCT
                    d.id,
                    d.filename,
                    d.owner,
                    d.category,
                    d.uploaded_at,
                    d.owner_id
                FROM documents d
                WHERE (
                    (? = 'admin')
                    OR d.owner_id = ?
                    OR EXISTS (
                        SELECT 1
                        FROM document_permissions p
                        WHERE p.document_id = d.id
                          AND p.username = ?
                          AND p.permission IN ('read', 'edit')
                    )
                )
            """
            params = [role, user_id, username]

            if name:
                query += " AND d.filename LIKE ?"
                params.append("%" + name + "%")

            if owner:
                query += " AND d.owner LIKE ?"
                params.append("%" + owner + "%")

            if category:
                query += " AND LOWER(d.category) = LOWER(?)"
                params.append(category)

            if date_from:
                query += " AND date(d.uploaded_at) >= date(?)"
                params.append(date_from)

            if date_to:
                query += " AND date(d.uploaded_at) <= date(?)"
                params.append(date_to)

            query += " ORDER BY d.uploaded_at DESC"

            docs = conn.execute(query, params).fetchall()
        finally:
            conn.close()

    def safe(value):
        return html.escape(str(value or ""))

    result_rows = ""

    for doc in docs:
        result_rows += """
        <tr>
          <td>FILE_NAME</td>
          <td>OWNER_NAME</td>
          <td>CATEGORY_NAME</td>
          <td>UPLOAD_DATE</td>
          <td>
            <a class="btn btn-primary"
               href="DOWNLOAD_URL">Download</a>
          </td>
        </tr>
        """.replace("FILE_NAME", safe(doc["filename"])).replace(
            "OWNER_NAME", safe(doc["owner"])
        ).replace(
            "CATEGORY_NAME", safe(doc["category"])
        ).replace(
            "UPLOAD_DATE", safe(doc["uploaded_at"])
        ).replace(
            "DOWNLOAD_URL",
            url_for("download_document", document_id=doc["id"])
        )

    if not result_rows:
        result_rows = """
        <tr>
          <td colspan="5">No matching documents found.</td>
        </tr>
        """

    content = """
    <div class="card">
      <h2>Search Documents</h2>
      <p>Find documents using one or more filters.</p>

      <form method="get" action="/document-search">
        <label>Document filename</label>
        <input name="name" value="NAME_VALUE"
               placeholder="Search by filename">

        <label>Document owner</label>
        <input name="owner" value="OWNER_VALUE"
               placeholder="Enter owner username">

        <label>Category</label>
        <input name="category" value="CATEGORY_VALUE"
               placeholder="Enter category">

        <div class="grid">
          <div>
            <label>Upload date from</label>
            <input type="date" name="date_from"
                   value="FROM_VALUE">
          </div>
          <div>
            <label>Upload date to</label>
            <input type="date" name="date_to"
                   value="TO_VALUE">
          </div>
        </div>

        <br>
        <button class="btn btn-primary" type="submit">
          Search Documents
        </button>
        <a class="btn" href="/document-search">Clear Filters</a>
      </form>

      <p>RESULT_COUNT matching documents</p>
      <p class="small">ERROR_MESSAGE</p>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Document</th>
              <th>Owner</th>
              <th>Category</th>
              <th>Uploaded</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>RESULT_ROWS</tbody>
        </table>
      </div>
    </div>
    """.replace("NAME_VALUE", safe(name)).replace(
        "OWNER_VALUE", safe(owner)
    ).replace(
        "CATEGORY_VALUE", safe(category)
    ).replace(
        "FROM_VALUE", safe(date_from)
    ).replace(
        "TO_VALUE", safe(date_to)
    ).replace(
        "RESULT_COUNT", str(len(docs))
    ).replace(
        "ERROR_MESSAGE", safe(error_message)
    ).replace(
        "RESULT_ROWS", result_rows
    )

    return render_page(
        "Document Search",
        content,
        active="mydocs",
        subtitle="Search and filter authorised documents"
    )
if __name__ == "__main__":
    app.run(debug=True)
# ============================================================
# TRUSTVAULT: DOCUMENT SEARCH AND FILTERS
# Add at the bottom of app.py
# ============================================================

from flask import jsonify, request, session, abort
from datetime import datetime


@app.route("/api/document-search", methods=["GET"])
def trustvault_document_search():
    # Require an authenticated user
    if not session.get("username"):
        abort(401)

    username = session["username"]
    role = session.get("role", "viewer")

    filename = request.args.get("name", "").strip()
    owner = request.args.get("owner", "").strip()
    category = request.args.get("category", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    # Validate ISO dates before querying
    try:
        if date_from:
            datetime.strptime(date_from, "%Y-%m-%d")
        if date_to:
            datetime.strptime(date_to, "%Y-%m-%d")
        if date_from and date_to and date_from > date_to:
            return jsonify({"error": "Start date must not exceed end date"}), 400
    except ValueError:
        return jsonify({"error": "Dates must use YYYY-MM-DD format"}), 400

    conn = get_db_connection()

    try:
        # Only return documents the current user is authorised to access.
        # Owners see their own documents; admins can search all documents;
        # viewers see only documents explicitly shared with them.
        query = """
            SELECT DISTINCT
                d.id,
                d.filename,
                d.category,
                d.owner,
                d.uploaded_at
            FROM documents d
            LEFT JOIN document_permissions p
                ON p.document_id = d.id
                AND p.username = ?
            WHERE (
                (? = 'admin')
                OR d.owner = ?
                OR p.permission IN ('read', 'edit')
            )
        """

        params = [username, role, username]

        if filename:
            query += " AND d.filename LIKE ?"
            params.append("%" + filename + "%")

        if owner:
            query += " AND d.owner LIKE ?"
            params.append("%" + owner + "%")

        if category:
            query += " AND d.category = ?"
            params.append(category)

        if date_from:
            query += " AND date(d.uploaded_at) >= date(?)"
            params.append(date_from)

        if date_to:
            query += " AND date(d.uploaded_at) <= date(?)"
            params.append(date_to)

        query += " ORDER BY d.uploaded_at DESC"

        rows = conn.execute(query, params).fetchall()

        return jsonify({
            "count": len(rows),
            "documents": [dict(row) for row in rows]
        })

    finally:
        conn.close()
