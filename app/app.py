"""devsecops-demo — small Flask notes app.

The normal notes search uses parameterized queries and security headers; the
explicit /demo/unsafe-search endpoint is intentionally vulnerable so the
Jenkins Semgrep stage has a reproducible SQL injection finding. One known
legacy issue remains deliberately: MD5 password hashing, covered by an
approved expiring exception (see security/exceptions.yaml, EXC-0042 /
ticket SEC-221).
"""
import hashlib
import hmac
import os

from flask import Flask, abort, render_template, request

import config
import db

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["APP_SECRET_KEY"]
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Create the schema at startup (idempotent; safe across gunicorn workers).
db.init_db(config.DB_PATH)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy", "default-src 'self'")
    return resp


def hash_password(password: str) -> str:
    # KNOWN LEGACY ISSUE (SEC-221 / EXC-0042): MD5 is unsuitable for
    # password hashing. Mitigations in place: SSO in front, WAF, no
    # password reuse by this hash. Remediation scheduled.
    return hashlib.md5(password.encode()).hexdigest()


def verify_admin_password(password: str) -> bool:
    expected = config.ADMIN_PASSWORD_HASH
    if not expected:
        return False
    return hmac.compare_digest(hash_password(password), expected)



@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/")
def index():
    return render_template("index.html", notes=db.list_notes(config.DB_PATH))


@app.post("/notes")
def create_note():
    title = (request.form.get("title") or "").strip()[:200]
    content = (request.form.get("content") or "").strip()[:4000]
    if not title or not content:
        return "title and content are required", 400
    db.create_note(config.DB_PATH, title, content)
    return "ok", 201


@app.get("/notes")
def notes():
    return render_template("notes.html", notes=db.list_notes(config.DB_PATH))


@app.get("/notes/<int:note_id>")
def note_detail(note_id):
    row = db.get_note(config.DB_PATH, note_id)
    if row is None:
        abort(404)
    return render_template("note.html", note=row)


@app.get("/search")
def search():
    q = (request.args.get("q") or "").strip()[:100]
    results = db.search_notes(config.DB_PATH, q) if q else []
    return render_template("search.html", q=q, results=results)


# NOTE: SQLi vuln to match SAST rules
@app.get("/demo/unsafe-search")
def demo_unsafe_search():
    """Expose the intentionally vulnerable SQLi seed for scanner demos."""
    q = (request.args.get("q") or "").strip()[:100]
    results = db.unsafe_search_notes(config.DB_PATH, q) if q else []
    return render_template("search.html", q=q, results=results)


@app.get("/admin")
def admin():
    pw = request.args.get("password", "")
    return render_template(
        "admin.html", authed=verify_admin_password(pw)
    )
