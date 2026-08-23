"""devsecops-demo — intentionally seeded DevSecOps showcase app.

The normal notes search uses parameterized queries and security headers;
the explicit /demo/unsafe-search endpoint is intentionally vulnerable so
the Jenkins Semgrep stage has a reproducible SQL injection finding. One known
legacy issue remains deliberately: MD5 password hashing, covered by an
approved expiring exception (see security/exceptions.yaml, EXC-0042 /
ticket SEC-221).

Each route also carries a purpose for the pipeline demo:
  /demo/unsafe-search   — SQLi seed (semgrep no-formatted-sql, BLOCKING)
  /admin                — MD5 password check (no-md5-hashing, EXCEPTED EXC-0042)
  /export/notes         — CSV export (ZAP scan coverage; defensive headers)
  /login (with /logout) — session-based login so ZAP can exercise authN
  /api/notes            — JSON API (SBOM inventory exercises the same code)
  /metrics              — numeric gauge for the demo's post-process stream
"""
import hashlib
import hmac
import csv
import io
import os
from flask import Flask, abort, redirect, render_template, request, session, url_for
import config
import db
# Ensure the SQLite schema exists before the first request. Idempotent and
# safe across gunicorn workers — runs once per process at import.
os.makedirs(os.path.dirname(config.DB_PATH) or ".", exist_ok=True)
db.init_db(config.DB_PATH)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", config.APP_SECRET_KEY)
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
    """Legacy admin panel. Access via password query param (legacy flow) or
    via the /login session (the modern flow ZAP exercises). The password
    check itself is the MD5-excepted legacy surface (EXC-0042)."""
    pw = request.args.get("password", "")
    authed = session.get("admin", False) or verify_admin_password(pw)
    return render_template(
        "admin.html", authed=authed
    )


@app.get("/export/notes")
def export_notes():
    """CSV export of all notes — exercises a data-exfiltration surface for
    DAST (ZAP) coverage; Content-Disposition + CSV quoting keep it safe."""
    rows = db.list_notes(config.DB_PATH)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "title", "content", "created_at"])
    for r in rows:
        writer.writerow([r["id"], r["title"], r["content"], r["created_at"]])
    resp = app.make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=notes.csv"
    return resp


@app.get("/login")
def login():
    """Session login (demo-only, not real authN). Exercises the authenticated
    surface so ZAP can crawl /admin behind a login; the gate treats the
    admin panel as the MD5-excepted legacy surface."""
    pw = request.args.get("password", "")
    if pw and verify_admin_password(pw):
        session["admin"] = True
        return redirect(url_for("admin"))
    return render_template("login.html")


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/api/notes")
def api_notes():
    """JSON API — same storage as the HTML pages; the SBOM/inventory story
    exercises the same code path."""
    return {"notes": [dict(r) for r in db.list_notes(config.DB_PATH)]}


@app.get("/metrics")
def metrics():
    """Numeric gauge for the demo post-process stream (gate/report/vuln-db
    consumers can scrape it). Exposes no internals.""",
    return {"notes_total": len(db.list_notes(config.DB_PATH)), "version": "0.1.0"}


@app.get("/demo/banner")
def demo_banner():
    """Shows the committed release banner (demo of release metadata flowing
    through the pipeline: git commit → env → runtime response)."""
    return {"banner": os.environ.get("DEMO_BANNER", "devsecops-demo")}
