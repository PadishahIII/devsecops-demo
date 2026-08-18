"""Smoke/unit tests for the notes app."""
import os

os.environ["APP_SECRET_KEY"] = "test-secret-key"
os.environ["ADMIN_PASSWORD_HASH"] = ""  # no admin access in tests

import config  # noqa: E402
import db  # noqa: E402
from app import app  # noqa: E402


def _client(tmp_path):
    config.DB_PATH = str(tmp_path / "test.db")
    db.init_db(config.DB_PATH)
    app.config["TESTING"] = True
    return app.test_client()


def test_health(tmp_path):
    c = _client(tmp_path)
    r = c.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_create_and_list_note(tmp_path):
    c = _client(tmp_path)
    r = c.post("/notes", data={"title": "hello", "content": "world"})
    assert r.status_code == 201
    r = c.get("/notes")
    assert b"hello" in r.data


def test_search_parameterized(tmp_path):
    c = _client(tmp_path)
    c.post("/notes", data={"title": "alpha", "content": "one"})
    r = c.get("/search?q=alpha")
    assert r.status_code == 200
    assert b"alpha" in r.data


def test_search_escaping(tmp_path):
    """Quote characters in input must not break the query."""
    c = _client(tmp_path)
    r = c.get("/search?q=%27%20OR%201%3D1--")
    assert r.status_code == 200


def test_admin_wrong_password(tmp_path):
    c = _client(tmp_path)
    r = c.get("/admin?password=nope")
    assert r.status_code == 200
    assert b"not authorized" in r.data


def test_security_headers(tmp_path):
    c = _client(tmp_path)
    r = c.get("/health")
    assert r.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("Content-Security-Policy") == "default-src 'self'"


def test_csv_export(tmp_path):
    c = _client(tmp_path)
    c.post("/notes", data={"title": "csv,title", "content": "line\ncontent"})
    r = c.get("/export/notes")
    assert r.status_code == 200
    assert r.headers.get("Content-Type", "").startswith("text/csv")
    assert "csv,title" in r.data.decode()


def test_api_notes_json(tmp_path):
    c = _client(tmp_path)
    c.post("/notes", data={"title": "json-note", "content": "body"})
    r = c.get("/api/notes")
    assert r.status_code == 200
    assert r.get_json()["notes"][0]["title"] == "json-note"


def test_metrics(tmp_path):
    c = _client(tmp_path)
    r = c.get("/metrics")
    assert r.status_code == 200
    assert "notes_total" in r.get_json()


def test_demo_banner(tmp_path):
    c = _client(tmp_path)
    r = c.get("/demo/banner")
    assert r.status_code == 200
    assert "banner" in r.get_json()


def test_login_flow(tmp_path):
    """Login route is reachable and logs out; the auth itself is the
    MD5-excepted legacy surface (admin password hash is empty in tests)."""
    c = _client(tmp_path)
    r = c.get("/login")
    assert r.status_code == 200
    r = c.get("/logout")
    assert r.status_code == 302
