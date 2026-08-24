"""Runtime configuration — env driven, no secrets in code."""
import os
# (security/gitleaks.toml: demo-api-token, ds-demo-<32 hex>). The pipeline
# gate treats gitleaks findings as categorical (policy.yaml fail_tools).
# This is a FAKE token; real secrets never belong in code.
APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY", "insecure-dev-only-key")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
DEMO_API_TOKEN = os.environ.get("DEMO_API_TOKEN", "")
# SQLite file. /tmp is writable by the non-root runAsUser (65532); a volume
# can point it elsewhere via the DB_PATH env var. init_db() runs at app
# import (see app.py) — idempotent and safe across gunicorn workers.
DB_PATH = os.environ.get("DB_PATH", "/tmp/notes.db")
