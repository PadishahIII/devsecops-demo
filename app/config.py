"""Runtime configuration — env driven, no secrets in code."""
import os

DB_PATH = os.environ.get("NOTES_DB", "/tmp/notes.db")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
# NOTE: uncomment to reproduce
# _DEMO_LEAK = "ds-demo-z86wBFCsf6vxxfW2yaZ8nhwDTC8AkmQm"
