# Lessons

## 2026-08-14 — Validated tool facts (from design validation runs)

- Context: Design validation for docs/DESIGN.md; facts verified locally.
- Memory:
  - Semgrep 1.155.0 `p/security-audit` has **no rule for sqlite3 f-string SQLi** (Django/SQLAlchemy only) → org rule needed; a custom `no-formatted-sql` pattern `$CONN.execute(f"...")` was tested and fires.
  - Semgrep 1.155.0 **SARIF omits per-result `level`** → recover severity from `runs[].tool.driver.rules[].defaultConfiguration.level`.
  - Semgrep generic HTML rules false-positive on `{{ x["y"] }}` inside attributes → use dot access `{{ x.y }}`.
  - **Gitleaks images moved to `ghcr.io/gitleaks/gitleaks`** (Docker Hub pull denied); v8.21.2/v8.24.0 exist.
  - syft 1.x: `-o cyclonedx-json=/path` (the `--file` flag is deprecated).
  - Fake `AKIA…` keys get **blocked by GitHub native push protection** on public repos → seed secrets use an org custom pattern (`ds-demo-<32hex>`).
  - Custom rego / grype CVE-2024-6827 CRITICAL / kyverno keyless / cosign OIDC / ZAP levels: **NOT yet validated** — DESIGN.md §3 lists fallbacks.
- Evidence: local runs 2026-08-14; commands in docs/DESIGN.md §3.
- Reuse: when implementing the pipeline, skip re-discovering these; still validate the pending list at build time.

## 2026-08-14 — Flask app: bugs found by "make sure it works" verification

- Context: Implementing the Python project only (user instruction). Local + container verification exposed three real bugs.
- Memory:
  - **Schema never initialized in production path** — tests passed because the fixture called `db.init_db()`; the live app 500'd with `no such table: notes`. Fix: `db.init_db(config.DB_PATH)` at app import (idempotent, safe across gunicorn workers).
  - **Workspace is on an exFAT volume (`/Volumes/T9`, `noowners`)**: `chmod` is a no-op, files always report `rwx------` → docker build context preserves those modes → non-root container user cannot read code (`PermissionError` on import). Fix inside the Dockerfile with `COPY --chmod`.
  - **`COPY --chmod=0644` on a directory strips the +x bit** → templates dir untraversable → `jinja2.TemplateNotFound` at runtime. Use symbolic mode `u=rwX,go=rX` (`X` = execute for directories only).
  - `app/tests/__init__.py` needed so pytest inserts `app/` into `sys.path` (imports of `config`/`db`/`app`).
- Evidence: `app/app.py`, `app/Dockerfile`, `app/tests/__init__.py`; final verification all green — pytest 6/6, ruff clean, gunicorn smoke (health/POST/notes/search/admin/headers), container run (non-root, HEALTHCHECK healthy, 0 log errors).
- Reuse: when containerizing anything from this volume, always set modes in the Dockerfile; never rely on host permissions; always boot the app for real (not just tests) before calling it done.
