## 2026-08-17 — Semgrep demo vulnerability seed

- Context: The Jenkinsfile already runs Semgrep with `p/security-audit` and `security/semgrep`, while `docs/DESIGN.md` calls for a reproducible SQL injection seed.
- Memory: Keep the normal `/search` path parameterized. Expose the deliberate SQL injection only through `/demo/unsafe-search`, backed by `db.unsafe_search_notes()`, so Semgrep reports a reachable finding without weakening the normal search behavior.
- Evidence: `app/app.py`, `app/db.py`, `security/semgrep/no-formatted-sql.yml`, `Jenkinsfile`, `docs/DESIGN.md`.
- Reuse: Use `/demo/unsafe-search` when demonstrating the Semgrep SQLi finding; do not deploy the demo endpoint in a production environment.

## 2026-08-17 — Syft/Grype compatibility

- Context: Jenkins SCA generated a CycloneDX SBOM with Syft `v1.51.0` and scanned it with Grype `v0.79.0`.
- Memory: Syft `v1.51.0` defaults to CycloneDX `specVersion: 1.7`, which Grype `v0.79.0` cannot decode; Grype `v0.79.0` supports DB schema 5 while current databases require schema 6. Use a Grype release with CycloneDX 1.7 and DB schema 6 support, or explicitly emit an older CycloneDX format as a temporary compatibility workaround.
- Evidence: `Jenkinsfile:6-7,80-87`; local Docker reproduction showed Syft SBOM `specVersion: 1.7`, Grype `v0.79.0` returned `sbom format not recognized` and a 23-week-old DB error; Grype `v0.115.0` scanned the same SBOM successfully.
- Reuse: Keep Syft and Grype versions compatible and ensure the Grype container can update its vulnerability database.
