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

## 2026-08-17 — Jenkins jq report formatting

- Context: The Jenkins pipeline failed while formatting `semgrep.sarif` with the `pretty_json` helper.
- Memory: `/wd` exists only inside the jq container, so a host-shell redirect to `/wd/${output}` fails before Docker starts. Also, using identical input/output paths can truncate the report before jq reads it; format to a temporary host-mounted file and then replace the original.
- Evidence: `Jenkinsfile:1-4,61,79,92,98`; Jenkins log reported `script.sh.copy: line 2: /wd/semgrep.sarif: No such file or directory`.
- Reuse: Keep container paths inside jq arguments, use host paths for shell redirection, and avoid in-place redirection without a temporary file.

## 2026-08-17 — Jenkins jq formatting fix applied

- Context: The report-formatting failure was fixed in the Jenkins pipeline.
- Memory: `pretty_json` now writes jq output to a temporary file under the host workspace and moves it into place after jq succeeds; the Syft report call uses `$WORKSPACE/reports` as its host path.
- Evidence: `Jenkinsfile:1-6,92`; `git diff --check` and path assertions passed.
- Reuse: Preserve the temporary-file pattern whenever a report is formatted in place.

## 2026-08-17 — Persistent Grype DB cache

- Context: The Jenkins SCA stage runs Grype in a disposable container and needs the vulnerability database to survive between builds.
- Memory: Mount the named Docker volume `grype-db` at Grype's default database cache path `/root/.cache/grype/db`.
- Evidence: `Jenkinsfile:96`; `git diff --check` passed and the volume path assertion matched.
- Reuse: Keep this volume mount on the Grype invocation so database updates persist across container runs.
