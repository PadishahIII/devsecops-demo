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

## 2026-08-18 — Gate/normalize overhaul: pydantic policy + lean findings stream
- Context: gate.py accessed policy dicts via string literals (no schema); normalize.py
  diverged from real Jenkins artifacts (~/.jenkins/workspace/test/reports).
- Memory: (1) Policy/exceptions are now pydantic models with `extra="forbid"` — typos
  fail fast at startup instead of silently disabling a control. (2) findings.jsonl is
  a LEAN gating stream (common fields + `source` pointer); normalize.py copies raw
  artifacts to `raw/` — raw files stay the source of truth for detailed reports.
  (3) SARIF severity: semgrep (1.155.0) emits NO result level and NO ruleIndex — the
  severity lives in runs[].tool.driver.rules[i].defaultConfiguration.level, looked up
  by rule id; gitleaks v8.21.2 has no level anywhere (default medium, gate treats it
  categorically); trivy Rego SARIF has a single-rule table and no ruleIndex.
  (4) grype EPSS is a LIST of {cve, epss, percentile, date} (v0.115+), not the old
  {EPSS:{score}} dict. (5) fingerprint path normalization: lstrip("/") + snippet strip
  so the exception fp matches despite the /src/ SARIF URI base.
- Evidence: tools/gate.py, tools/normalize.py, security/exceptions.yaml (EXC-0042 fp
  d22854fb... = sha256(semgrep|security.semgrep.no-md5-hashing|app/app.py|43|stripped));
  real-artifact run: 17 findings, md5 finding now EXCEPTION_APPLIED.
- Reuse: run `python3 tools/normalize.py <reports-dir> --out findings.jsonl --raw-dir raw`
  then `python3 tools/gate.py findings.jsonl security/policy.yaml security/exceptions.yaml
  --out gate-decision.json`; exit 1 = block.

## 2026-08-18 — Curated security report (tools/report.py)

- Context: gate-decision.json is machine-readable but unreadable; the demo needed a
  human report grouped per tool class with per-kind formats.
- Memory: (1) NEW pipeline stage: normalize → gate --findings-out gated.jsonl →
  report.py gated.jsonl gate-decision.json --out <DIR> writes report.md + raw/ into
  that dir; --out is now a DIRECTORY. (2) report.py sections: SAST (source→sink code
  blocks, "Reachable from" for the demo seeds), secrets (commit/author via gitleaks
  partialFingerprints), SCA (CVSS/EPSS/KEV/fix + advisory URLs), misconfig (rule
  description + avd link), license; verdicts FAIL/WARN/EXCEPTED/PASS. (3) gate.py
  --findings-out persists the annotated stream (action+reason per finding); decision
  lists now carry fingerprint. (4) normalize.py: gitleaks commit metadata now kept in
  metadata.commit; grype fix lives under vulnerability.fix (not match.fix). (5) report
  dedupes by fingerprint within a tool (gitleaks.sarif + -full + -repro = 2 unique
  rows, not 9). (6) Jenkinsfile: stage 'gate + report' runs the trio, archives
  reports/security-report/. (7) .gitignore now excludes audit/, findings.jsonl,
  gated.jsonl, gate-decision.json, raw/, reports/security-report/.
- Evidence: tools/report.py, tools/gate.py, tools/normalize.py, Jenkinsfile; real
  artifacts → 7 unique findings, gate FAIL 11/4/2.
- Reuse: run the trio in order; exit 1 from gate still blocks (report runs with || true
  after it in Jenkins so the report renders even on failure).

## 2026-08-18 — Gate owns the workflow status: WARN/FAIL/ERROR exit codes
- Context: Jenkinsfile neutralized the gate with `|| true` and the gate only returned
  1 on hard fail — the gate could never block, and a broken scan stage (absent
  findings) silently passed as green.
- Decision: gate.py now exits 0=pass / 1=warn / 2=fail / 3=error, recorded in
  gate-decision.json.status. ABSENT findings input = ERROR (fail-closed, exit 3) —
  an empty scans dir is never a pass; an EMPTY findings stream IS a legit pass.
  Jenkinsfile reads the status back: fail/error -> error() (red), warn -> unstable()
  (yellow), report always renders (python exit neutralized, no `|| true` needed).
- Evidence: tools/gate.py (STATUS_EXIT, absent-input branch), Jenkinsfile
  (gate + report stage), tools/report.py badges, docs/DESIGN.md §4.3.
- Reuse: status is the contract between gate and CI; exit codes are the encoding.

## 2026-08-18 — App enrichment: routes mapped to pipeline stages
- Context: user asked to enrich the demo app so it exercises every stage of the
  workflow (Jenkinsfile + docs/DESIGN.md + docs/idea.md).
- Memory: (1) EXC-0042 fingerprint d22854fb… = sha256("semgrep|security.semgrep.
  no-md5-hashing|src/app/app.py|43|return hashlib.md5(password.encode()).hexdigest()")
  — computed from the UN-STRIPPED SARIF uri "src/app/app.py" (pre-lstrip code),
  so the md5 return statement MUST stay on app.py line 43 or the exception
  silently stops applying (EXCEPTION_UNUSED in audit). Line 43 is a hard
  invariant for future edits. (2) New routes: /export/notes (CSV, ZAP surface),
  /login+/logout (session auth; /admin honors session), /api/notes (JSON),
  /metrics (numeric gauge), /demo/banner (release metadata). (3) config.py now
  env-driven with the gitleaks seed at lines 9-10 (any re-line must keep the
  seed stable or re-baseline gitleaks findings). (4) `import csv, io` style
  multi-imports fail ruff E401 — split them.
- Evidence: app/app.py, app/config.py, app/templates/*, app/tests/test_app.py
  (11 tests), live gunicorn smoke all green; gate e2e on synthetic scan dir
  shows md5 finding EXCEPTED / EXC-0042 applied.
- Reuse: before adding/removing ANY line above app.py:43, re-verify the
  fingerprint; run `python tools/normalize.py + gate.py` on a scan dir as the
  exception regression test.

## 2026-08-19 — VEX demo: seeded gunicorn CVE + OpenVEX not_affected (bd devsecops-demo-836)

- Context: Repo needed a VEX story; docs/DESIGN.md §4.1 seed #5 was broken — it claimed gunicorn==22.0.0 as "the seeded critical" for CVE-2024-6827, but 22.0.0 is the FIXED version, so no scanner ever fired.
- Decision: Pin `app/requirements.txt` to `gunicorn==21.2.0` (vulnerable, fix 22.0.0) so Trivy fs reports CVE-2024-6827 CRITICAL, then ignore it with an OpenVEX document at `security/trivy/vex.openvex.json` (`status: not_affected`, `justification: vulnerable_code_not_in_execute_path`, PURL `pkg:pypi/gunicorn@21.2.0`).
- Memory: Trivy filters VEX'd vulns at scan time (`--vex file`), logs `Filtered out the detected vulnerability {"VEX format": "OpenVEX", ...}`; OpenVEX covers the fs target (CycloneDX VEX needs an SBOM + BOM-Links). VEX ≠ `.trivyignore`: it carries status/justification/impact_statement and is tool-agnostic.
- Evidence: trivy.dev/docs/v0.51/guide/supply-chain/vex/; docs/DESIGN.md rows updated; docs/VEX.md walkthrough; JSON validated.
- Reuse: run `trivy fs --scanners vuln --severity CRITICAL,HIGH [--vex security/trivy/vex.openvex.json] app/requirements.txt` to demonstrate; the VEX pin stays the same while the accepted-risk story is told.
