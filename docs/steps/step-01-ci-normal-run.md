# Step 01 — CI normal run: scanners fire, gate decides

| | |
| --- | --- |
| Pipeline | `Jenkinsfile.ci` (multibranch — PR branch) |
| Mode | **Normal run** (the seeded findings make this build red BY DESIGN) |
| Prereqs | CI job configured per SETUP_DEMO.md §9.2 |
| Expected outcome | Build FAILS at `gate + report` with the seeded gitleaks + semgrep findings; every scan stage ran; all SARIFs + `security-report/report.md` archived |

## Objective

Show that the CI half is a **complete control loop**: four independent scanners,
one decision point, one human-readable verdict — and that the failure state is
deliberate and interpretable, not a broken pipeline.

## Walkthrough

### 1. Trigger the build

Push a commit to the branch Jenkins watches, or "Build Now" on the branch job.

🖼 `assets/screenshots/step-01-01-trigger.png` — the run appears in Build History,
timestamped. Show the job the run belongs to (branch name visible).

### 2. Stage View

Open the running build → **Stage View**.

🖼 `assets/screenshots/step-01-02-stage-view.png` — full stage list:
`cleanup → checkout → fmt-lint-test → secret-scan → SAST - semgrep → SCA - syft+grype
→ IaC - trivy → gate + report`. Point out: stages 3–6 are green/blue (scans ran),
stage 7 (gate) red. That contrast is the story: *scanners don't fail builds — the
gate does.*

### 3. Scanner evidence, one by one

Walk each stage's console log and the archived artifacts. Expected content below is
the **seed contract** — if a finding is missing, the seed or its fingerprint moved
(see `docs/DESIGN.md` §4.2).

- **secret-scan (gitleaks v8.21.2)** — `reports/gitleaks.sarif` contains the
  `demo-api-token` finding for `ds-demo-<32hex>` in `app/config.py` (redacted).
- **SAST (semgrep 1.155.0)** — `reports/semgrep.sarif` contains:
  - `security.semgrep.no-formatted-sql` → `app/db.py:60` (SQLi seed, reachable from
    `/demo/unsafe-search`) — expected **FAIL** class.
  - `security.semgrep.no-md5-hashing` → `app/app.py:43` — expected **EXCEPTED**
    (EXC-0042) — that is step 02's story.
- **SCA (syft v1.51.0 + grype v0.115.0)** — `reports/sbom.cdx.json` (CycloneDX) +
  `reports/grype.json`: flask 3.0.3 CVEs (LOW/MEDIUM → pass), pytest 8.3.4 GHSA
  (LOW/MEDIUM), gunicorn CVE-2024-6827 CRITICAL (source-level scan sees it; the
  CD image gate VEX-filters it — see step 03).
- **IaC (trivy 0.74.0 config)** — `reports/trivy.sarif` — misconfiguration
  checks + org Rego (DS-001/002/003 names appear in rule ids).

🖼 `assets/screenshots/step-01-03-secret-scan.png` — gitleaks console output +
the SARIF finding (file, line, redacted secret).
🖼 `assets/screenshots/step-01-04-sast.png` — semgrep finding with the SQL
interpolation source→sink block.
🖼 `assets/screenshots/step-01-05-sca.png` — grype JSON row for
CVE-2024-6827 (severity, fix version 22.0.0).
🖼 `assets/screenshots/step-01-06-iac.png` — trivy config SARIF rows (builtin +
ReGo rule ids).

### 4. The gate

Open the `gate + report` stage console. Expected console lines:

```
gate verdict: fail — N fail / M warn / K pass
```

and the curl of `gate-decision.json` (from the archived artifacts):

```json
{ "status": "fail",
  "counts": { "fail": 2, "warn": 1, "pass": ... },
  ... }
```

🖼 `assets/screenshots/step-01-07-gate.png` — console verdict line + the
`gate-decision.json` file view together.
🖼 `assets/screenshots/step-01-08-report.png` — first page of
`reports/security-report/report.md`: badges (FAIL/WARN/EXCEPTED), SAST section with
the source→sink block.

### 5. Close the loop

From the report, trace a finding back to the code line. This is the "findings are
actionable" moment: the candidate reads the violation off the report and points at
the source.

## What to point out (interview callouts)

- **catchError + gate pattern**: scan stages marked red by `catchError` still let
  the gate + report run — the build's final color is *owned by the gate*, and the
  report ALWAYS renders (even on failure) so developers get the why.
- **Fail-closed**: if a scan artifact were missing, the gate would ERROR —
  highlight the `status: error` semantics.
- **Reproducible tools**: every scanner is version-pinned (`environment` block) —
  noise is a credibility killer; pinning is the first noise-control.
- **No credentials touched** in CI: the PR tier is untrusted by construction.

## Artifacts to download (from the build)

`reports/gitleaks.sarif`, `reports/semgrep.sarif`, `reports/sbom.cdx.json`,
`reports/grype.json`, `reports/trivy.sarif`, `reports/security-report/report.md`,
`gate-decision.json`, `findings.jsonl`.

## Verification checklist

- [ ] Build ends red with verdict `fail` at the gate stage (not at a scanner)
- [ ] gitleaks finding present + redacted; semgrep SQLi + MD5 findings present
- [ ] grype shows CVE-2024-6827 CRITICAL for gunicorn (source view)
- [ ] trivy SARIF lists DS-* Rego rules
- [ ] `security-report/report.md` renders with FAIL/WARN/EXCEPTED badges
- [ ] all screenshots above captured and committed under `assets/screenshots/`

## Capture checklist

- [ ] `step-01-01-trigger.png`
- [ ] `step-01-02-stage-view.png`
- [ ] `step-01-03-secret-scan.png`
- [ ] `step-01-04-sast.png`
- [ ] `step-01-05-sca.png`
- [ ] `step-01-06-iac.png`
- [ ] `step-01-07-gate.png`
- [ ] `step-01-08-report.png`