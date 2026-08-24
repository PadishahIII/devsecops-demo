# Step 02 — CI yellow path: WARN, exceptions, and VEX

| | |
| --- | --- |
| Pipeline | `Jenkinsfile.ci` |
| Mode | **Soft-failure path** — the gate's non-blocking face |
| Prereqs | Step 01 artifacts available (same build works) |
| Expected outcome | Show that `warn` → `UNSTABLE` (yellow, not red), that EXC-0042 turns the MD5 finding into `EXCEPTED` with an audit row, and that the VEX document filters the gunicorn CVE at scan time — with evidence, not silence |

## Objective

The gate must not be a binary bomb. This step proves the **three non-blocking
mechanisms** — warnings, expiring exceptions, and VEX — and how each one stays
auditable. This is the "severity alone is never the verdict" pitch.

## Walkthrough

### 1. The WARN finding

In `gate-decision.json` from step 01, locate the MD5 finding:

```
rule: security.semgrep.no-md5-hashing | path: app/app.py | line: 43
action: EXCEPTED (EXC-0042, expires 2026-09-13)
```

and the warning-class finding (if any — e.g. low/medium SCA noise is `pass`, a
high-severity non-class finding would be `warn`). Explain the mapping:
`severity_defaults: critical=fail, high=warn, medium=pass`.

🖼 `assets/screenshots/step-02-01-warn-row.png` — the decision JSON rows for the
MD5 finding (fingerprint + action + exception id).

### 2. What EXCEPTED means

Open `security/exceptions.yaml` — EXC-0042 carries: fingerprint, `approved_by`,
`date`, `expires`, `reason`, `ticket`. Two properties matter:

- **Expiry** — after 2026-09-13 the finding fails closed again (no silent
  whitelist).
- **Fingerprint matching** — the exception matches ONE exact finding
  (`rule|path|line|snippet hash`). Move the code → the exception silently stops
  applying and the finding is `EXCEPTION_UNUSED` in the audit. It is
  self-invalidating by design.

🖼 `assets/screenshots/step-02-02-exception.png` — `exceptions.yaml` EXC-0042
block annotated (expires, ticket).

### 3. The audit trail

From the build artifacts, open `audit/exceptions-audit.jsonl` (also archived):
rows show `EXCEPTION_APPLIED` for the MD5 finding. Note: `EXCEPTION_UNUSED` is the
alarm row you WANT to see in a talk about stale exceptions.

🖼 `assets/screenshots/step-02-03-audit.png` — audit JSONL rows.

### 4. VEX at scan time (bonus demo — local, 2 minutes)

From `docs/VEX.md`, run locally:

```bash
trivy fs --scanners vuln --severity CRITICAL,HIGH app/requirements.txt                        # CVE-2024-6827 present
trivy fs --scanners vuln --severity CRITICAL,HIGH --vex security/trivy/vex.openvex.json app/requirements.txt
```

Console shows: `Filtered out the detected vulnerability {... "CVE-2024-6827",
"status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"}`.

🖼 `assets/screenshots/step-02-04-vex.png` — the two-terminal diff: finding
present without `--vex`, filtered with `--vex`, filter log line visible.

### 5. The yellow build

Show the build result: **UNSTABLE** (yellow), not failed. `gate.py` exit 1 = warn
→ Jenkins `unstable()`.

🖼 `assets/screenshots/step-02-05-unstable.png` — build summary badge UNSTABLE +
console line `gate WARN — non-blocking warnings present`.

## What to point out (interview callouts)

- **VEX ≠ `.trivyignore`**: VEX carries *status + justification + impact_statement*
  — a decision with evidence; `.trivyignore` is a bare "don't show it".
- **Exceptions can't whitelist rules**, only exact findings; criticals can never be
  excepted (`exceptions.max_severity: high`).
- **The audit file is machine-readable** — the future vuln-management platform
  (DefectDojo, bd devsecops-demo-2ct) consumes these rows without pipeline changes.
- **Anti-pattern being avoided**: "delete the exception to make it red again"
  — expiry does this automatically.

## Artifacts to download

`gate-decision.json`, `audit/exceptions-audit.jsonl`, `reports/security-report/report.md`
(EXCEPTED badge section), `security/exceptions.yaml`, `security/trivy/vex.openvex.json`.

## Verification checklist

- [ ] MD5 finding shows `EXCEPTED`/`EXC-0042` with the applied audit row
- [ ] WARN-class findings (if present) map to UNSTABLE, not FAILURE
- [ ] Local VEX demo shows the before/after diff and the filter log line
- [ ] all screenshots captured and committed

## Capture checklist

- [ ] `step-02-01-warn-row.png`
- [ ] `step-02-02-exception.png`
- [ ] `step-02-03-audit.png`
- [ ] `step-02-04-vex.png`
- [ ] `step-02-05-unstable.png`