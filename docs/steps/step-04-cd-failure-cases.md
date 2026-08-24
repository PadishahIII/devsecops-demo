# Step 04 — CD failure cases: when the gate blocks

| | |
| --- | --- |
| Pipeline | `Jenkinsfile.cd` |
| Mode | **Error paths** (pick per audience: the DAST block is the money shot) |
| Prereqs | Step 03 ran once (baseline works) |

This file covers the three ways CD can go red on purpose — and why each failure
shape is a design feature. **Run all three against a throwaway `demo-staging`
namespace; never demo failure cases against production.**

---

## Case 1 — DAST SQLi blocks the promotion gate (the money shot)

Trigger: `ENVIRONMENT=staging`, `RUN_DAST=true` on the seeded app. ZAP finds the
SQLi on `/demo/unsafe-search` (High).

| | |
| --- | --- |
| Expected | Build red at `Vuln Gate - incl. DAST` — DISTINCT from the image gate: GATE #1 passed, signing/deploy already happened. The staging deploy is real (that's the story: *runtime findings only surface after the thing is live — that is why you scan staging, not prod*) |

Walkthrough:

1. Build to staging normally (step 03 path). 
2. `DAST - ZAP in-cluster` completes — `zap-exit.txt` says `zap exit=1`.
3. **GATE #2**: `gate verdict: fail — …` with the DAST line
   `DAST verdict: 1 fail / … warn / … pass (tracked separately)`.
4. `gate-decision-dast.json`: the SQLi finding carries `"category": "dast"`,
   evaluated against `policy.dast` (`fail_rule_classes`/severity high→fail).
5. Build FAILURE. `Production Deployment` stage never appears.

Point out the **design contrast**: the SAME SQLi rule in the static SAST scan was a
WARN-class finding — a finding on a **live endpoint** is a different risk class,
so the DAST policy flips high→fail and the promotion stops.

🖼 `assets/screenshots/step-04-01-dast-block.png` — gate #2 console: fail verdict
+ DAST line + failing finding (rule, URL, category).
🖼 `assets/screenshots/step-04-02-dast-decision.png` — `gate-decision-dast.json`:
the SQLi entry with `category: dast` and `action: fail`.
🖼 `assets/screenshots/step-04-03-zap-report.png` — `reports/zap-report.json`
alert row for the SQLi (url `/demo/unsafe-search`, risk High).

## Case 2 — Fail-closed: a missing scan artifact is an ERROR, not a pass

| | |
| --- | --- |
| Trigger | Simulate a broken scan: temporarily rename/remove `reports/trivy.sarif` (e.g. by breaking the trivy invocation in a scratch branch) or run with the trivy stage failing |
| Expected | GATE #1 hard-fails with `gate ERROR — missing scanner artifact(s): …` — the build aborts BEFORE sign/deploy. The log never prints a pass verdict |

Point out: an empty findings stream alone would not save a build — the gate only
evaluates what `normalize.py` found, so a dead scanner can't masquerade as a clean
one. This is the trust-critical property of the whole design.

🖼 `assets/screenshots/step-04-04-fail-closed.png` — gate #1 console:
`gate ERROR — missing scanner artifact(s)` + build aborting at that stage.

## Case 3 — Image gate blocks pre-sign (static path)

| | |
| --- | --- |
| Trigger | Any static CRITICAL finding that is not excepted (e.g. temporarily introduce one; or drop the VEX file so the gunicorn CVE-2024-6827 CRITICAL surfaces in trivy image) |
| Expected | GATE #1 fails → build aborts **before** `Sign Image` — the "nothing signed from an ungated image" property, visible in the Stage View as a stop |

🖼 `assets/screenshots/step-04-05-image-gate-block.png` — stage view: abort at
gate, cosign stages never ran (greyed out).

## What to point out (interview callouts)

- **Never the scanner's exit code**: ZAP exits 1 in Case 1 yet the stage is blue —
  the gate owns the verdict, so scanners can be safely noisy/upgraded without
  pipeline rewiring.
- **Two gates, two jobs**: GATE #1 protects what gets signed; GATE #2 protects
  what gets promoted — a DAST failure can never re-litigate the image (separate
  decision files archived).
- **Fail-closed beats fail-open**: error ≠ pass, always.
- **Honesty about runtime risk**: this is exactly why DAST runs on staging, never
  production — and why the hotfix path (ENVIRONMENT=production direct) is gated on
  static findings + verification only (RUN_DAST never targets prod).

## Verification checklist

- [ ] Case 1: red at GATE #2 with `category: dast` + fail action; prod stage absent
- [ ] Case 2: red at GATE #1 with `missing scanner artifact(s)`; no sign stage ran
- [ ] Case 3: red at GATE #1; cosign stages greyed out
- [ ] decision JSONs + ZAP report archived for each case
- [ ] screenshots captured and committed

## Capture checklist

- [ ] `step-04-01-dast-block.png`
- [ ] `step-04-02-dast-decision.png`
- [ ] `step-04-03-zap-report.png`
- [ ] `step-04-04-fail-closed.png`
- [ ] `step-04-05-image-gate-block.png`