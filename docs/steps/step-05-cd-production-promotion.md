# Step 05 — CD production promotion: the same digest, gated by a human

| | |
| --- | --- |
| Pipeline | `Jenkinsfile.cd` |
| Mode | **Full path: staging → production** |
| Params | `ENVIRONMENT=staging`, `RUN_DAST=true`, `PROMOTE_TO_PROD=true` |
| Prereqs | Step 03 path must pass (this run reuses it: gate #2 + verification must be green) |
| Expected outcome | After the manual approval, `demo-production` receives the SAME digest that was built, gated, signed, scanned and verified for staging; build ends green; evidence archives |

## Objective

The promotion is the demo's final control: **byte-identical artifact + explicit
human decision**. No rebuild, no new tags, no override — the deployed image is the
one with the audit trail.

## Walkthrough

### 1. Run the full path

Trigger `ENVIRONMENT=staging, PROMOTE_TO_PROD=true` — the build auto-runs
everything from step 03. Land at the `Production Deployment` stage: the build sits
at the **input approval**. Show the paused state (yellow hourglass) and the
approval message quoting the DAST note ("The vuln gate (incl. DAST) and
post-deployment verification passed for staging.").

🖼 `assets/screenshots/step-05-01-approval.png` — the input dialog with the
message + "Deploy to Production" button; build paused at the stage.

### 2. Approve, watch the promote

Click approve. Console:

```
promoting docker.io/padishahiii/demo-web-app@sha256:… to demo-production via Helm
```

Note the **`@sha256:…`** — the digest string is what made it through GATE #2 and
verification, not a re-resolved tag. Then `rollout status` + `kubectl get pods -o
wide`.

🖼 `assets/screenshots/step-05-02-promote.png` — promote log line (digest
highlighted) + production pod list (digest image, non-root).

### 3. Prove identity across environments

From the archived artifacts cross-check: the digest in `reports/digest.txt` == the
digest in step 03's staging deployment == the digest in demo-production's pod.
One command is enough for the audience:

```bash
kubectl get deployment notes -n demo-staging  -o jsonpath='{.spec.template.spec.containers[0].image}'
kubectl get deployment notes -n demo-production -o jsonpath='{.spec.template.spec.containers[0].image}'
```

🖼 `assets/screenshots/step-05-03-same-digest.png` — side-by-side terminal output
of the two jsonpath commands.

### 4. The verification evidence

Open the archived `verification-rbac.txt`, `verification-netpol.json`,
`verification-events.txt` — the "we looked before we promoted" artifacts.

🖼 `assets/screenshots/step-05-04-evidence.png` — evidence file snippets
(events tail showing the rollout).

### 5. Production is not a scan target

Highlight: in production there is no DAST Job, no smoke Job — the chart renders
the app-only production object set (namespace + regcred + deployment + service).
Rolling verification happened on staging; production gets the same bytes.

🖼 `assets/screenshots/step-05-05-prod-objects.png` — `kubectl get all -n
demo-production` (no dast/smoke Jobs) + production `values-production.yaml` view.

## Bonus: the hotfix path (skip DAST vs prod)

`ENVIRONMENT=production, PROMOTE_TO_PROD=false` deploys straight to production,
skipping staging (documented as the "hotfix" route). `Initialize` rejects
`ENVIRONMENT=production + PROMOTE_TO_PROD=true` (mutually exclusive) and
`RUN_DAST` never targets production. If time allows, show the rejection error
committing the guardrail.

🖼 `assets/screenshots/step-05-06-param-guard.png` — `Initialize` error for the
invalid param combination.

## What to point out (interview callouts)

- **Manual approval between gate and prod** — the human is a control, not a
  bottleneck: the decision is binary (approve/abort), all evidence is in the build.
- **Controlled blast radius**: staging risk-took the DAST; production risk-took
  nothing new.
- **Idempotent by design**: same chart, same values strategy — promoting is just
  another `helm upgrade -f` with the identical base values file.

## Artifacts to download

`gate-decision-dast.json`, `reports/security-report-dast/report.md`,
`verification-*.txt/json`, `notes-app-*.tgz.prov`, `reports/zap-report.json`.

## Verification checklist

- [ ] Build paused at input with DAST-qualified message
- [ ] Promote used `@sha256:…` (same digest, no re-resolve)
- [ ] demo-production pod: digest image, non-root uid
- [ ] cross-env digest comparison identical
- [ ] evidence files archived
- [ ] screenshots captured and committed

## Capture checklist

- [ ] `step-05-01-approval.png`
- [ ] `step-05-02-promote.png`
- [ ] `step-05-03-same-digest.png`
- [ ] `step-05-04-evidence.png`
- [ ] `step-05-05-prod-objects.png`
- [ ] `step-05-06-param-guard.png`