# Step 03 — CD staging path: build once, gate, sign, deploy, scan, verify

| | |
| --- | --- |
| Pipeline | `Jenkinsfile.cd` |
| Mode | **Normal path** |
| Params | `ENVIRONMENT=staging`, `RUN_DAST=true`, `PROMOTE_TO_PROD=false`, `APP_VERSION=1.0.0` |
| Prereqs | CD job + kind cluster + credentials per SETUP_DEMO.md §9.3; CI (step 01) green |
| Expected outcome | Build deploys to `demo-staging` with a digest-pinned, cosign-signed, chart-signed image; ZAP DAST runs; vuln gate passes; smoke verification passes; build ends green |

## Objective

The supply-chain story end to end: the image is built **once**, every later step
consumes the same digest; the image is scanned and gated **before** it is signed;
deployment is provenance-signed; runtime is verified — and each of those is a
visible stage with commands in the log.

## Walkthrough

### 1. Kick off the CD build

"Build with Parameters" — show the parameter form filled in.

🖼 `assets/screenshots/step-03-01-params.png` — parameter form:
ENVIRONMENT=staging, RUN_DAST=true, PROMOTE_TO_PROD=false, APP_VERSION=1.0.0.

### 2. Build & push — the three-tag strategy

Console shows: build, `docker login` (stdin-fed), push of
`<sha8>-<BUILD_NUMBER>` + `latest` + `1.0.0`, then:

```
image: docker.io/padishahiii/demo-web-app:<sha8>-<n>
digest: sha256:…
```

`reports/digest.txt` records the digest — the single source of truth for every
later stage.

🖼 `assets/screenshots/step-03-02-tags.png` — console: 3 tags pushed + digest line.

### 3. SBOM + image scan + GATE #1

- `SBOM - syft` → `reports/sbom.cdx.image.json`.
- `Image Scan - trivy` → `--vex security/trivy/vex.openvex.json` (the gunicorn
  CVE-2024-6827 CRITICAL is filtered here with its justification — cross-reference
  step 02).
- `gate + report` (GATE #1) — console: `gate verdict: pass …`; `expected` check
  (`trivy.sarif`, `sbom.cdx.image.json`) demonstrated by *what is NOT in the log*:
  no "missing scanner artifact" error.

🖼 `assets/screenshots/step-03-03-gate1.png` — gate #1 console verdict + the
archived `gate-decision.json` (status pass, counts).

### 4. Sign & verify (image)

`Sign Image && attach SBOM attestation - cosign` then `Verify signature and
attestation - cosign`: `cosign sign --key … digest`, `cosign attest --type
cyclonedx --predicate sbom.cdx.image.json`, then verify both against the public
key. (This is step 06's deep-dive; here a glance suffices.)

🖼 `assets/screenshots/step-03-04-sign.png` — sign + attest lines; note the
`@sha256:…` digest in the signature subject, NOT a tag.

### 5. Package & Sign Chart

`helm package --sign` + `helm verify` — log ends with the chart hash verified
against the committed public key; `.tgz.prov` listed in artifacts.

🖼 `assets/screenshots/step-03-05-chart.png` — package/verify output.

### 6. Deploy to staging

`Deploy` stage: `helm upgrade --install notes … -n demo-staging`, `rollout status
deployment/notes`, `kubectl get pods -o wide`. Show the pod: `runAsUser: 65532`
(non-root), digest image. Console mentions `rendered/values-base.yaml` was
re-specified (Helm doesn't persist `--set`).

🖼 `assets/screenshots/step-03-06-deploy.png` — helm upgrade output + pod list
(image digest visible).

### 7. DAST — ZAP in-cluster

`DAST - ZAP in-cluster`: the Job appears (`kubectl get job dast-scan`), runs the
baseline scan against the staging service, and the report is pulled from the kind
node. Console: `scanning http://notes.demo-staging.svc.cluster.local:80 …`.
If the seeded SQLi fires, the scan verdict is `zap exit=1` — but **the stage does
not fail**: `the gate decides`.

🖼 `assets/screenshots/step-03-07-dast.png` — DAST stage: Job view + log lines
(scan URL, docker cp of the report) + `zap-exit.txt` content.

### 8. GATE #2 — vuln gate incl. DAST

`Vuln Gate - incl. DAST` console: verdict + the separate DAST line
(`DAST verdict: … fail / … warn / … pass (tracked separately)`). For the happy
path, expect the static findings to pass and the DAST SQLi to be the thing to
discuss — see **step 04** for the blocking variant. If the demo audience is short
on time, this is the moment to say "runtime finding on a live endpoint → stricter
policy" and move on.

🖼 `assets/screenshots/step-03-08-gate2.png` — gate #2 console verdict +
`gate-decision-dast.json` (`counts.dast` block).

### 9. Post-deployment verification

`Post-Deployment Verification`: ready-endpoint check (EndpointSlices),
smoke Job logs (`smoke: health OK`, `smoke: create note 201`, `smoke: search
found`), then `verification-rbac.txt` / `verification-netpol.json` /
`verification-events.txt` evidence lines.

🖼 `assets/screenshots/step-03-09-smoke.png` — smoke Job logs with the three
check lines.

### 10. Done — green build

Build result: SUCCESS. Archival list includes both gate decisions, ZAP reports,
the signed-chart `.prov`, and the exception audit.

🖼 `assets/screenshots/step-03-10-success.png` — build summary + archived artifacts
list.

## What to point out (interview callouts)

- **Digest, not tag**: deploy uses `@sha256:…`; `latest`/`1.0.0` are convenience
  pointers only. Tag rewrite can't redirect the deploy.
- **Nothing is signed before the image gate passes** — trust is applied to gated
  artifacts only.
- **Progressive delivery via Helm values**: the same chart renders app, DAST Job,
  smoke Job — `--set dast.enabled=true` toggles the scan, no parallel manifests.
- **DAST in-cluster, not from the agent**: the scan hits the service as a cluster
  client; report retrieval is the interesting engineering bit (kind node hostPath
  + `docker cp`, documented in-deployment).

## Artifacts to download

`reports/digest.txt`, `reports/sbom.cdx.image.json`, `reports/trivy.sarif`,
`gate-decision.json`, `gate-decision-dast.json`, `reports/zap-report.json` (+ .html),
`reports/security-report-dast/report.md`, `notes-app-*.tgz.prov`.

## Verification checklist

- [ ] 3 tags pushed; digest written to `reports/digest.txt`
- [ ] GATE #1 verdict pass or explicit fail with reason
- [ ] cosign sign + attest + verify all green
- [ ] helm verify printed the chart hash OK
- [ ] staging deployment running with digest image + non-root
- [ ] ZAP Job completed; `zap-report.json` archived
- [ ] GATE #2 verdict line + `counts.dast` present
- [ ] smoke Job: health/create/search lines OK
- [ ] build ends SUCCESS
- [ ] screenshots captured and committed

## Capture checklist

- [ ] `step-03-01-params.png`
- [ ] `step-03-02-tags.png`
- [ ] `step-03-03-gate1.png`
- [ ] `step-03-04-sign.png`
- [ ] `step-03-05-chart.png`
- [ ] `step-03-06-deploy.png`
- [ ] `step-03-07-dast.png`
- [ ] `step-03-08-gate2.png`
- [ ] `step-03-09-smoke.png`
- [ ] `step-03-10-success.png`