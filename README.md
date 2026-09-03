# Gatehouse - a gated, supply-chain-aware delivery pipeline

> [English](README.md) | [中文](README.zh-CN.md)

A production-shaped CI/CD pipeline of turning security scanners into **reliable controls**:

**CI/CD pipeline:**

<img width="828" height="2122" alt="Untitled Diagram drawio (1)" src="https://github.com/user-attachments/assets/05e6032f-c174-4822-92a3-4f5bfb0cbbcc" />

## Security methods included

| Method                      | Tool                                                 | Phase                    | Gate behavior                                                          | Decision/Trade-off                                                                        |
| --------------------------- | ---------------------------------------------------- | ------------------------ | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Secret scanning             | Gitleaks `v8.21.2` (+ org rule `demo-api-token`)     | CI                       | **Fails categorically** (`fail_tools`) — never exceptable              | A leaked secret is a leak regardless of severity                                          |
| SAST                        | Semgrep `1.155.0` (`p/security-audit` + org rules)   | CI                       | Fail critical and specific vuln types, warn high                       | Semgrep is lightweight and shallow, enough for our demo app                               |
| SCA / SBOM                  | Syft `v1.51.0` + Grype `v0.115.0`                    | CI (source) + CD (image) | Severity defaults + **KEV/EPSS overrides**                             | SBOM-first: CycloneDX out, Grype consumes SBOM; the inventory outlives the scan           |
| IaC / manifest              | Trivy `0.74.0` config + **custom Rego** (DS-001/2/3) | CI                       | Org severity OVERRIDES vendor severity; CRITICAL Rego = fail           | Policy-as-code: org risk > vendor labels                                                  |
| Image scanning              | Trivy `0.74.0` + **OpenVEX**                         | CD pre-sign              | Fail-closed gate #1 before anything is signed                          | Never sign/attest an image that failed its gate                                           |
| Image signing + attestation | Cosign (key)                                         | CD                       | Sign digest + SBOM `cyclonedx` attestation, then **self-verify**       | Identity (sig) ≠ inventory (SBOM)                                                         |
| Chart provenance            | Helm `package --sign` (GPG)                          | CD                       | `helm verify` with the **committed** public key                        | Deploy-unit authenticity; tamper detected                                                 |
| DAST                        | ZAP baseline, in-cluster Job                         | CD (staging)             | Stricter `dast:` policy — high=fail, medium=warn                       | Live vulns deserve stricter gate: A finding on a live endpoint is worse than a static hit |
| Runtime verification        | k8s probes + in-cluster smoke Job                    | CD                       | Hard-fail stage with diagnostics-fallback                              | Probes ≠ business logic; smoke proves the app works                                       |
| Policy gate                 | `tools/{normalize,gate,report}.py`                   | CI + CD                  | One decision point per gate; exit codes 0/1/2/3 → pass/warn/fail/error | Read scanners reports, **the gate decides the pipeline state**                            |

---

# Overview

## Continuous Integration (`Jenkinsfile.ci`)

Triggered on PRs and pushes to `main`. Sequential stages for demo determinism; **no credentials** — the PR tier is untrusted.

<img width="1416" height="111" alt="image" src="https://github.com/user-attachments/assets/16130cdf-172a-4b7f-aeb6-60edc08ae201" />

1. **Clone + unit tests** — ruff + pytest

   _Why: cheapest control first; we don't scan broken code._

2. **Secret scanning** — gitleaks over git history (org config, SARIF out, `--redact`).

   _Why: a leaked secret can't be un-leaked — the policy treats gitleaks as categorical (`fail_tools`), no exception possible. Stage red is deferred to the gate (`catchError`): scanner breakage ≠ finding, the gate still decides._

3. **SAST** — semgrep (`p/security-audit` + org rules `no-formatted-sql`, `no-md5-hashing`).

   _Why: generic rules only catch what their vendors think is risky; the org rules carry the risks *this* codebase actually cares about (unsafe SQL, MD5)._

4. **SCA / SBOM** — Syft → CycloneDX SBOM → Grype → report, uploaded to the artifact store.

   _Why: SBOM-first; the inventory outlives the scan and can be re-evaluated as the vuln DB updates._

5. **IaC** — trivy config (builtin checks + org Rego `DS-001/2/3`).

   _Why: Rego policies carry the org's own risk statements — vendor severity gets overridden by org intent._

6. **Gate + report** — `normalize → gate → report`; `fail`/`error` → FAILURE, `warn` → UNSTABLE.

   _Why_: scanners run sequentially for a deterministic demo — in production they would run in parallel. Best-effort: report issues as many as possible, and the gate decides the pipeline status.

## Configurable Gate

[security/policy.yaml](security/policy.yaml) — action precedence: **exceptions** (fingerprint-matched) > **categorical tools** (gitleaks) > **KEV/EPSS** > **severity defaults** (critical=fail, high=warn, medium=pass).

_Why_: we use highly configurable policy to fit different org requirements

## Continuous Delivery (`Jenkinsfile.cd`)

Manual, parameterized. One build → one digest → gated promotion.

<img width="1434" height="75" alt="image" src="https://github.com/user-attachments/assets/0d0b2c9e-4582-4dc8-8aa6-0406657cfe33" />

1. **Build & push image ONCE** — 3 tags (`<sha8>-<BUILD_NUMBER>`, `latest`, `<APP_VERSION>`), digest recorded.

   _Why: immutable identity + convenience pointers; only the digest is ever deployed._

2. **Image SBOM + scan + GATE #1** — syft SBOM, trivy image scan (CRITICAL/HIGH, VEX-filtered).

   _Why: the scanned subject is the exact artifact that will be signed; nothing is signed from an ungated image._

3. **Sign + verify** — cosign sign + SBOM attestation, verified against the public key; helm chart GPG-signed + verified.

   _Why: two independent trust chains_

4. **Deploy staging + DAST + GATE #2** — signed chart deploys the digest-pinned image; in-cluster ZAP baseline; gate evaluates static + DAST findings (stricter `dast:` policy).

   _Why: a runtime finding on a live endpoint is a different risk class; production never gets active scanning._

5. **Verify + manual promote to production** — smoke Job (health, CRUD, search) + evidence; human approval; SAME digest deployed.

   _Why_: promotion is an explicit human decision; we ensure the digest deployed is scanned and trusted._

## Security Policy and CI violations

| `policy.yaml` rule                           | Example in this repo                                              | CI result                                                             |
| -------------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------- |
| `fail_tools: [gitleaks]`                     | `ds-demo-<32hex>` token (seed, `app/config.py`)                   | Build **FAILS** — categorical, no exception possible                  |
| `fail_rule_classes` (SQLi/SSRF/deserial/RCE) | `/demo/unsafe-search` interpolates SQL (seed, `app/db.py:60`)     | Build **FAILS** — reachable injection is blocking even at vendor-High |
| `fail_when` KEV / EPSS ≥ 0.9                 | (metadata-driven; no current finding matches)                     | High+KEV → behaves as Critical                                        |
| `severity_defaults` high → warn              | MD5 password hashing (seed, `app/app.py:43`)                      | **UNSTABLE** unless excepted                                          |
| Exceptions (expiring, fingerprint-matched)   | EXC-0042 (MD5, expires 2026-09-13, ticket SEC-221)                | Finding **EXCEPTED**; audit row written; expiry → fails closed        |
| VEX (`--vex`)                                | gunicorn CVE-2024-6827 = `not_affected` (do-not-fix-forward case) | filtered at scan time — with evidence, not silence                    |
| Fail-closed gate                             | missing `trivy.sarif` / absent findings input                     | **ERROR** — a broken scan never looks like a pass                     |

## End to end showcase

Showcase: **[docs/steps/steps.md](docs/steps/steps.md)**.

## Setup the Demo

Follow **[SETUP_DEMO.md](SETUP_DEMO.md)** — Docker Hub repo + token, kind cluster on the Jenkins agent, cosign + helm GPG keys, GitHub App, Jenkins plugins/credentials (credential IDs: `dockerhub`, `cosign-key`, `cosign-pub`, `kind-kubeconfig`, `helm-signing-key`), and the two multibranch jobs.

## Repository layout

```
Jenkinsfile.ci / Jenkinsfile.cd   the two pipelines (CI = source gates, CD = supply chain + deploy)
app/                              deliberately seeded Flask app (token, SQLi, MD5, gunicorn CVE)
security/                         policy.yaml (gate), exceptions.yaml (expiring), gitleaks/semgrep/trivy-rego/kyverno rules, VEX
tools/                            normalize.py · gate.py · report.py — the policy engine
deploy/helm/notes-app/            single versioned chart: app + DAST Job + smoke Job + regcred
deploy/helm/keys/public.asc       committed chart-signing public key (secret pair is a Jenkins credential)
docs/                             pipeline-stages.md (stage detail) · steps/ (e2e showcase) · DESIGN.md · VEX.md
SETUP_DEMO.md                     environment bring-up guide
```

# Threat Model the Demo Flask App - A Practice

## Trust Boundaries

In order of trust:

1. Internet/attacker
2. Jenkins agent + containers
3. docker registry, kind cluster
4. Flask app process
5. SQLite DB, secrets, signing keys

## Assets

DREAD-style value ranking:

| Asset                                  | Value    | Notes                                |
| -------------------------------------- | -------- | ------------------------------------ |
| Signed image digest + SBOM attestation | Critical | verify-image stage in CD enforces it |
| Notes DB                               | Medium   | demo data                            |
| APP_SECRET_KEY,ADMIN_PASSWORD_HASH     | Medium   | env-driven                           |

## Dataflow

<img width="790" height="473" alt="image" src="https://github.com/user-attachments/assets/c44c3864-b98c-49c3-8dd9-f5d235d9e465" />

## STRIDE

| Threat                 | Risk                                                                                                                            | Pipeline control (countermeasure)                                                                             |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Spoofing               | 1) /login+/admin accept a password query param, md5 hash is crackable, no rate-limiting; 2) Image in registry could be replaced | 1) Semgrep no-md5-hashing -> gate fail -> block CI; 2) cosign key signing + verification, Helm chart Sigining |
| Tampering              | 1) /demo/unsafe-search f-string SQLi; 2) SBOM drift                                                                             | 1) Semgrep no-formatted-sql -> gate fail -> block CI; 2) SBOM attested by cosign                              |
| Repudiation            | No audit logging for POST /notes (anonymous create)                                                                             | no countermeasure; future story: audit log                                                                    |
| Information Disclosure | /export/notes is unauthenticated bulk data exfiltration surface                                                                 | no countermeasure; future story: authentication                                                               |
| Denial of Service      | /demo/unsafe-search '%' wildcard + unbounded LIKE condition + no rate-limiting                                                  | no countermeasure; future story: DDoS protection                                                              |
| Elevation              | -                                                                                                                               | -                                                                                                             |
