# devsecops-demo — a gated, supply-chain-aware delivery pipeline

A production-shaped demo of turning security scanners into **reliable controls**:
PR-time gating, build-once digest promotion, signed + attested artifacts, policy-as-code
gates with expiring exceptions, runtime verification (DAST + post-deployment smoke),
and a manual-gated promotion path — all running on a real Jenkins instance against a
small-but-deliberately-vulnerable Flask app.

The pipeline itself is the artifact; the app is a vehicle. Every stage ships with the
**decision** behind it, because "why this gate behaves this way" is the point of this demo.

```
┌────────────────────────── PR / feature branch (Jenkinsfile.ci) ──────────────────────────┐
│                                                                                          │
│  checkout → fmt/lint/test (ruff + pytest)                                                │
│  ──── parallel-in-concept, sequential for the demo ────                                  │
│  │  gitleaks  (org rule set: ds-demo-<32hex> token, SARIF out)                           │
│  │  semgrep   (p/security-audit + org rules: no-formatted-sql, no-md5-hashing)           │
│  │  syft+grype(SBOM CycloneDX → vulnerability DB)                                        │
│  │  trivy     (IaC config: builtin checks + org Rego DS-001/2/3)                         │
│  └──────────────┬──────────────────────────────────────────────┘                         │
│                 ▼                                                                        │
│  GATE: normalize.py → gate.py (policy.yaml + exceptions.yaml) → report.py                │
│         critical=FAIL / high=WARN / exceptions apply / gitleaks=categorical              │
│         gate verdict → build FAILURE | UNSTABLE | PASS                                   │
└──────────────────────────────────────────────────────────────────────────────────────────┘
                                          │ only gate-green code reaches main
                                          ▼
┌────────────────────────────── main (Jenkinsfile.cd, manual) ────────────────────────────┐
│                                                                                          │
│  build & push image ONCE (3 tags: <sha8>-<build#>, latest, <APP_VERSION>) → digest       │
│  syft SBOM  →  trivy image scan (CRITICAL/HIGH, VEX-filtered)                            │
│  GATE #1 (image gate, fail-closed on missing artifacts) — nothing is signed before       │
│  the gate passes.  cosign sign (key) + SBOM attestation → verify signature+attestation   │
│  helm package --sign (GPG provenance) + helm verify (committed public key)               │
│  deploy STAGING via signed chart (image pinned BY DIGEST, non-root PSS-ish context)      │
│  ZAP baseline DAST in-cluster (staging only) → GATE #2 (incl. DAST, stricter dast:       │
│  policy: high=fail, medium=warn) → post-deployment verification (health + smoke CRUD)    │
│  [manual approval] → deploy PRODUCTION — the SAME digest, never rebuilt                  │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

> 🖼 **SCREENSHOT (pending — bd devsecops-demo-hrj):** `assets/screenshots/pipeline-overview.png`
> Replace this ASCII diagram with the real Jenkins stage-view captures of both jobs.

## Security methods included in this demo

| Method                      | Tool                                                                                         | Phase                    | Gate behavior                                                                    | Decision                                                                                 |
| --------------------------- | -------------------------------------------------------------------------------------------- | ------------------------ | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Secret scanning             | Gitleaks `v8.21.2` (+ org rule `demo-api-token`)                                             | CI                       | **Fails categorically** (`fail_tools`) — never exceptable                        | A leaked secret is a leak regardless of severity; rules are deterministic, SARIF out     |
| SAST                        | Semgrep `1.155.0` (`p/security-audit` + org rules)                                           | CI                       | Fail by **exploitability class** (SQLi/SSRF/deserialization/RCE), warn otherwise | Vendor severity undervalues reachable injection — class override is the risk model       |
| SCA / SBOM                  | Syft `v1.51.0` + Grype `v0.115.0`                                                            | CI (source) + CD (image) | Severity defaults + **KEV/EPSS overrides**                                       | SBOM-first: CycloneDX out, Grype consumes SBOM; known-exploited behaves like Critical    |
| IaC / manifest              | Trivy `0.74.0` config + **custom Rego** (DS-001 privileged, DS-002 non-root, DS-003 seccomp) | CI                       | Org severity OVERRIDES vendor severity; CRITICAL Rego = fail                     | Policy-as-code is the showpiece: org risk > vendor labels                                |
| Image scanning              | Trivy `0.74.0` + **OpenVEX**                                                                 | CD pre-sign              | Fail-closed gate #1 before anything is signed                                    | Never sign/attest an image that failed its gate                                          |
| Image signing + attestation | Cosign (key)                                                                                 | CD                       | Sign digest + SBOM `cyclonedx` attestation, then **self-verify**                 | Identity (sig) ≠ inventory (SBOM) — each artifact separate                               |
| Chart provenance            | Helm `package --sign` (GPG)                                                                  | CD                       | `helm verify` with the **committed** public key                                  | The deploy unit is signed; tamper = "sha256 sum does not match"                          |
| DAST                        | ZAP baseline, in-cluster Job                                                                 | CD (staging)             | Dedicated `dast:` policy — high=fail, medium=warn, runtime classes block         | A finding on a live endpoint is worse than the same rule in static scan                  |
| Runtime verification        | k8s probes + in-cluster smoke Job (health, CRUD, search)                                     | CD                       | Hard-fail stage with diagnostics-fallback                                        | Probes ≠ business logic; the smoke Job proves the app actually works                     |
| Policy gate                 | `tools/{normalize,gate,report}.py`                                                           | CI + CD                  | One decision point per gate; exit codes 0/1/2/3 → pass/warn/fail/error           | Scanners produce findings; **the gate owns the verdict** — never the scanner's exit code |

---

# Overview

## Continuous Integration (`Jenkinsfile.ci`)

Triggered on every pull request and on push to `main` (multibranch). Runs in
**sequential stages for demo determinism** (see Further optimization). Uses **no
credentials** — the PR tier is untrusted and read-only by construction.

> 🖼 **SCREENSHOT (pending):** `assets/screenshots/ci-01-stage-view.png` — Jenkins run → Stage View for a full CI build.

**The pipeline in four steps — and the reasoning behind each:**

1. **Code is cloned from the Git server and the unit tests are run.** The multibranch job checks out the branch from GitHub (every PR and every push to `main`), then runs `ruff` (lint) and `pytest` (unit tests) inside a pinned `python:3.12.7-slim` container.
   **Why?** The cheapest control runs first: broken code is rejected in under a minute, before any security tool spends compute — we do not scan broken code. Pinning the toolchain keeps the stage reproducible.
2. **A dependency report is generated from the source code and uploaded to the report server repository.** Syft produces a CycloneDX SBOM of the source tree; Grype cross-references it with the vulnerability database; the SBOM and the vulnerability report are archived as build artifacts — the Jenkins artifact store is this pipeline's report server.
   **Why?** SBOM-first: the inventory is a deliverable that outlives the scan, so the same SBOM can be re-evaluated when the vulnerability DB updates — DB freshness becomes a schedule concern, not a per-build one. Uploading every report keeps a per-branch audit record.
3. **The code is analyzed by static scanners for anti-patterns and misconfiguration.** Gitleaks scans the git history for leaked secrets (org rule set), Semgrep analyzes the source for exploitable patterns (`p/security-audit` + org rules: formatted SQL, MD5), and Trivy scans the IaC manifests with builtin checks plus org Rego policies.
   **Why?** (i) The org rule sets are the differentiator — they encode *our* risk, and Semgrep is chosen over a generic quality gate because its security rules ship SARIF-compatible, class-based results that can *fail* the build. (ii) In the reference design these scanners run in parallel; the demo runs them sequentially so every stage and its report is deterministic and screenshotable. (iii) Scanner breakage ≠ finding: a failing scan marks the stage red via `catchError`, but the verdict is always deferred to the gate so reports still render.
4. **Every finding is evaluated by a single policy gate.** `normalize.py` folds all scanner outputs into one findings stream, `gate.py` applies `security/policy.yaml` (severity → exploitability class → tool → KEV/EPSS) plus expiring exceptions, and `report.py` renders the human-readable report. The verdict maps onto the build: `fail`/`error` → FAILURE, `warn` → UNSTABLE.
   **Why?** One decision point can be fail-closed (absent scanner input = ERROR, never a pass), consistent across tools, and auditable — every build archives `gate-decision.json` and the exception audit trail. Scanners report; the gate decides.

The same pipeline in implementation detail — exact commands, gate behavior, and failure modes:

| #   | Stage                  | What it does                                                                                                                                                                     | Failure mode                                                       | Why this design                                                                                                                       |
| --- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `cleanup` / `checkout` | `cleanWs()`, SCM checkout                                                                                                                                                        | —                                                                  | Hermetic workspace: no state leaks between builds                                                                                     |
| 2   | `fmt-lint-test`        | `python:3.12.7-slim` agent, `ruff check app` (hard fail), `pytest -q --junitxml`                                                                                                 | Build red on lint or test failure                                  | Fast inner-loop quality gate BEFORE security scans — don't scan broken code                                                           |
| 3   | `secret-scan`          | Gitleaks on the git history (`git /src`), custom config `security/gitleaks.toml`, SARIF out, `--redact`                                                                          | Stage red via `catchError`, **verdict deferred to the gate**       | Scanner breakage ≠ finding: `catchError` marks the build but the gate decides; the report must still render                           |
| 4   | `SAST - semgrep`       | `p/security-audit` registry + org rules (`no-formatted-sql`, `no-md5-hashing`)                                                                                                   | Same catchError→gate pattern                                       | Registry rules close the gap the org rules define — the org rules are what make this repo's story real                                |
| 5   | `SCA - syft+grype`     | Syft emits CycloneDX SBOM (`dir:.`); Grype consumes the SBOM against its DB (persistent `grype-db` volume)                                                                       | Same                                                               | SBOM-first workflow; the SBOM itself is archived as a CI artifact — vulnerability DB freshness is a cron concern, not a per-build one |
| 6   | `IaC - trivy`          | `trivy config` on the repo: builtin checks + **custom Rego** (`security/trivy/ds-001-privileged.rego`, `ds-002-nonroot.rego`, `ds-003-seccomp.rego`), `--severity CRITICAL,HIGH` | Same                                                               | Rego policies carry the org's _own_ risk statements — vendor severity gets overridden by org intent                                   |
| 7   | `gate + report`        | `normalize.py` → `findings.jsonl` → `gate.py` (policy + exceptions) → `gate-decision.json` → `report.py` → `reports/security-report/report.md`; verdict mapped onto the build    | `fail`/`error` → **FAILURE** (red), `warn` → **UNSTABLE** (yellow) | **Single decision point.** The gate reads back a JSON verdict — the workflow status is _derived from_ the gate, never guessed         |

Each of the steps above is walked through with screenshots in the
[end-to-end showcase](docs/steps/README.md) (`docs/steps/step-01-ci-normal-run.md`,
`step-02-ci-gate-warn-and-exceptions.md`).

### Configurable Gate

`security/policy.yaml` is the one knob. Action precedence (highest wins):

1. **Exceptions** — `security/exceptions.yaml`, matched by _exact finding fingerprint_
   (rule|path|line|snippet hash), always **expiring**, critical never exceptable
2. **Exploitability classes** — `fail_rule_classes`: formatted-SQL/SQLi, SSRF,
   deserialization, RCE → fail regardless of vendor severity
3. **Categorical tools** — `fail_tools: [gitleaks]`: a leaked secret never passes
4. **KEV / EPSS** — known-exploited or EPSS ≥ 0.9 behaves like Critical at high severity
5. **Severity defaults** — critical=fail, high=warn, medium=pass, low=pass

The gate is **fail-closed**: missing/absent scanner input is an `ERROR` (exit 3),
never a pass — a broken scan must not look like a green build. The exception audit
(`audit/exceptions-audit.jsonl`, archived per build + git-ignored) records every
applied/expired/unused exception: if the code moves, the fingerprint stops matching
and the finding **fails closed** instead of silently whitelisting a rule.

### Further optimization (CI)

- **Parallelize the four scanners** — currently sequential for reproducible demo
  runs; they are independent and would fan out a single build from ~10–15 min to
  wall-clock max-of-scans.
- **CI-side image build + digest handoff** (bd devsecops-demo-tpe) — today CI is
  source-scan-only (fast feedback); the image is built once in CD. A build-once
  digest promoted from CI to CD is the documented next step.
- **PR blocking wiring** — the multibranch job + GitHub integration is set up to
  report check status; branch protection enforcing the Jenkins check on `main` is
  a repo-settings step (see SETUP_DEMO.md §6).

## Continuous Delivery (`Jenkinsfile.cd`)

Manual, parameterized, environment-aware. One build → one digest → gated promotion.

> 🖼 **SCREENSHOT (pending):** `assets/screenshots/cd-01-stage-view.png` — full staging→production run, Stage View.

**The pipeline in five steps — and the reasoning behind each:**

1. **The application is packaged as a container image and released to the registry repository.** The image is built once and pushed to Docker Hub (this pipeline's artifact repository), tagged `<sha8>-<BUILD_NUMBER>` (primary), `latest`, and `<APP_VERSION>`; the digest is resolved and recorded for every later stage.
   **Why?** The three-tag strategy gives one immutable, reproducible identity (primary) plus convenience pointers for humans (`latest`, `<APP_VERSION>`) — and only the *digest* is ever deployed, so a tag rewrite can never redirect a rollout.
2. **A dependency report of the image is generated, the image is scanned, and an image gate must pass before trust is applied.** Syft generates the image's CycloneDX SBOM; Trivy scans the image (CRITICAL/HIGH, VEX-filtered); GATE #1 (`runGate`) aborts fail-closed if any expected scanner artifact is missing or any finding is blocking.
   **Why?** The scanned subject is the exact artifact that will be signed — the SBOM is of the *image*, not the source tree. Nothing is signed, attested, or deployed from an ungated image, and a broken scan never looks like a pass.
3. **The image is signed, its SBOM attestation is attached and verified; the deployment chart is packaged and GPG-signed.** Cosign signs the digest and attests the CycloneDX SBOM, then verifies both against the public key; the Helm chart is `helm package --sign`'d and `helm verify`'d using only the committed public key.
   **Why?** Two independent trust chains with zero secret material in the repository (private keys live only in Jenkins credentials): the signature proves identity, the attestation binds the inventory to the artifact, and the chart `.prov` proves deploy-unit authenticity — each verified *inside* the pipeline before anything is deployed.
4. **The same digest is deployed to the staging environment, where it is pentested by ZAP (DAST) against a second gate.** The signed chart deploys the digest-pinned image to the kind cluster (staging) under a PSS-style security context; an in-cluster ZAP baseline Job scans the live service; GATE #2 evaluates static + DAST findings against the stricter `dast:` policy (high → fail, medium → warn).
   **Why?** A finding on a live endpoint is a different risk class than a static hit, and staging is where that runtime risk is discovered — production never receives aggressive active scanning. Two separate gates keep the image decision and the promotion decision independently archived.
5. **After post-deployment verification, the same digest is promoted to production behind a manual approval.** Probes plus an in-cluster smoke Job (health, CRUD, search) verify the deployment and archive evidence (RBAC, network policies, events); then a human approves, and the SAME digest — never rebuilt, never re-resolved — is deployed to production.
   **Why?** The promotion is an explicit human decision with all evidence attached to the build, and byte-identical artifacts mean exactly what was scanned, signed, and verified is what runs in production.

The same pipeline in implementation detail — exact commands, gate behavior, and failure modes:

| #   | Stage                                   | What it does                                                                                                                                                                                                                                  | Gate / guard                                                                                                        | Why this design                                                                                                                                                                                                |
| --- | --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `Initialize`                            | Parameter validation: `ENVIRONMENT`/`PROMOTE_TO_PROD` exclusivity; `APP_VERSION` must be a valid tag ≤ 63 chars (k8s label); gate-tool deps (pydantic/pyyaml)                                                                                 | Hard error on bad params                                                                                            | Fail before spending 30 min building; tag-limit check is a k8s-label safety net                                                                                                                                |
| 2   | `build & push image`                    | `docker build` with 3 tags always: `<sha8>-<BUILD_NUMBER>` (primary), `latest`, `<APP_VERSION>`; push to Docker Hub; digest resolved via `buildx imagetools inspect` → `reports/digest.txt`                                                   | Push is a hard requirement (`PUSH_IMAGE=true`): digest/sign/verify need the registry                                | **Three-tag strategy**: immutable reproducible tag (primary) + convenience pointers; the _digest_ is what gets deployed                                                                                        |
| 3   | `SBOM - syft`                           | Syft on the **image** → CycloneDX (`sbom.cdx.image.json`)                                                                                                                                                                                     | —                                                                                                                   | SBOM of the actual artifact (not the source tree), one-to-one with what gets signed                                                                                                                            |
| 4   | `Image Scan - trivy`                    | `trivy image --severity CRITICAL,HIGH`, `--ignore-status affected,will_not_fix,fix_deferred,end_of_life`, **`--vex security/trivy/vex.openvex.json`**                                                                                         | `catchError` + gate                                                                                                 | Only _fixable_ findings matter for a gate; the VEX document is the auditable way to carry an accepted risk (see [docs/VEX.md](docs/VEX.md)) — `.trivyignore` is a suppression, VEX is a decision with evidence |
| 5   | `gate + report` — **GATE #1**           | `runGate()` with `expected: [trivy.sarif, sbom.cdx.image.json]` — **missing artifact → hard error before anything is signed**                                                                                                                 | fail/error → abort                                                                                                  | The single decision point BEFORE trust is applied: nothing is signed, attested, or deployed from an ungated image                                                                                              |
| 6   | `Sign Image && attach SBOM attestation` | Cosign (key from Jenkins File credential): sign the **digest** + attest `--type cyclonedx` with the SBOM predicate                                                                                                                            | Private key never on disk beyond the credential                                                                     | Signature = identity, attestation = inventory; both travel with the digest                                                                                                                                     |
| 7   | `Verify signature and attestation`      | Cosign verify with the **public key** (matching credential)                                                                                                                                                                                   | Hard fail                                                                                                           | Self-check before deploy: we sign, then prove the signature verifies — the demo of the trust chain                                                                                                             |
| 8   | `Package & Sign Chart`                  | `helm package --sign` (GPG, de-armored keyring inside the build), then `helm verify` using **only the committed public key** (`deploy/helm/keys/public.asc`)                                                                                  | Verify with the committed key — no secret key present                                                               | The deploy unit is provenance-signed; `helm verify` output ("Chart Hash Verified") is the artifact                                                                                                             |
| 9   | `Deploy` (staging or hotfix prod)       | `helm upgrade --install` the signed chart with values layered: chart defaults + `values-<env>.yaml` + workspace-only `rendered/values-base.yaml` (image **digest**, registry `dockerConfigJson` — chmod 600, never `--set`); `rollout status` | Digest-pinned image, non-root `runAsUser: 65532`, `allowPrivilegeEscalation: false`, seccomp RuntimeDefault, probes | Build once → deploy the same bytes everywhere; secrets travel via a workspace file, not the process list                                                                                                       |
| 10  | `DAST - ZAP in-cluster` (staging only)  | Helm toggles a `dast` Job rendering ZAP baseline against `notes.demo-staging.svc` (image pinned by digest, `runAsUser 1000`); report lands on a per-run unique hostPath dir in the **kind node container**, pulled out with `docker cp`       | Fail-closed: `zap-report.json` missing → error; ZAP's own exit code is captured but **never** the verdict           | Active scanning on prod is rejected by design (aggressive scans on a live service); the gate decides, never the scanner                                                                                        |
| 11  | `Vuln Gate - incl. DAST` — **GATE #2**  | Second `runGate()` — static findings + ZAP findings evaluated against the dedicated `dast:` policy section; `counts.dast` reported separately                                                                                                 | DAST high → **fail** (static would only warn), medium → warn                                                        | A runtime finding on a live endpoint is worse than a static hit; separation of counts keeps the promotion decision honest                                                                                      |
| 12  | `Post-Deployment Verification`          | Rollout status + EndpointSlice **ready-endpoint check** + in-cluster smoke Job (health, create note, search) + evidence collection (RBAC list, network policies, events)                                                                      | Hard fail with diagnostics fallback (Job logs before the failure message)                                           | `/health` green ≠ app works — the smoke Job proved this repo's own `DB_PATH` bug; evidence files are archived for the audit story                                                                              |
| 13  | `Production Deployment`                 | **Manual `input` approval** → `helm upgrade` with the SAME digest (`repo@sha256:…`, no override possible) → rollout status                                                                                                                    | Human approval between gate and prod                                                                                | The promotion is an explicit, reviewed decision — and it is byte-identical to what was gated                                                                                                                   |

The two gates are the design's spine: **GATE #1** (image, pre-sign) and **GATE #2**
(static + DAST, pre-promotion). Each writes its own `gate-decision-*.json` +
`gated-*.jsonl` + human `report.md`, so a failed promotion never erases the image
gate's verdict.

> 🖼 Screenshots pending: `assets/screenshots/cd-02-sign-verify.png` (cosign sign + verify,
> SBOM attestation), `assets/screenshots/cd-03-chart-sign.png` (helm package --sign + verify),
> `assets/screenshots/cd-04-dast.png` (ZAP Job + report), `assets/screenshots/cd-05-gate-dast.png`
> (vuln gate verdict incl. DAST), `assets/screenshots/cd-06-smoke.png` (smoke Job),
> `assets/screenshots/cd-07-promote.png` (approval dialog + prod rollout).

Walkthroughs: [docs/steps/step-03-cd-staging-path.md](docs/steps/step-03-cd-staging-path.md),
[step-04-cd-failure-cases.md](docs/steps/step-04-cd-failure-cases.md),
[step-05-cd-production-promotion.md](docs/steps/step-05-cd-production-promotion.md),
[step-06-supply-chain-verification.md](docs/steps/step-06-supply-chain-verification.md).

### Image signing and Helm chart signing

Two independent trust chains, one per artifact kind:

- **Image** — cosign signs the digest; the SBOM (CycloneDX) is attached as a
  `cyclonedx` predicate. Verification uses the public key credential — the demo
  shows sign → verify → deploy in one build, plus the tamper-detection story
  (a different digest fails `cosign verify` before the deploy stage is reached).
- **Chart** — `helm package --sign` + `helm verify --keyring` against the
  committed public key. The `.prov` file is archived as evidence. Tamper test
  (appended byte → `sha256 sum does not match`) is a documented demo script.

### Post-CI — Pentesting (DAST)

ZAP baseline runs **inside the cluster** (a Job rendered by the same Helm chart —
progressive delivery via `helm upgrade --set dast.enabled=true`), not from the
agent: it exercises the service exactly as a cluster client would, at
`http://notes.demo-staging.svc.cluster.local:80`, with the report copied out of
the kind node. The scan level is `-l WARN` to feed the gate with actionable
findings instead of a noise wall.

### Further optimization (CD)

- **Kyverno admission control** (bd devsecops-demo-e1g) — policies exist
  (`security/kyverno/verify-image.yaml`, `pod-security-baseline.yaml`) but are not
  yet enforced in the pipeline; the chart's PSS-style securityContext is today's
  runtime posture. Wiring `verify-images` (keyless/digest) + registry allowlist on
  the kind cluster is the planned admission stage.
- **Notifications** — omitted from the demo (draft decision): gate failures
  currently surface as build status + archived reports. Slack/Teams webhook on
  gate verdict is a drop-in `post { failure { … } }` addition.
- **SLSA provenance** — Jenkins `docker build` doesn't emit buildx provenance by
  default; the upgrade path is documented in docs/DESIGN.md §1 (v1 baseline +
  `slsa-github-generator`).

## Security Policy and CI violations

| `policy.yaml` rule                           | Example in this repo                                              | CI result                                                             |
| -------------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------- |
| `fail_tools: [gitleaks]`                     | Hardcoded `ds-demo-<32hex>` token (seed, `app/config.py`)         | Build **FAILS** — categorical, no exception possible                  |
| `fail_rule_classes` (SQLi/SSRF/deserial/RCE) | `/demo/unsafe-search` interpolates SQL (seed, `app/db.py:60`)     | Build **FAILS** — reachable injection is blocking even at vendor-High |
| `fail_when` KEV / EPSS ≥ 0.9                 | (metadata-driven; no current finding matches)                     | High+KEP → behaves as Critical                                        |
| `severity_defaults` high → warn              | MD5 password hashing (seed, `app/app.py:43`)                      | **UNSTABLE** unless excepted                                          |
| Exceptions (expiring, fingerprint-matched)   | EXC-0042 (MD5, expires 2026-09-13, ticket SEC-221)                | Finding **EXCEPTED**; audit row written; expiry → fails closed        |
| VEX (`--vex`)                                | gunicorn CVE-2024-6827 = `not_affected` (do-not-fix-forward case) | filtered at scan time — with evidence, not silence                    |
| Fail-closed gate                             | missing `trivy.sarif` / absent findings input                     | **ERROR** — a broken scan never looks like a pass                     |

The CI job itself is seeded to be **stably red on purpose**: new contributors see
the gate block the PR, then read `reports/security-report/report.md` to learn
what the org treats as a violation. That report is the interview artifact:
grouped per tool class, with source→sink code blocks for the SAST seeds,
commit metadata for secret leaks, and CVSS/EPSS/KEV/fix-version for SCA.

## Threat Modeling

TODO

## End to end showcase

All runs, normal and failure cases, with screenshots and capture checklists:
**[docs/steps/README.md](docs/steps/README.md)**.

| Step                           | Path                                                                                        | Demonstrates                                                |
| ------------------------------ | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| 01 — CI normal run             | [step-01-ci-normal-run.md](docs/steps/step-01-ci-normal-run.md)                             | full CI: scanners + gate verdicts (seeded FAILs), artifacts |
| 02 — CI warn/exception/VEX     | [step-02-ci-gate-warn-and-exceptions.md](docs/steps/step-02-ci-gate-warn-and-exceptions.md) | UNSTABLE path, EXC-0042, VEX filtering, exception audit     |
| 03 — CD staging path           | [step-03-cd-staging-path.md](docs/steps/step-03-cd-staging-path.md)                         | build→gate→sign→chart→staging→DAST→vuln gate→smoke          |
| 04 — CD failure cases          | [step-04-cd-failure-cases.md](docs/steps/step-04-cd-failure-cases.md)                       | DAST SQLi blocks promotion; fail-closed missing artifact    |
| 05 — CD production promotion   | [step-05-cd-production-promotion.md](docs/steps/step-05-cd-production-promotion.md)         | approval → same-digest prod deploy → verification evidence  |
| 06 — Supply-chain verification | [step-06-supply-chain-verification.md](docs/steps/step-06-supply-chain-verification.md)     | cosign sign/verify + SBOM attestation, chart GPG, tamper    |

## Setup the Demo

Follow **[SETUP_DEMO.md](SETUP_DEMO.md)** — Docker Hub repo + token, kind cluster on
the Jenkins agent, cosign + helm GPG keys, GitHub App, Jenkins plugins/credentials
(the credential IDs are the contract: `dockerhub`, `cosign-key`, `cosign-pub`,
`kind-kubeconfig`, `helm-signing-key`), and the two multibranch jobs.

## Repository layout

```
Jenkinsfile.ci / Jenkinsfile.cd   the two pipelines (CI = source gates, CD = supply chain + deploy)
app/                              deliberately seeded Flask app (token, SQLi, MD5, gunicorn CVE)
security/                         policy.yaml (gate), exceptions.yaml (expiring), gitleaks/semgrep/trivy-rego/kyverno rules, VEX
tools/                            normalize.py · gate.py · report.py — the policy engine
deploy/helm/notes-app/            single versioned chart: app + DAST Job + smoke Job + regcred
deploy/helm/keys/public.asc       committed chart-signing public key (secret pair is a Jenkins credential)
docs/
SETUP_DEMO.md                     environment bring-up guide
```

