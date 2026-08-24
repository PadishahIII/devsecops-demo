# Pipeline stages in detail

Companion to `README.md` — the implementation-level view of both Jenkins
pipelines: every stage with its exact commands, gate behavior, and failure
modes, plus the full reasoning behind each design decision.

## Continuous Integration (`Jenkinsfile.ci`)

| # | Stage | What it does | Failure mode | Why this design |
| --- | --- | --- | --- | --- |
| 1 | `cleanup` / `checkout` | `cleanWs()`, SCM checkout | — | Hermetic workspace: no state leaks between builds |
| 2 | `fmt-lint-test` | `python:3.12.7-slim` agent, `ruff check app` (hard fail), `pytest -q --junitxml` | Build red on lint or test failure | Fast inner-loop quality gate BEFORE security scans — don't scan broken code |
| 3 | `secret-scan` | Gitleaks on the git history (`git /src`), custom config `security/gitleaks.toml`, SARIF out, `--redact` | Stage red via `catchError`, **verdict deferred to the gate** | Scanner breakage ≠ finding: `catchError` marks the build but the gate decides; the report must still render |
| 4 | `SAST - semgrep` | `p/security-audit` registry + org rules (`no-formatted-sql`, `no-md5-hashing`) | Same catchError→gate pattern | Registry rules close the gap the org rules define — the org rules are what make this repo's story real |
| 5 | `SCA - syft+grype` | Syft emits CycloneDX SBOM (`dir:.`); Grype consumes the SBOM against its DB (persistent `grype-db` volume) | Same | SBOM-first workflow; the SBOM itself is archived as a CI artifact — vulnerability DB freshness is a cron concern, not a per-build one |
| 6 | `IaC - trivy` | `trivy config` on the repo: builtin checks + **custom Rego** (`security/trivy/ds-001-privileged.rego`, `ds-002-nonroot.rego`, `ds-003-seccomp.rego`), `--severity CRITICAL,HIGH` | Same | Rego policies carry the org's *own* risk statements — vendor severity gets overridden by org intent |
| 7 | `gate + report` | `normalize.py` → `findings.jsonl` → `gate.py` (policy + exceptions) → `gate-decision.json` → `report.py` → `reports/security-report/report.md`; verdict mapped onto the build | `fail`/`error` → **FAILURE** (red), `warn` → **UNSTABLE** (yellow) | **Single decision point.** The gate reads back a JSON verdict — the workflow status is *derived from* the gate, never guessed |

### Reasoning behind the CI steps (full)

1. **Code is cloned from the Git server and the unit tests are run.**
   **Why?** The cheapest control runs first: broken code is rejected in under
   a minute, before any security tool spends compute — we do not scan broken
   code. Pinning the toolchain keeps the stage reproducible.
2. **A dependency report is generated from the source code and uploaded to
   the report server repository.**
   **Why?** SBOM-first: the inventory is a deliverable that outlives the
   scan, so the same SBOM can be re-evaluated when the vulnerability DB
   updates — DB freshness becomes a schedule concern, not a per-build one.
   Uploading every report keeps a per-branch audit record.
3. **The code is analyzed by static scanners for anti-patterns and
   misconfiguration.**
   **Why?** (i) The org rule sets are the differentiator — they encode *our*
   risk, and Semgrep is chosen over a generic quality gate because its
   security rules ship SARIF-compatible, class-based results that can *fail*
   the build. (ii) In the reference design these scanners run in parallel;
   the demo runs them sequentially so every stage and its report is
   deterministic and screenshotable. (iii) Scanner breakage ≠ finding: a
   failing scan marks the stage red via `catchError`, but the verdict is
   always deferred to the gate so reports still render.
4. **Every finding is evaluated by a single policy gate.**
   **Why?** One decision point can be fail-closed (absent scanner input =
   ERROR, never a pass), consistent across tools, and auditable — every
   build archives `gate-decision.json` and the exception audit trail.
   Scanners report; the gate decides.

## Continuous Delivery (`Jenkinsfile.cd`)

| # | Stage | What it does | Gate / guard | Why this design |
| --- | --- | --- | --- | --- |
| 1 | `Initialize` | Parameter validation: `ENVIRONMENT`/`PROMOTE_TO_PROD` exclusivity; `APP_VERSION` must be a valid tag ≤ 63 chars (k8s label); gate-tool deps (pydantic/pyyaml) | Hard error on bad params | Fail before spending 30 min building; tag-limit check is a k8s-label safety net |
| 2 | `build & push image` | `docker build` with 3 tags always: `<sha8>-<BUILD_NUMBER>` (primary), `latest`, `<APP_VERSION>`; push to Docker Hub; digest resolved via `buildx imagetools inspect` → `reports/digest.txt` | Push is a hard requirement (`PUSH_IMAGE=true`): digest/sign/verify need the registry | **Three-tag strategy**: immutable reproducible tag (primary) + convenience pointers; the *digest* is what gets deployed |
| 3 | `SBOM - syft` | Syft on the **image** → CycloneDX (`sbom.cdx.image.json`) | — | SBOM of the actual artifact (not the source tree), one-to-one with what gets signed |
| 4 | `Image Scan - trivy` | `trivy image --severity CRITICAL,HIGH`, `--ignore-status affected,will_not_fix,fix_deferred,end_of_life`, **`--vex security/trivy/vex.openvex.json`** | `catchError` + gate | Only *fixable* findings matter for a gate; the VEX document is the auditable way to carry an accepted risk (see [VEX.md](VEX.md)) — `.trivyignore` is a suppression, VEX is a decision with evidence |
| 5 | `gate + report` — **GATE #1** | `runGate()` with `expected: [trivy.sarif, sbom.cdx.image.json]` — **missing artifact → hard error before anything is signed** | fail/error → abort | The single decision point BEFORE trust is applied: nothing is signed, attested, or deployed from an ungated image |
| 6 | `Sign Image && attach SBOM attestation` | Cosign (key from Jenkins File credential): sign the **digest** + attest `--type cyclonedx` with the SBOM predicate | Private key never on disk beyond the credential | Signature = identity, attestation = inventory; both travel with the digest |
| 7 | `Verify signature and attestation` | Cosign verify with the **public key** (matching credential) | Hard fail | Self-check before deploy: we sign, then prove the signature verifies — the demo of the trust chain |
| 8 | `Package & Sign Chart` | `helm package --sign` (GPG, de-armored keyring inside the build), then `helm verify` using **only the committed public key** (`deploy/helm/keys/public.asc`) | Verify with the committed key — no secret key present | The deploy unit is provenance-signed; `helm verify` output ("Chart Hash Verified") is the artifact |
| 9 | `Deploy` (staging or hotfix prod) | `helm upgrade --install` the signed chart with values layered: chart defaults + `values-<env>.yaml` + workspace-only `rendered/values-base.yaml` (image **digest**, registry `dockerConfigJson` — chmod 600, never `--set`); `rollout status` | Digest-pinned image, non-root `runAsUser: 65532`, `allowPrivilegeEscalation: false`, seccomp RuntimeDefault, probes | Build once → deploy the same bytes everywhere; secrets travel via a workspace file, not the process list |
| 10 | `DAST - ZAP in-cluster` (staging only) | Helm toggles a `dast` Job rendering ZAP baseline against `notes.demo-staging.svc` (image pinned by digest, `runAsUser 1000`); report lands on a per-run unique hostPath dir in the **kind node container**, pulled out with `docker cp` | Fail-closed: `zap-report.json` missing → error; ZAP's own exit code is captured but **never** the verdict | Active scanning on prod is rejected by design (aggressive scans on a live service); the gate decides, never the scanner |
| 11 | `Vuln Gate - incl. DAST` — **GATE #2** | Second `runGate()` — static findings + ZAP findings evaluated against the dedicated `dast:` policy section; `counts.dast` reported separately | DAST high → **fail** (static would only warn), medium → warn | A runtime finding on a live endpoint is worse than a static hit; separation of counts keeps the promotion decision honest |
| 12 | `Post-Deployment Verification` | Rollout status + EndpointSlice **ready-endpoint check** + in-cluster smoke Job (health, create note, search) + evidence collection (RBAC list, network policies, events) | Hard fail with diagnostics fallback (Job logs before the failure message) | `/health` green ≠ app works — the smoke Job proved this repo's own `DB_PATH` bug; evidence files are archived for the audit story |
| 13 | `Production Deployment` | **Manual `input` approval** → `helm upgrade` with the SAME digest (`repo@sha256:…`, no override possible) → rollout status | Human approval between gate and prod | The promotion is an explicit, reviewed decision — and it is byte-identical to what was gated |

### Reasoning behind the CD steps (full)

1. **The application is packaged as a container image and released to the
   registry repository.**
   **Why?** The three-tag strategy gives one immutable, reproducible
   identity (primary) plus convenience pointers for humans (`latest`,
   `<APP_VERSION>`) — and only the *digest* is ever deployed, so a tag
   rewrite can never redirect a rollout.
2. **A dependency report of the image is generated, the image is scanned,
   and an image gate must pass before trust is applied.**
   **Why?** The scanned subject is the exact artifact that will be signed —
   the SBOM is of the *image*, not the source tree. Nothing is signed,
   attested, or deployed from an ungated image, and a broken scan never
   looks like a pass.
3. **The image is signed, its SBOM attestation is attached and verified;
   the deployment chart is packaged and GPG-signed.**
   **Why?** Two independent trust chains with zero secret material in the
   repository (private keys live only in Jenkins credentials): the
   signature proves identity, the attestation binds the inventory to the
   artifact, and the chart `.prov` proves deploy-unit authenticity — each
   verified *inside* the pipeline before anything is deployed.
4. **The same digest is deployed to the staging environment, where it is
   pentested by ZAP (DAST) against a second gate.**
   **Why?** A finding on a live endpoint is a different risk class than a
   static hit, and staging is where that runtime risk is discovered —
   production never receives aggressive active scanning. Two separate gates
   keep the image decision and the promotion decision independently
   archived.
5. **After post-deployment verification, the same digest is promoted to
   production behind a manual approval.**
   **Why?** The promotion is an explicit human decision with all evidence
   attached to the build, and byte-identical artifacts mean exactly what
   was scanned, signed, and verified is what runs in production.

## The gate — `security/policy.yaml`

One knob, action precedence (highest wins):

1. **Exceptions** — `security/exceptions.yaml`, matched by *exact finding
   fingerprint* (rule|path|line|snippet hash), always **expiring**, critical
   never exceptable
2. **Exploitability classes** — `fail_rule_classes`: formatted-SQL/SQLi,
   SSRF, deserialization, RCE → fail regardless of vendor severity
3. **Categorical tools** — `fail_tools: [gitleaks]`: a leaked secret never
   passes
4. **KEV / EPSS** — known-exploited or EPSS ≥ 0.9 behaves like Critical at
   high severity
5. **Severity defaults** — critical=fail, high=warn, medium=pass, low=pass

Fail-closed semantics: missing/absent scanner input is an `ERROR` (exit 3),
never a pass — a broken scan must not look like a green build. The exception
audit (`audit/exceptions-audit.jsonl`, archived per build + git-ignored)
records every applied/expired/unused exception: if the code moves, the
fingerprint stops matching and the finding **fails closed** instead of
silently whitelisting a rule.

The `dast:` policy section grades runtime findings one level stricter than
static ones (high → fail instead of warn, medium → warn instead of pass),
tracked separately as `counts.dast` so a runtime finding can never hide
inside the static counts.
