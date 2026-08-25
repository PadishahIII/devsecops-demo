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

## 2026-08-20 — CD half: staging deploy → in-cluster ZAP DAST → DAST-aware gate → verify → gated prod (bd devsecops-demo-v43)

- Context: User asked to turn Jenkinsfile.cd into a full CD pipeline borrowing designs from the `sample` file at repo root: ENVIRONMENT/APP_VERSION/RUN_DAST/PROMOTE_TO_PROD params, three-tag push strategy, deploy staging → run ZAP DAST in-cluster → vuln gate → post-deployment verification → promote to prod, and "extend gate.py to handle DAST vuln separately". User directive: ALL k8s objects live as files under deploy/ (never inline in the Jenkinsfile).
- Decisions:
  - Tag strategy: three tags ALWAYS emitted — `<sha8>-<BUILD_NUMBER>` (primary/digest source) + `latest` + `<APP_VERSION>` — replacing the old "default tag + free-form IMAGE_TAG param" scheme. Deploys pin the image BY DIGEST (`docker.io/repo@sha256:…`, design decision #4).
  - gate.py: findings from `tool == "zap"` (DAST_TOOLS set) get `category: dast` and are evaluated against a new typed `policy.dast` (DastPolicy: severity_defaults high→fail, medium→warn; own fail_rule_classes: sqli/xss/rce/path-traversal/ssrf). Decision JSON gains `counts.dast.{total,fail,warn,pass}`; failures/warnings entries carry `category`; console prints a separate DAST verdict line. General policy untouched; exception matching still uniform (fingerprint includes tool, so semgrep exceptions can never match zap findings).
  - Two gates: image gate pre-sign (gate-decision.json) and promotion "Vuln Gate - incl. DAST" post-scan (gate-decision-dast.json) — shared runGate() helper.
  - All k8s objects are versioned templates in deploy/k8s/cd/*.tpl: namespace.yaml.tpl, regcred.yaml.tpl (dockerconfigjson built in-pipeline from the dockerhub credential, b64), notes-secret.yaml.tpl (b64 from secret-text creds via b64FromEnv), deployment.yaml.tpl (digest image, probes, PSS-ish securityContext, regcred), service.yaml.tpl (ClusterIP 80→8000), dast-job.yaml.tpl (zap-baseline.py in-cluster Job, backoffLimit 0, runAsUser 1000 = image's default zap user, scans write /zap/wrk, container exits 0 — GATE decides, not the scanner), smoke-job.yaml.tpl (in-cluster curl Job: health+CRUD+search).
  - Jenkinsfile only renders + applies (renderManifest = readFile + ${VAR} replace, no envsubst dep) and drives kubectl: apply -f, rollout status, bounded wait loop for DAST job terminal state (Failed.status==True OR status.succeeded==1, 15m ceiling), kubectl cp collection, fail-closed `[ ! -s reports/zap-report.json ] → exit 1`. Namespace/secret bootstrap is idempotent (dry-run|apply pattern).
  - ENVIRONMENT=production + PROMOTE_TO_PROD=true = hotfix path (deploy straight to prod, DAST scans prod service before the gate); ENVIRONMENT=staging + PROMOTE_TO_PROD=true = full staging→(gate)→prod with input approval; staging-only when PROMOTE_TO_PROD=false.
- Evidence: tools/gate.py (DastPolicy + DAST_TOOLS + category + counts.dast), security/policy.yaml dast: section, deploy/k8s/cd/*.tpl (7 files), Jenkinsfile.cd. groovyc (groovy:4.0-jdk17) passes; 11 app tests pass; ruff clean. E2E: realistic zap-report.json (SQLi High/clickjack Medium/mime Low) → normalize → gate exit 2, DAST high SQLi FAILS (static would WARN), DAST medium WARNS, counts.dast {1,1,1}; EXC-0042 exception regression still WARN/exit 1 (fingerprint d22854fb… matches). ZAP image fact: stable image puts zap-baseline.py in /zap/ which is ON PATH (Dockerfile-stable ENV PATH=$JAVA_HOME/bin:/zap/:$PATH), default user zap(uid 1000), reports default to /zap/wrk/ when in docker.
- Reuse: BEFORE running the CD job, create Jenkins credentials: dockerhub, cosign-key/pub, kind-kubeconfig (File), app-secret-key + admin-password-hash (Secret text) — the environment block fails fast if missing. Reports dir is the single normalize source; zap-report.json must be named with "zap" in it or normalize never sees it. Keep the `reports/` conventions (digest.txt, trivy.sarif, sbom.cdx.image.json) — runGate re-normalizes the whole dir twice; normalize is idempotent (same inputs → same findings).

## 2026-08-21 — CD deploy: envsubst-rendered manifests → signed Helm chart (bd devsecops-demo-eed)

- Context: User wanted industry-level deploy tooling (this repo is a DevSecOps portfolio). The CD half rendered `deploy/k8s/cd/*.yaml` via a Groovy `renderManifest` (envsubst scoped substitution) + `kubectl apply`. User chose **Helm** (single chart, all 6 objects) + **GPG provenance** (helm package --sign + helm verify), no OCI registry.
- Decisions:
  - Single chart `deploy/helm/notes-app/` holds ALL objects: namespace, regcred secret, deployment, service, dast-job, smoke-job. DAST/smoke Jobs are conditional templates (`{{- if .Values.dast.enabled }}` / `.Values.smoke.enabled`) — progressive delivery via `helm upgrade` value toggles, not separate manifests.
  - Namespaces: templates use `.Release.Namespace`; pipeline passes `-n demo-<env> --create-namespace`. Do NOT pre-create the ns (Helm must own it or install fails on ownership metadata).
  - **Helm does NOT persist `--set` across upgrades** (confirmed v4.2.3): each `helm upgrade` recomputes values from chart defaults + `-f` files + that command's `--set`. So EVERY deploy call re-specifies ALL values: common via a workspace-only `rendered/values-base.yaml` (image.repository+digest, buildNumber, appVersion, registry.dockerConfigJson — chmod 600), env via `values-<env>.yaml`, Job toggles via `--set`.
  - Sensitive `registry.dockerConfigJson` is NEVER `--set` (leaks to process list/logs) — written to the workspace values file. regcred secret + deployment imagePullSecrets are gated on `{{- if .Values.registry.dockerConfigJson }}`.
  - **GPG signing gotcha (Helm 4)**: Helm signs with a built-in Go openpgp library (NOT the gpg CLI — a gpg wrapper logs zero calls). It reads the OLD binary keyring format only (armored + modern .kbx both fail: "tag byte does not have MSB set"), so the pipeline DEARMORS the armored credential first (`gpg --dearmor`). `--key` must match the key's IDENTITY NAME (e.g. "Name <email>"), not the fingerprint/keyid (sign.go matches `e.Identities` via `strings.Contains`) — derived from the public key via `gpg --show-keys --with-colons | awk -F: '/^uid/{print $10; exit}'`. The `.prov` is named `<chart>.tgz.prov`.
  - DAST Job lifecycle: a completed Job within its TTL window is re-used (not re-run) by a repeat `helm upgrade`, so the DAST stage does `kubectl delete job dast-scan` THEN `helm upgrade` (Helm recreates it after a manual delete — verified). A running Job IS removed by a disabling upgrade; a completed one lingers until TTL (harmless).
  - Removed `deploy/k8s/cd/` (6 manifests) + the `renderManifest`/`ensureNamespace`/`deployApp` helpers. Kept `deploy/k8s/` (3 SAST-demo manifests, used by the CI throwaway-cluster path). New `helm-signing-key` File credential (armored private key); public key committed at `deploy/helm/keys/public.asc` (gitignored: `deploy/helm/keys/*` except `!public.asc`; root `/keys/` for cosign).
  - New stage "Package & Sign Chart" (before Deploy) → `env.CHART_TGZ`; Deploy/DAST/Verification/Production all call `helmDeploy(ns, env, CHART_TGZ, extraSets)`.
- Evidence: `helm lint` clean; `helm template` staging=6 objects / production=3 (no dast, no secret when dockerConfigJson empty); all 6 pass `kubectl apply --dry-run=server` (ns pre-created). E2E on live kind: sign+verify (Chart Hash Verified), app-only deploy, dast Job created+recreated-after-delete, smoke Job created, app-only upgrade removes Jobs. Tamper test: appending a byte to the .tgz → "sha256 sum does not match" (detected).
- Reuse: `tools/generate-helm-signing-key.sh` makes the key pair (isolated GNUPGHOME, armored exports). Demo key pair is committed (public) + gitignored (secret) so the pipeline runs out of the box. If the agent lacks `helm`/`gpg`, the Package & Sign Chart stage fails fast. The base values file is written in Deploy and REUSED by DAST/Verification/Production (same digest).

## 2026-08-21 — DAST report dir: per-run random suffix, no pre-scan rm -rf

- Context: User flagged the DAST stage's `rm -rf <hostDir>` (run before the scan to clear stale state) as dangerous — a misconfigured/empty hostPath would delete critical node state, and a fixed name (`dast-<ns>`) collides across concurrent builds.
- Decision: Each run writes to its OWN fresh hostPath dir `reports/dast-<BUILD_NUMBER>-<uuid>` (base stays under `reports/` in the node container's rootfs). No pre-scan `rm -rf` (the fresh dir is empty by definition); after the report is pulled out via `docker cp`, ONLY that unique per-run leaf is removed (safe cleanup). `runId = "${env.BUILD_NUMBER}-${UUID.randomUUID()}"`.
- Evidence: live-kind test — fresh dir created (no rm), report written + pulled out via `docker cp`, unique leaf removed, sibling dirs untouched.
- Reuse: the per-run leaf is what makes the post-copy `rm -rf` safe; never `rm -rf` a shared/stale hostPath before a scan.

## 2026-08-21 — SETUP_DEMO.md environment setup guide (bd devsecops-demo-nhv)

- Context: User wanted a single doc to take a fresh Jenkins agent to "ready to run the pipeline". Explicitly: tool binary installation (helm/kind/kubectl/gpg/cosign) is OUT of scope — the pipeline/agent bootstrap handles it.
- Decisions:
  - Doc covers: Docker Hub (repo padishahiii/demo-web-app + access token), kind cluster (must be pre-created, name `kind`, KIND_NODE=kind-control-plane, agent Docker daemon must run the node), cosign keypair (empty passphrase — pipeline signs with COSIGN_PASSWORD=""), helm GPG key (tools/generate-helm-signing-key.sh; repo ships a demo pair), GitHub App, Jenkins plugins, credentials table, job config, verification, troubleshooting.
  - **GitHub App + plugins were INFERRED** (not in the pipeline code): the pipeline itself uses no GitHub credentials. The user's existing Jenkins creds (githubapp-id=4646534 secret-text, github-padishahiii user+PAT) reveal the intended integration: GitHub App = branch source + webhook trigger (GitHub plugin) + check-run reporting (GitHub Checks plugin). App perms: Contents RW, Checks RW, Metadata R; callback <jenkins>/github-webhook.
  - Plugin list inferred from pipeline steps: Pipeline Aggregator, Docker Pipeline (docker agent/withRegistry/build/push), Credentials Binding (env `credentials()` + file), Workspace Cleanup (cleanWs), Timestamper, Git, JUnit (CI post), GitHub, GitHub Checks. Pipeline Utility Steps explicitly NOT needed (uses JsonSlurper, not readJSON).
  - Two Multibranch Pipeline jobs, same repo, different Script Path: Jenkinsfile.ci / Jenkinsfile.cd.
  - Expected demo outcomes documented: CI FAILS at gate (gitleaks seeded ds-demo token, fail_tools categorical); CD staging deploys OK but DAST gate FAILS (seeded /demo/unsafe-search SQLi High). Both are "the demo working".
- Evidence: SETUP_DEMO.md (11 sections); facts cross-checked against Jenkinsfile.ci/.cd, security/policy.yaml (fail_tools: [gitleaks]), security/exceptions.yaml (EXC-0042), security/gitleaks.toml (demo-api-token rule), app/app.py (/demo/unsafe-search).
- Reuse: the credential IDs are the contract — dockerhub, cosign-key, cosign-pub, kind-kubeconfig, helm-signing-key (+ githubapp-id, github-padishahiii for the GitHub integration). CI uses NO credentials.

## 2026-08-23 — CD gate: sandbox rejects `new java.io.File` (runGate fix)

- Context: After the credentials fix, the CD run reached the 'gate + report' stage and died with `RejectedAccessException: Scripts not permitted to use new java.io.File java.lang.String` — `runGate`'s missing-artifact pre-check used `new File(p)`.
- Memory: (1) The Groovy sandbox default whitelist is DATA-FILE driven — script-security plugin resources `generic-whitelist` + `jenkins-whitelist` (NOT the StaticWhitelist.java source, which just parses them). `java.io.File` has NO constructor entry → `new File(...)` is rejected in declarative pipelines; `new groovy.json.JsonSlurper` + `parseText` and `staticMethod java.util.UUID randomUUID` ARE whitelisted (both used in the Jenkinsfiles, safe). (2) Fix: the check is now `sh("[ -f p ] && [ -s p ]", returnStatus: true) != 0` — identical semantics to `isFile() && length()>0`, fail-closed preserved, no script approval needed (keeps the demo out-of-the-box). (3) Verification workflow: declarative Jenkinsfiles can't be fully compiled outside Jenkins — syntax-check with `docker run groovy:4.0-jdk17` + `CompilationUnit.compile(Phases.CONVERSION)` (parse-only; full compile fails on unresolved declarative symbols like `agent any`).
- Evidence: Jenkinsfile.cd runGate (commit e66e98a); generic-whitelist lines 15-16 (JsonSlurper), 782 (UUID randomUUID), no java.io.File; docker CONVERSION check printed SYNTAX OK; shell predicate tested missing/empty/nonempty → 1/1/0.
- Reuse: before using `new X(...)` in a declarative pipeline, grep the plugin's `generic-whitelist` for the constructor signature; prefer sh-based checks for filesystem existence/emptiness. Alternative was approving `new java.io.File java.lang.String` in Manage Jenkins → In-process Script Approval — works, but adds a manual setup step.


## 2026-08-25 — Chinese README (README.zh-CN.md)

- Context: User is using this repo as a DevSecOps portfolio; wanted a Chinese version of README.md with a concise narrative.
- Decision: Created README.zh-CN.md (standard localization convention) rather than overwriting README.md; English README kept as canonical. Added a top link back to README.md. Kept tool names, stage names, and credential IDs in English; narrative cells translated with light restructuring for flow.
- Reuse: If README.md changes materially, regenerate README.zh-CN.md from it.
