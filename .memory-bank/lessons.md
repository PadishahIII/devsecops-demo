# Lessons

## 2026-08-14 — Validated tool facts (from design validation runs)

- Context: Design validation for docs/DESIGN.md; facts verified locally.
- Memory:
  - Semgrep 1.155.0 `p/security-audit` has **no rule for sqlite3 f-string SQLi** (Django/SQLAlchemy only) → org rule needed; a custom `no-formatted-sql` pattern `$CONN.execute(f"...")` was tested and fires.
  - Semgrep 1.155.0 **SARIF omits per-result `level`** → recover severity from `runs[].tool.driver.rules[].defaultConfiguration.level`.
  - Semgrep generic HTML rules false-positive on `{{ x["y"] }}` inside attributes → use dot access `{{ x.y }}`.
  - **Gitleaks images moved to `ghcr.io/gitleaks/gitleaks`** (Docker Hub pull denied); v8.21.2/v8.24.0 exist.
  - syft 1.x: `-o cyclonedx-json=/path` (the `--file` flag is deprecated).
  - Fake `AKIA…` keys get **blocked by GitHub native push protection** on public repos → seed secrets use an org custom pattern (`ds-demo-<32hex>`).
  - Custom rego / grype CVE-2024-6827 CRITICAL / kyverno keyless / cosign OIDC / ZAP levels: **NOT yet validated** — DESIGN.md §3 lists fallbacks.
- Evidence: local runs 2026-08-14; commands in docs/DESIGN.md §3.
- Reuse: when implementing the pipeline, skip re-discovering these; still validate the pending list at build time.

## 2026-08-14 — Flask app: bugs found by "make sure it works" verification

- Context: Implementing the Python project only (user instruction). Local + container verification exposed three real bugs.
- Memory:
  - **Schema never initialized in production path** — tests passed because the fixture called `db.init_db()`; the live app 500'd with `no such table: notes`. Fix: `db.init_db(config.DB_PATH)` at app import (idempotent, safe across gunicorn workers).
  - **Workspace is on an exFAT volume (`/Volumes/T9`, `noowners`)**: `chmod` is a no-op, files always report `rwx------` → docker build context preserves those modes → non-root container user cannot read code (`PermissionError` on import). Fix inside the Dockerfile with `COPY --chmod`.
  - **`COPY --chmod=0644` on a directory strips the +x bit** → templates dir untraversable → `jinja2.TemplateNotFound` at runtime. Use symbolic mode `u=rwX,go=rX` (`X` = execute for directories only).
  - `app/tests/__init__.py` needed so pytest inserts `app/` into `sys.path` (imports of `config`/`db`/`app`).
- Evidence: `app/app.py`, `app/Dockerfile`, `app/tests/__init__.py`; final verification all green — pytest 6/6, ruff clean, gunicorn smoke (health/POST/notes/search/admin/headers), container run (non-root, HEALTHCHECK healthy, 0 log errors).
- Reuse: when containerizing anything from this volume, always set modes in the Dockerfile; never rely on host permissions; always boot the app for real (not just tests) before calling it done.

## 2026-08-20 — Jenkinsfile.cd review: 5 verified P0 blockers

- Context: Review of Jenkinsfile.cd + tools/sign.sh, tools/verify.sh, gate/normalize/report.
- Memory:
  1. **`env.DOCKER_IMAGE` used before assignment** — digest line (`docker buildx imagetools inspect ${env.DOCKER_IMAGE}`) runs 3 lines before `env.DOCKER_IMAGE = ...` → empty arg → `requires 1 argument` → build dies post-push.
  2. **`reports/` never created in CD** (CI does `mkdir -p reports` per stage) → digest.txt write, syft `--output /src/reports/...`, and `normalize.py reports` (uncaught FileNotFoundError) all fail.
  3. **`trivy image ... /src`** — positional arg must be an image reference; `/src` → FATAL exit 2. Trivy container also lacks `/var/run/docker.sock` (syft stage has it), so it can't see local images. Custom Rego checks are k8s-scoped (`input: schema["kubernetes"]`) → `--check-namespaces/--config-check` in the image stage is CI copy-paste, never fires.
  4. **Single-quoted `sh '''...'''` in cosign stages** — `${env.DOCKERHUB_CRED_USR}` etc. NOT Groovy-interpolated → shell gets literal → `bash: bad substitution` (verified locally). Fix: use shell env vars `$DOCKERHUB_CRED_USR` (credentials binding exports them).
  5. **`docker run -it`** in cosign stages → `the input device is not a TTY` in Jenkins (verified).
- Design: gate runs AFTER push+sign — a gate FAIL leaves a published AND signed image. Reorder: build(no push)→SBOM→trivy→gate→push→sign→verify. `buildx imagetools inspect` digest only works for pushed images → conditional on PUSH_IMAGE. `cosign login -p` on CLI exposes token (use `--password-stdin`). `BRANCH` param unused. `docker rmi` only removes default tag. CD doesn't archive `reports/security-report/report.md` (CI does).
- Verified facts: trivy `will_not_fix` IS a valid `--ignore-status` value; trivy exits 0 by default even with findings (gate-as-single-decision-point is coherent); `--ignore-status affected,...` = only FIXED vulns reported.
- Evidence: local shell tests (bad substitution, -it no-TTY, buildx no-arg); trivy.dev docs; git log c7d60e1/4159fee/a6d1c6a.
- Reuse: pipeline was never run end-to-end — after fixing, do a full `PUSH_IMAGE=false` dry run first, then a real push.

## 2026-08-20 — Jenkinsfile.cd: user fixed P0s; op field removed; docs/cosmetics fixed

- Context: Follow-up to the 2026-08-20 review. User applied the P0 fixes themselves; I applied the remaining review items.
- Memory:
  - User's P0 fixes (verified in file): DOCKER_IMAGE assigned before digest lookup; `mkdir -p reports` in checkout; trivy now mounts docker socket + scans `${env.DOCKER_IMAGE}` (k8s-only `--check-namespaces/--config-check` dropped); cosign stages use shell env vars (`$DOCKERHUB_CRED_USR` etc.) and `docker run --rm` (no `-it`); `docker rmi -f`; `reports/security-report/report.md` archived; gate+report moved BEFORE sign/verify; `set -e` added to pretty_json; BRANCH param removed; PUSH_IMAGE became an env constant `true` (booleanParam commented out).
  - I removed `FailWhenCondition.op` from tools/gate.py AND the `op: ">="` key from security/policy.yaml — REQUIRED pair: the pydantic model is `extra="forbid"`, so removing only one side breaks policy validation at startup. Comparison stays hard-coded `>=`. Verified: policy validates + EPSS/KEV fail_when paths still fire (synthetic e2e, gate exit 2).
  - Docs fixed: header trigger line (REPOSITORY/IMAGE_TAG only), plugin list (Docker Pipeline + Credentials Binding + Workspace Cleanup), cosign file credentials documented, PUSH_IMAGE "must stay true" comment (digest/sign/verify need the image on the registry), post-block comment updated.
  - Restored the `if (env.DOCKERHUB_CRED_USR && ...)` login guard the user's edit had dropped — without it the dedicated "push requested but credentials not set" error is unreachable (docker login fails first with a cryptic error).
  - Cosmetics: trailing whitespace removed (L39/42/110/140), env-block tabs normalized to spaces, 4 archiveArtifacts calls merged into one, 3 blank lines → 1.
  - Left in place (user's deliberate comments): commented-out PUSH_IMAGE booleanParam, commented-out post cleanup block (cleanup is now a first stage).
  - `.venv` was missing tools/requirements.txt deps (pydantic, pyyaml) — reinstalled before verifying.
- Reuse: when removing a pydantic field with `extra="forbid"`, grep the YAML for the key in the same commit; the model and the file are a contract pair.

## 2026-08-20 — cosign image pin: sha256- (hyphen) is not a valid docker reference

- Context: CD build #18 failed at the sign stage: `docker: invalid reference format` on `bitnami/cosign@sha256-3b59b946…`.
- Memory: Docker Hub's UI displays digests with a HYPHEN (`sha256-…`); docker CLI requires the COLON form (`sha256:…`). Copy-pasting from the Hub UI breaks `docker pull/run/manifest inspect` with "invalid reference format" (client-side parse error, before any network call). Fix applied: `COSIGN_VERSION = "sha256:3b59b946…"` in Jenkinsfile.cd. Verified: `docker manifest inspect bitnami/cosign@sha256:3b59…` resolves (manifest OK); bitnami/cosign is a real repo (1.4M pulls) and the digest is a published tag.
- Reuse: when pinning any image by digest, always write `sha256:<hex>` — verify with `docker manifest inspect <ref>` before running the pipeline.
- Also this session: Jenkinsfile.ci beautified (4-space indent, no trailing ws/tabs, 2 misleading "continue on error" comments → accurate catchError comment, 5 fingerprinted archiveArtifacts merged into 1 call, report.md call kept separate — it has no fingerprint: true, behavior preserved). Verified token-level: all 7 sh blocks byte-identical modulo indentation; stage/catchError/pretty_json counts unchanged.

## 2026-08-23 — CD smoke wait: "timed out" is ambiguous — a Failed Job looks like a timeout

- Context: CD build failed in Post-Deployment Verification: `kubectl wait --for=condition=complete job/smoke-test -n demo-staging --timeout=3m` → `error: timed out waiting for the condition on jobs/smoke-test` (full 3m: 19:00:40 → 19:03:47).
- Memory:
  - The smoke Job is NOT started by an explicit kubectl command — it is rendered by `helmDeploy(..., "--set smoke.enabled=true --set smoke.svcUrl=...")` from `deploy/helm/notes-app/templates/smoke-job.yaml` (`{{- if .Values.smoke.enabled }}`, Job name `smoke-test`).
  - **`kubectl wait --for=condition=complete` never fires for a Failed Job** — the template sets `backoffLimit: 0`, so a failing check ends the Job in `Failed`, and the wait burns the full timeout with a bare "timed out". The old smoke block had no diagnostic fallback (unlike the DAST wait) and `kubectl logs` sat AFTER the wait in the same `set -euo pipefail` block → never ran → zero clues in the build log.
  - Fix (applied + committed): `|| { kubectl get job -o wide; kubectl get pods -l job-name=smoke-test; kubectl logs --tail=50; exit 1; }` on the smoke wait, mirroring the DAST stage. Verified: `bash -n` on the extracted shell block + Groovy CONVERSION-phase parse of the whole Jenkinsfile.
  - Root-cause triage for the next failure: Job `Failed` → a smoke check failed (logs show which curl died); pod `ImagePullBackOff`/`ErrImagePull` → kind node cannot pull `curlimages/curl:8.12.1@sha256:94e9…` (the Job has NO imagePullSecrets — anonymous Docker Hub pull).
- Reuse: for ANY `kubectl wait --for=condition=complete` on a Job, always add a `|| { diagnostics; exit 1; }` fallback — a bare timeout cannot distinguish "never started" / "still running" / "already failed".

## 2026-08-23 — Smoke Job caught a REAL app bug: config.DB_PATH was never defined

- Context: after the wait-diagnostics fix, the next CD build showed: `smoke: health` OK → `smoke: create note` → `curl: (22) The requested URL returned error: 500`. The pipeline was fine — the app was broken.
- Memory:
  - Root cause: `app/config.py` defines secret/token vars only — **`DB_PATH` was NEVER defined**. Every DB route (`POST /notes`, `/`, `/search`, `/metrics`, …) does `db.create_note(config.DB_PATH, …)` → `AttributeError: module 'config' has no attribute 'DB_PATH'` → 500. `/health` returns 200 because it never touches the DB — and the k8s probes only hit `/health`, so the deployment looked healthy. Tests passed because `app/tests/test_app.py` sets `config.DB_PATH` in its `_client()` fixture; the live app never got it. (The 2026-08-14 memory note said `db.init_db` at import was the fix — but the enriched app commit 6509e49 evidently lost `DB_PATH` + the import-time init.)
  - Fix (app + chart, committed): `DB_PATH = os.environ.get("DB_PATH", "/tmp/notes.db")` in config.py (`/tmp` is writable by the non-root runAsUser 65532; env-overridable for volumes); `os.makedirs(dirname) + db.init_db(config.DB_PATH)` at app.py import (idempotent, safe across gunicorn workers); `replicas: 1` in values-staging.yaml + values-production.yaml (per-pod SQLite + multi-replica ⇒ smoke create→search hits different pods — flaky; scale-out needs a shared DB, not replicas).
  - Verified: test client health 200 / POST /notes 201 / search contains 'smoke'; REAL gunicorn (2 workers, HTTP) same result, `/tmp/notes.db` created; pytest 11/11; ruff clean; values YAML parse OK.
- Reuse: when a route 500s in-cluster but /health is green and tests pass — suspect config that only tests set (fixture-injected). Grep the production config for every name the app references. And: per-pod SQLite ⇒ replicas must be 1.
