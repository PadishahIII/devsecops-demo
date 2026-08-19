# devsecops-demo — Pipeline & Demonstration Design (v1)

|          |                                                                                       |
| -------- | ------------------------------------------------------------------------------------- |
| Status   | **Design** (no implementation)                                                        |
| Date     | 2026-08-14                                                                            |
| Owner    | jason.harris                                                                          |
| Audience | DevSecOps role interview — live demo of a gated, supply-chain-aware delivery pipeline |

---

## 0. Objective

Prove, in one reproducible repo, that the candidate can turn scanners into **reliable
controls**: PR-time gating, build-once digest promotion, signed+attested artifacts,
admission enforcement, risk-based (not severity-based) policy, and auditable expiring
exceptions. The demo pipeline itself is the artifact; the app is deliberately small.

Positioning note: the earlier Java-SAST narrative is **discarded** by owner decision.
Future-depth stories are the in-house DAST/AI-audit platform and the post-processing
layer (structural outputs, not PDFs).

## 1. Locked decisions

| Decision         | Choice                                                                           | Rationale                                                                                                 |
| ---------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| App              | Python 3.12 / Flask + gunicorn, SQLite                                           | Small, fast builds, easy seeds; multi-paradigm vulns (injection, crypto, deps, manifests)                 |
| CI               | GitHub Actions (2 workflows)                                                     | Spec says pick one; GH Actions has OIDC for keyless signing, `upload-sarif`, kind-action                  |
| Ephemeral target | kind cluster **inside the runner** + Kyverno admission                           | Dies with the job = honest ephemeral story; gives admission-control proof                                 |
| Signing          | Cosign **OIDC keyless** (no key material)                                        | Modern pattern; GH Actions `id-token: write`; short-lived certs                                           |
| Provenance       | buildx `provenance: true` + SBOM attestation                                     | v1 baseline; slsa-github-generator is the documented upgrade                                              |
| Post-process     | Minimal: `normalize.py` → `findings.jsonl` + `gate.py` + SARIF upload            | Structural outputs are the interface; consumers (DB/Slack/reports) plug in later without pipeline changes |
| Pipeline split   | **PR tier** (untrusted, read-only) vs **main tier** (trusted, full supply chain) | Core design lever; "new findings block PR, inherited debt goes to backlog"                                |

## 2. Pipeline architecture — two tiers, seven stages

```
PR branch (untrusted)                                  main (trusted)
┌──────────────────────────────────────────┐          ┌──────────────────────────────────────────────┐
│ 1 fmt/lint + unit tests + build          │          │ 4 docker buildx ONCE (provenance+sbom) → D    │
│ 2 parallel (read-only, no secrets):      │          │   syft SBOM (CycloneDX)                       │
│   ├─ gitleaks   (custom rule set)        │          │   trivy image scan (CRITICAL,HIGH)            │
│   ├─ semgrep    (p/security-audit+org)   │          │ 5 cosign sign D (keyless)                     │
│   ├─ syft+grype (lockfile SBOM → vulns)  │          │   cosign attest --type cyclonedx (SBOM)       │
│   └─ trivy config (builtin + org Rego)   │          │   self-check: verify + verify-attestation     │
│ 3 GATE: normalize → policy → decision    │          │ 6 kind (ephemeral) + Kyverno admission:       │
│   fail critical / warn high / exceptions │          │   verify-images (sig+SBOM) + PSS + registry   │
│   upload SARIF → code scanning           │          │   smoke tests (health, CRUD, search)          │
│  (new critical ⇒ PR blocked)             │          │ 7 ZAP baseline (DAST)                         │
└──────────────────────────────────────────┘          │   GATE (image scan + ZAP) → promotion decision│
                                                       │   promote SAME digest (tag) — never rebuild   │
                                                       └──────────────────────────────────────────────┘
```

Triggers & permissions:

| Workflow           | Triggers                              | Permissions (minimal)                                  | Notes                                                                                         |
| ------------------ | ------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| `01-pr-checks`     | `pull_request` **and** `push: [main]` | `contents: read`, `security-events: write`             | Push trigger covers the direct-push hole; branch protection should block direct pushes anyway |
| `02-main-pipeline` | `push: [main]`, manual dispatch       | `contents: read`, `packages: write`, `id-token: write` | `concurrency` group serializes deploys                                                        |

Fork PRs: no secrets, no SARIF upload (`continue-on-error`) — the gate still decides.

## 3. Tool selection & rationale

| Stage     | Chosen                                                                                              | Why                                                                                                              | Rejected (and why)                                                                                                                                 |
| --------- | --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Secrets   | **Gitleaks** (extended default rules + org rules)                                                   | Deterministic rules, SARIF out, `gitleaks:allow` inline opt-out; custom patterns = org-specific detection        | TruffleHog: entropy+_verified live-credential_ check is the differentiator, but noisier; keep as optional second layer                             |
| SAST      | **Semgrep** (`p/security-audit` + 2 org rules)                                                      | Fast, SARIF, huge registry; org rules close vendor gaps                                                          | Joern: research-grade CPG tool, no rules, steep curve — wrong for a gate; CodeQL: heavyweight, same concept. Joern/CodeQL = future-depth narrative |
| SCA/SBOM  | **Syft + Grype**                                                                                    | SBOM-first (CycloneDX out, Grype consumes SBOM), severity + EPSS/KEV metadata → feeds the risk model             | OSV-Scanner: lighter, deps.dev reachability for some ecosystems, but no SBOM-first workflow                                                        |
| IaC       | **Trivy config** + **custom Rego** (DS-001/2/3)                                                     | One vendor for image+config+secrets; Rego = policy-as-code showpiece; **org severity overrides vendor severity** | Checkov: great custom YAML/Python policies but duplicates Trivy                                                                                    |
| Signing   | **Cosign keyless** + buildx provenance + SBOM attestation                                           | Identity (sig) ≠ inventory (SBOM) ≠ build history (provenance) — each a separate artifact                        | Key-pair: simpler but the pattern industry is leaving                                                                                              |
| Admission | **Kyverno**: verify-images (keyless, sig + SBOM attestation) + PSS-style rules + registry allowlist | Enforces trust at deploy, not just scan output; registry allowlist = defense in depth                            | Ratify: same concept, heavier                                                                                                                      |
| DAST      | **ZAP baseline**                                                                                    | Zero-config smoke DAST, JSON out; crawls + passive/active baseline                                               | Nuclei: template _sender_, not a crawler — complements ZAP (CVE checks post-deploy), doesn't replace it. Own DAST engine = future depth            |

## 4. Expected vulnerabilities (seeds) — one per control, verified against real scanner output

The demo app is *deliberately* seeded so every scanner stage has at least one
finding that matches the org rules. Nothing below is theoretical: each row was
observed in real Jenkins artifact runs (2026-08-18) and re-verified after the
app enrichment.

### 4.1 Seed inventory (verified)

| # | Seed | Tool + rule that fires | Verdict | Where | Verified |
| --- | --- | --- | --- | --- | --- |
| 1 | Hardcoded API token `ds-demo-z86w…` in `app/config.py` | gitleaks org rule `demo-api-token` (`ds-demo-<32hex>`) | **FAIL — categorical** (`fail_tools`) | PR tier / secret-scan | ✅ real SARIF (3 findings: lines 6-7) |
| 2 | SQLi: `db.unsafe_search_notes()` interpolates `pattern` into an f-string query, reachable from `/demo/unsafe-search` | semgrep `security.semgrep.no-formatted-sql` (org rule) | **FAIL — exploitability class** (`fail_rule_classes`) | PR tier / SAST | ✅ real SARIF (db.py:59, now :60) |
| 3 | Legacy MD5 password hash in `app.hash_password()` (reachable from `/admin` and `/login`) | semgrep `security.semgrep.no-md5-hashing` (org rule) | **WARN → EXCEPTED** (EXC-0042, expires 2026-09-13) | PR + main / SAST | ✅ real SARIF (app.py:43) |
| 4 | Dependency CVEs: flask 3.0.3 (GHSA-68rp-wp8r-4726), pytest 8.3.4 (GHSA-6w46-j5rx-g56g) | grype (PR) / trivy image (main) | LOW/MEDIUM → **PASS** by default; the gunicorn pin is the seeded critical | PR / SCA | ✅ real grype.json |
| 5 | `gunicorn==21.2.0` — the seeded critical-with-fix (CVE-2024-6827, fix 22.0.0; intentionally pinned back from 22.0.0) | grype (PR) / trivy image (main) / trivy fs (demo) | **CRITICAL + fix available → FAIL** (severity + `fix_available`); VEX `not_affected` (security/trivy/vex.openvex.json) filters it out — see docs/VEX.md | PR / SCA or main / 4 | ⏳ to validate (fallbacks listed) |
| 6 | Deployment manifest: image `:main` tag (not digest) + pinned-by-tag scanner inputs | trivy config builtin `KSV-0014` (root/privileged container) | **WARN** at high severity (vendor severity) | PR / IaC | ✅ real SARIF (deployment.yaml:25) |
| 7 | (Demo branches only) `privileged: true`, no securityContext — see §3-2 | trivy config org Rego `DS-001` (CRITICAL, org severity override) | **FAIL — policy-as-code** | PR / IaC (demo branch) | ⏳ to validate |
| 8 | Unsigned / wrong-key image at deploy | Kyverno `verify-image` (keyless) + `pod-security-baseline` (registry allowlist, non-root, seccomp) | **Admission DENY** (not a finding — enforcement) | main / 6 | ⏳ to validate |

### 4.2 Fingerprint stability invariants (do not break)

The gate matches exceptions by exact fingerprint, so the *physical location* of
seeds is part of the contract:

- `app/app.py` line **43** — the MD5 statement. EXC-0042's fingerprint
  `d22854fb3e9aa2b7c7a70ab45fcc84f5b4566442aeb37d6b60fd4ebbe12b6510` was
  computed from `semgrep|security.semgrep.no-md5-hashing|src/app/app.py|43|snippet`
  (pre-lstrip SARIF URI). If this line moves, the exception silently stops applying
  and the audit records `EXCEPTION_UNUSED`.
- `app/config.py` lines 9-10 — the gitleaks seed. Moving it re-baselines every
  gitleaks finding (and the 3 historical commits that leaked it).
- Normal routes stay safe (parameterized queries, security headers); only
  `/demo/unsafe-search` and `/admin` are intentionally weak. This contrast is
  what makes the gate story believable.

### 4.3 Expected gate output (baseline run)

```
gate: FAIL — 4 fail, 2 warn, 2 pass
  FAIL  [gitleaks/medium] demo-api-token @ app/config.py — tool=gitleaks is categorical
  FAIL  [semgrep/high]    security.semgrep.no-formatted-sql @ /src/app/db.py — exploitability class matched
  WARN  [semgrep/high]    security.semgrep.no-md5-hashing @ /src/app/app.py — exception EXC-0042 applied
  WARN  [trivy/high]      KSV-0014 @ deploy/k8s/deployment.yaml — severity=high
```

That is the *honest* baseline: the demo repo is never green while the seeds are
in place. Green only happens after a fix PR (or on a clean fork).

### 4.4 App surface that feeds the scans (route → control)

| Route | Behavior | Feeds |
| --- | --- | --- |
| `/search` | parameterized search (safe) | contrast story for the SQLi seed |
| `/demo/unsafe-search` | f-string SQLi sink | semgrep `no-formatted-sql` → FAIL |
| `/admin` | MD5 password check | semgrep `no-md5-hashing` → EXCEPTED |
| `/login` `/logout` | session auth (demo-only) | ZAP authenticated-surface crawl |
| `/export/notes` | CSV download (safe headers) | DAST exfiltration surface |
| `/api/notes` | JSON API | post-process consumers |
| `/metrics` | numeric gauge | gate/report/vuln-DB integration |
| `/demo/banner` | release metadata from env | provenance story (commit → env → runtime) |
### 4.5 Artifacts per stage

| Stage | Tool                              | Format            | Consumer                                                               |
| ----- | --------------------------------- | ----------------- | ---------------------------------------------------------------------- |
| 2     | gitleaks / semgrep / trivy config | SARIF             | `upload-sarif` → GitHub code scanning UI (vendor-neutral) + normalizer |
| 2c    | syft                              | CycloneDX JSON    | normalizer (licenses) + SBOM story                                     |
| 2c    | grype                             | JSON              | normalizer                                                             |
| 4     | trivy image                       | JSON + SARIF      | normalizer + code scanning                                             |
| 4/5   | syft SBOM / cosign attestation    | CycloneDX + Rekor | provenance story; Kyverno admission                                    |
| 7     | ZAP baseline                      | JSON              | normalizer                                                             |

### 4.6 Unified finding schema (`findings.jsonl`)

```json
{
  "tool": "semgrep",
  "rule": "security.semgrep.no-md5-hashing",
  "severity": "high",
  "path": "app/app.py",
  "line": 43,
  "snippet": "return hashlib.md5(password.encode()).hexdigest()",
  "message": "...",
  "fingerprint": "<sha256>",
  "metadata": { "known_exploited": false, "epss": null },
  "source": "semgrep.sarif"
}
```

- `fingerprint = sha256(tool | rule | path | line | snippet)` — location-precise, so an
  exception can never whitelist a whole rule.
- `source` = the raw artifact file this finding came from (normalize.py also copies
  the artifacts to `raw/`) — the raw scanner output remains the source of truth for
  detailed reports; the findings stream only carries what the gate needs.
- Severity mapping: SARIF `error→high, warning→medium, note→low` (with the rules-table
  fallback from §3-2); grype/trivy/ZAP use native severities canonicalized to
  `critical/high/medium/low/informational`.

### 4.7 Gate (`gate.py`) — single decision point, precedence order

```
exceptions (exact fingerprint, expiring)  >  fail_rule_classes (injection/RCE…)
  >  fail_tools (gitleaks: categorical)   >  fail_when (KEV, EPSS ≥ 0.9)
  >  severity_defaults (critical=fail, high=warn, medium/low=pass)
```

Outputs: `gate-decision.json` (status, per-finding action+reason, counts) and
`audit/exceptions-audit.jsonl` (append-only). The **gate decides the workflow
status**: exit 0 = PASS, 1 = WARN (CI maps to UNSTABLE), 2 = FAIL (block),
3 = ERROR — absent findings input, fail-closed (a broken scan stage can never
look like a clean pass). An *empty* findings stream is a legitimate pass. The
gate runs **twice** (PR tier over source scans, main tier over image scan + ZAP)
— same code.
**Security gate design: severity, exploitability, reachability, exception process**

### Deploy

Deploy to kind/K8s with a simple gate (fail on Critical, warn on High, ticket on Medium)

## 5. Seeded failure catalogue (5 blocked + 1 excepted)

The verified inventory lives in §4.1; this table is the *demo story* version —
what gets shown in the interview and on which branch. §4.1 is the source of
truth for what each seed produces today.

| #   | Seed                                                             | Tool that blocks                                  | Tier/stage          | The _correct reason_                                                                                               | Status                                               |
| --- | ---------------------------------------------------------------- | ------------------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| 1   | Hardcoded token `ds-demo-<32hex>` in `config.py` (line 9-10)     | gitleaks (org rule)                               | PR / 2              | Secrets are **categorical** — a leaked secret can never be un-leaked by review; exceptions forbidden               | ready (custom pattern avoids GitHub push-protection) |
| 2   | SQLi: `db.unsafe_search_notes()` interpolates `pattern` in the `/demo/unsafe-search` route | semgrep `no-formatted-sql` (org rule)             | PR / 2              | Injection is **reachable exploitation**, not a warning — fail-by-class even at High                                | validated today                                      |
| 3   | `gunicorn==21.2.0` pin — seeded critical-with-fix (CVE-2024-6827, fix 22.0.0); VEX demo: security/trivy/vex.openvex.json, docs/VEX.md | grype (PR) **or** trivy image (main) / trivy fs (demo) | PR / 2c or main / 4 | **Critical + fix available** — debt with a fix is a blocker; KEV/EPSS override if present. VEX `not_affected` is the demo of an accepted, *explained* risk — not an indefinite suppression | to validate (fallbacks listed)                        |
| 4   | Deployment manifest: `:main` tag, KSV-0014 (privileged)          | trivy config builtin KSV-0014 + org Rego DS-001    | PR / 3              | **Policy-as-code**: org severity overrides vendor severity; privileged = critical, period                          | KSV-0014 validated; DS-001 to validate               |
| 5   | Unsigned / wrong-key image at deploy                             | Kyverno `verify-images` + registry allowlist      | main / 6            | **Scanning ≠ trust**: image was never scanned, but admission denies it — identity+integrity are enforced at deploy | to validate                                          |
| E   | MD5 password hashing (main baseline, app.py:43)                  | semgrep `no-md5-hashing` — HIGH, **excepted**     | PR + main           | Exception honors the **compensating controls** (SSO/WAF/ticket) and expires                                        | validated today                                      |
| 6†  | Same exception, `expires` set to yesterday                       | gate                                              | any                 | **Expiry enforcement** — expired exceptions block; nothing is indefinite                                           | trivial (demo step)                                  |

† Optional dramatic sixth case for the live demo.

⚠️ **Line numbers are part of the contract.** See §4.2 — moving the MD5 line
(app.py:43) or the gitleaks seed (config.py:9-10) silently breaks the EXC-0042
exception or re-baselines leak history.

## 6. Design decisions (spec) → mechanisms

| Spec principle                           | Mechanism in this design                                                                                                                                       |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Severity ≠ risk                          | Gate model: severity defaults + exploitability-class + KEV/EPSS + tool categoricals + exceptions; two same-severity findings can resolve differently by design |
| New vs inherited                         | PR tier blocks new findings; main-tier debt → bd/issues + time-bound exceptions (EXC-0042 pattern); expired exception blocks                                   |
| Pin & minimize                           | Action tags + dependabot, base image digest, scanner image tags, minimal `permissions:` blocks, fork PRs get no secrets, environment protection                |
| Build once, promote digest               | One buildx run on main → digest D → syft/trivy/cosign/Kyverno/ZAP all reference D → promote = new tag on D                                                     |
| SBOM/sign/provenance/admission semantics | Four separate artifacts with four roles; admission (Kyverno) is the enforcement proof, demonstrated live with a deny                                           |

## 7. Demo script outline (interview run)

1. **Baseline run** — push to main; show tier-2 completing end-to-end: build once →
   SBOM → scan → keyless sign → attest → kind deploy → Kyverno verifies → smoke →
   ZAP → gate passes → `promoted-<run>` tag on the **same digest**. Point at the MD5
   finding: warn + `EXCEPTION_APPLIED` audit entry + open ticket.
2. **PR #1 hardcoded secret** → gitleaks red; gate blocks; SARIF lands in code
   scanning. Talk: categorical, no exceptions, custom org patterns.
3. **PR #2 SQLi** → semgrep org rule red; gate blocks. Talk: vendor gap closed by
   org rule; injection fails by class, not by severity.
4. **PR #3 vulnerable dep** → grype CRITICAL with fix; blocked. Talk: fix-available
   critical = immediate blocker; KEV/EPSS = risk above severity.
5. **PR #4 privileged manifest** → trivy DS-001 CRITICAL (our severity, not
   vendor's). Talk: policy-as-code, org overrides vendor.
6. **Admission deny (live)** — deploy an unsigned image of the same app (wrong
   registry / wrong key) → Kyverno denies; show the policy report + events. Talk:
   scanning is necessary, admission is the enforcement.
7. **Exception audit** — show `exceptions.yaml` git history, `gate-decision.json`,
   `audit/exceptions-audit.jsonl`; flip expiry to yesterday → rerun → blocked with
   `EXCEPTION_EXPIRED`. Talk: nothing is indefinite, everything is evidence.
8. **Post-process** — show `findings.jsonl` shape and how a consumer (SQLite/Slack/
   renderer) would attach without touching the pipeline.

## 8. Repo enablement checklist (manual, GitHub UI)

- [ ] Code scanning: enable **Default setup** or verify `upload-sarif` acceptance
- [ ] Branch protection on `main`: require `01-pr-checks` (all jobs incl. gate), require PRs (no direct pushes)
- [ ] GHCR packages enabled; repo **public** (Kyverno/GHCR anonymous pull in CI)
- [ ] Repo secrets: `APP_SECRET_KEY`, `ADMIN_PASSWORD_HASH` (fallbacks documented for forks)
- [ ] Environment protection on deploy step if using environments (documented future)

## 9. Risks & open questions

- **Kyverno self-interception**: policies must exclude `kyverno`/`kube-system`
  namespaces (else Kyverno denies its own pods).
- **Registry allowlist vs smoke tests**: allowlist pattern `ghcr.io/<owner>/*` must
  be scoped to `spec.containers[].image` (pause/coredns live outside pod specs).
- **ZAP on CI runner**: needs `host.docker.internal` (add `--add-host=host.gateway`)
  - port-forward; alert levels unvalidated against this app.
- **Grype DB staleness**: pinned grype image carries an old bundled DB; ensure
  runtime DB download (CI has network; locally it warned "built 22 weeks ago").
- **Demo branches** must never be merged; gitleaks scans history, so seeds stay
  branch-local.

## 10. Suggested build order (when approved)

1. Validate the §3 "to validate" facts (seeds + rego + kyverno + cosign + ZAP) — each has a fallback.
2. Scaffold app + manifests + org rules; local scan dry-run (semgrep/gitleaks/trivy/syft+grype).
3. Workflows tier 1 → tier 2 → iterate on the first green run.
4. Demo branches (4) + admission-deny script; then rehearse §7 twice.
