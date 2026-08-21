# devsecops-demo — Setup Guide

Take a fresh Jenkins agent from zero to "ready to run the pipeline". This covers
everything the two pipelines (`Jenkinsfile.ci`, `Jenkinsfile.cd`) need from the
**environment**: Docker Hub, the kind cluster, the signing keys/certificates
(with the commands that generate them), the GitHub App, the Jenkins plugins,
the Jenkins credentials, and the job configuration.

**In scope:** credentials, key/certificate generation, kind cluster, GitHub App,
Jenkins plugins + jobs, verification.

**Out of scope:** installing tool binaries (`helm`, `kind`, `kubectl`, `gpg`,
`cosign`, `docker`, `python3`, `git`). Those are provisioned by the pipeline /
agent bootstrap — this file only configures the environment around them.

---

## 1. Architecture

```
                          ┌──────────────────────────────────────────────┐
   push / PR              │                 Jenkins (agent)              │
 ┌────────┐   webhook     │  ┌────────────┐         ┌─────────────────┐  │
 │        │───────────────┼─▶│ CI job     │         │ CD job          │  │
 │ GitHub │               │  │Jenkinsfile │         │Jenkinsfile.cd   │  │
 │  repo  │               │  │    .ci     │         │                 │  │
 └────────┘               │  │ lint/test  │         │ build→push→scan │  │
                          │  │ secret/    │         │ →sign→chart(GPG)│  │
                          │  │ SAST/SCA/  │         │ →deploy→DAST    │  │
                          │  │ IaC → gate │         │ →gate→verify    │  │
                          │  └────────────┘         │ →promote        │  │
                          │        │                └───────┬─────────┘  │
                          └────────┼────────────────────────┼────────────┘
                                   ▼                        ▼
                            ┌─────────────┐         ┌──────────────────┐
                            │  Docker Hub │         │   kind cluster   │
                            │ image +     │         │ demo-staging /   │
                            │ cosign sig  │         │ demo-production  │
                            └─────────────┘         │ (ZAP DAST, smoke)│
                                                    └──────────────────┘
```

Two pipelines, one repo:

- **CI** (`Jenkinsfile.ci`) — lint/test → secret scan (gitleaks) → SAST (semgrep)
  → SCA (syft+grype) → IaC (trivy) → **gate** (the single decision point).
  Uses **no credentials**.
- **CD** (`Jenkinsfile.cd`) — build & push (3 tags) → SBOM → trivy → image gate
  → cosign sign+verify → package + GPG-sign the Helm chart → deploy staging
  (helm) → ZAP DAST (in-cluster) → DAST-aware gate → post-deployment
  verification → [manual approval] → promote to production (same digest).

---

## 2. Prerequisites (agent host)

- A Jenkins agent with a **Docker daemon** — and that daemon must be the one
  running the kind node (DAST report retrieval uses `docker cp` from the node
  container).
- `python3` + `pip` on the agent. The CD `Initialize` stage auto-installs
  `pydantic` + `pyyaml` for the gate tools (`tools/requirements.txt`).
- `git` on the agent.
- Network egress from the agent to `docker.io` and `ghcr.io` (base images,
  scanner images, the cosign image, the in-cluster ZAP/curl images).
- A pre-created kind cluster (section 4).

> Tool binaries are provisioned by the pipeline / agent bootstrap — installing
> them is out of scope for this file.

---

## 3. Docker Hub

1. Create (or reuse) a Docker Hub account — the demo default user is
   `padishahiii`.
2. Create the repository the CD pipeline pushes to (matches the `REPOSITORY`
   parameter default): **`padishahiii/demo-web-app`**. Public or private both
   work — for a private repo the pipeline creates an in-cluster `regcred`
   secret from the `dockerhub` credential.
3. Create an **access token**: Docker Hub → Account Settings → Security →
   New Access Token (read/write on the repo).

**Jenkins credential** `dockerhub` (Username with password):
- Username: `padishahiii`
- Password: `<access token>`

---

## 4. kind cluster (on the agent host)

The CD pipeline **connects to** a kind cluster; it does not create or manage
it. The cluster must already exist on the agent host and share the agent's
Docker daemon.

```bash
# 1. Create the cluster. The name must be `kind` (default) — the pipeline's
#    KIND_NODE assumes the default node container name `kind-control-plane`.
kind create cluster --name kind

# 2. Generate the kubeconfig.
kind get kubeconfig --name kind > kind-kubeconfig.yaml

# 3. Verify.
kubectl --kubeconfig kind-kubeconfig.yaml get nodes
```

Notes:

- **Cluster name must be `kind`.** `Jenkinsfile.cd` sets
  `KIND_NODE = 'kind-control-plane'` (the node container of the default
  cluster). If you create it with a custom name, set `KIND_NODE` to
  `<name>-control-plane`.
- **The agent's Docker daemon must be the one running the kind node.** DAST
  report retrieval runs `docker cp kind-control-plane:<dir> ...` on the agent,
  which only works if the kind node is a container on that daemon.
- The kubeconfig's API-server port can change when the cluster is recreated —
  re-run `kind get kubeconfig --name kind` and update the credential. (The repo
  ships a demo kubeconfig at `deploy/jenkins/kind-kubeconfig.demo.yaml` for a
  local cluster.)

**Jenkins credential** `kind-kubeconfig` (Secret file): upload
`kind-kubeconfig.yaml`.

---

## 5. Signing keys / certificates

### 5.1 cosign — image signing + SBOM attestation

The CD pipeline signs the pushed image and attaches a CycloneDX SBOM
attestation, then verifies both. It runs cosign in a digest-pinned
`bitnami/cosign` container with `COSIGN_PASSWORD=""` — **the key must have an
empty passphrase**.

```bash
mkdir -p keys                          # keys/ is gitignored
cosign generate key-pair keys/cosign.key
#   → "Enter password for new key":  press Enter (empty)
#   → "Repeat password":             press Enter (empty)
# produces: keys/cosign.key (private) + keys/cosign.pub (public)
```

**Jenkins credentials** (both Secret file):
- `cosign-key` → `keys/cosign.key` (private)
- `cosign-pub` → `keys/cosign.pub` (public)

### 5.2 Helm chart signing — GPG provenance

The CD pipeline packages the in-repo chart (`deploy/helm/notes-app`),
GPG-signs it (provenance), and verifies the signature with the committed public
key **before** deploying.

```bash
tools/generate-helm-signing-key.sh
#   defaults: name="devsecops-demo", email="devsecops-demo@localhost"
#   or: tools/generate-helm-signing-key.sh "Your Name" "you@example.com"
```

Writes:
- `deploy/helm/keys/public.asc` — **commit this** (used to verify).
- `deploy/helm/keys/helm-signing-key.asc` — **gitignored** (the private key).

**Jenkins credential** `helm-signing-key` (Secret file): upload
`deploy/helm/keys/helm-signing-key.asc`.

> The repo ships a demo key pair so the pipeline runs out of the box. For real
> use, regenerate with the script and update the `helm-signing-key` credential
> (and commit the new `public.asc`).
>
> Helm 4 signs with a built-in Go openpgp library (not the `gpg` CLI): it reads
> the old binary keyring format and matches `--key` to the key's identity name.
> The pipeline dearmors the armored key and derives the identity from the public
> key automatically — just use the script's output, no extra setup.

---

## 6. GitHub App

The GitHub App is the integration identity between GitHub and Jenkins. It powers
the multibranch **branch source + webhook trigger** (GitHub plugin) and
**check-run reporting** (GitHub Checks plugin).

### 6.1 Create the App

GitHub → your account → **Settings → Developer settings → GitHub Apps → New
GitHub App**:

- **App name:** `devsecops-demo` (any name)
- **Homepage URL:** `https://github.com/<you>/devsecops-demo`
- **Callback URL:** `https://<jenkins>/github-webhook` (needed for webhook
  triggering; leave "Disable webhook" **unchecked**)
- **Permissions:**
  - Contents: **Read and write** (branch source + checkout)
  - Checks: **Read and write** (check runs)
  - Metadata: **Read only** (always required)
- **Create GitHub App**

### 6.2 Private key + App ID

- On the App's settings page → **Generate private key** → download the `.pem`.
  This is the App's certificate — keep it safe.
- Note the **App ID** (numeric, shown on the settings page), e.g. `4646534`.

**Jenkins credentials:**
- `githubapp-id` (Secret text): the App ID, e.g. `4646534`.
- The `.pem` is entered into the plugin configs in section 9.1 (or stored as a
  Secret file credential and referenced).

### 6.3 Install the App on the repo

App settings → **Install App** → select your account/org → tick the
`devsecops-demo` repo → **Install**.

### 6.4 (Optional) GitHub user credential

`github-padishahiii` (Username with password): GitHub username + a fine-grained
**PAT** with `Contents: read` on the repo. Use as a fallback for SCM checkout /
API access when the App's installation token is not used.

---

## 7. Jenkins plugins

Install via **Manage Jenkins → Plugins → Available**. ("Pipeline: Aggregator"
pulls in the core workflow plugins.)

| Plugin | Why the pipeline needs it |
| --- | --- |
| **Pipeline: Aggregator** (`workflow-aggregator`) | declarative `pipeline {}`, `script`, `input`, `properties`, multibranch |
| **Docker Pipeline** (`docker-workflow`) | `agent { docker {} }`, `docker.withRegistry`, `docker.build`, `docker.image().push()` |
| **Credentials Binding** (`credentials-binding`) | `DOCKERHUB_CRED = credentials('dockerhub')` in `environment {}`, `file(...)` bindings |
| **Workspace Cleanup** (`ws-cleanup`) | `cleanWs()` in the cleanup stage |
| **Timestamper** (`timestamper`) | `timestamps()` option |
| **Git** (`git`) | `checkout scm` |
| **JUnit** (`junit`) | `junit 'app/reports/pytest.xml'` (CI post) |
| **GitHub** (`github`) | multibranch branch source + webhook trigger (uses the GitHub App) |
| **GitHub Checks** (`github-checks`) | check-run reporting to PRs (configured with the GitHub App) |

> The pipeline deliberately avoids **Pipeline Utility Steps** — it parses JSON
> with Groovy's built-in `JsonSlurper` instead of `readJSON` — so that plugin is
> **not** required.

---

## 8. Jenkins credentials (summary)

All at **System** (global) scope.

| ID | Kind | Value / source |
| --- | --- | --- |
| `dockerhub` | Username with password | Docker Hub user + access token (§3) |
| `cosign-key` | Secret file | `keys/cosign.key` (§5.1) |
| `cosign-pub` | Secret file | `keys/cosign.pub` (§5.1) |
| `kind-kubeconfig` | Secret file | `kind get kubeconfig --name kind` (§4) |
| `helm-signing-key` | Secret file | `deploy/helm/keys/helm-signing-key.asc` (§5.2) |
| `githubapp-id` | Secret text | GitHub App ID, e.g. `4646534` (§6.2) |
| `github-padishahiii` | Username with password | GitHub user + PAT (§6.4) |

---

## 9. Jenkins jobs

Two **Multibranch Pipeline** jobs, both pointing at the same repo with different
script paths.

### 9.1 Configure the GitHub connection (once)

**Manage Jenkins → Configuration → GitHub:**
- Add a **GitHub App** (App ID + the `.pem` private key).
- Add a **GitHub Server** for `https://github.com` using that App.

For check reporting: **Manage Jenkins → Configuration → GitHub Checks** → enter
the App ID + private key.

### 9.2 CI job

- New Item → **Multibranch Pipeline** → name e.g. `devsecops-demo-ci`
- **Branch Sources** → GitHub → select the server + `<you>/devsecops-demo`
- **Build Strategy** → Multibranch → **Script Path:** `Jenkinsfile.ci`

### 9.3 CD job

- New Item → **Multibranch Pipeline** → name e.g. `devsecops-demo-cd`
- **Branch Sources** → GitHub → same repo
- **Build Strategy** → Multibranch → **Script Path:** `Jenkinsfile.cd`

CD parameters (set at build time):

| Parameter | Default | Meaning |
| --- | --- | --- |
| `REPOSITORY` | `padishahiii/demo-web-app` | Docker Hub repo to push to |
| `ENVIRONMENT` | `staging` | `staging` = normal path; `production` = hotfix (straight to prod) |
| `APP_VERSION` | `1.0.0` | app version + immutable image tag (valid docker tag, ≤63 chars) |
| `RUN_DAST` | `true` | run in-cluster ZAP after the staging deploy (never against prod) |
| `PROMOTE_TO_PROD` | `false` | staging only: promote the same digest after gate + verification (manual approval) |

Common runs:
- **Deploy to staging:** `ENVIRONMENT=staging`, `PROMOTE_TO_PROD=false`
- **Staging → production:** `ENVIRONMENT=staging`, `PROMOTE_TO_PROD=true`
- **Hotfix to production:** `ENVIRONMENT=production`, `PROMOTE_TO_PROD=false`

---

## 10. Verification

### 10.1 CI

Push a commit (or "Scan Multibranch Project", then build `main`).

- **Expected: the build FAILS at the gate.** gitleaks (custom rule in
  `security/gitleaks.toml`) detects the seeded `ds-demo-…` token in
  `app/config.py`, and `policy.yaml` treats secret leaks as categorical
  (`fail_tools: [gitleaks]`). **This is the demo working** — the gate blocks a
  leaked secret.
- The semgrep MD5 finding (`no-md5-hashing`, HIGH) is matched by exception
  `EXC-0042` → WARN (non-blocking).
- Artifacts: `reports/*.sarif`, `reports/sbom.cdx.json`, `reports/grype.json`,
  `reports/security-report/report.md`, `gate-decision.json`.

> To see a green CI you'd remove the seeded token — but that defeats the demo.
> The point is that **the gate decides**, not the scanner's exit code.

### 10.2 CD (staging)

Build the CD job on `main` with `ENVIRONMENT=staging`, `PROMOTE_TO_PROD=false`.

- Expected: image built + pushed (3 tags), SBOM + trivy, image gate, cosign
  sign+verify, chart packaged + GPG-signed, **staging deploy succeeds**
  (`kubectl rollout status` OK), ZAP DAST runs in-cluster, report pulled out.
- The app has a seeded SQLi endpoint (`/demo/unsafe-search`), so ZAP reports a
  High finding and the **DAST-aware promotion gate fails** — again the demo
  working (a DAST High blocks promotion).
- Artifacts: `reports/zap-report.{json,html}`, `reports/zap-exit.txt`,
  `gate-decision-dast.json`, `notes-app-*.tgz.prov`,
  `reports/security-report*/report.md`, `verification-*.txt/json`.

### 10.3 (Optional) View the app

```bash
kubectl --kubeconfig kind-kubeconfig.yaml port-forward -n demo-staging svc/notes 8080:80
curl -s localhost:8080/health
```

---

## 11. Troubleshooting / gotchas

- **`KIND_NODE` mismatch** — if the cluster isn't named `kind`, the node
  container isn't `kind-control-plane` and DAST report retrieval (`docker cp`)
  fails. Recreate with the default name or update `KIND_NODE`.
- **Stale kubeconfig port** — recreating the kind cluster changes the
  API-server port. Re-run `kind get kubeconfig --name kind` and update the
  `kind-kubeconfig` credential.
- **cosign "invalid private key" / passphrase prompt** — the key must be
  passphrase-less (the pipeline signs with `COSIGN_PASSWORD=""`). Regenerate
  with empty passwords.
- **helm "private key not found"** — the `helm-signing-key` credential must be
  the **armored** private key from `tools/generate-helm-signing-key.sh` (the
  pipeline dearmors it), and `deploy/helm/keys/public.asc` must match it.
- **DAST report missing** — the agent's Docker daemon must be the one running
  the kind node; the report dir is a per-run hostPath inside the node container
  (pulled out via `docker cp`, then cleaned up).
- **Private Docker Hub repo** — the pipeline creates an in-cluster `regcred`
  secret from the `dockerhub` credential; if that credential is wrong, in-cluster
  image pulls fail.
