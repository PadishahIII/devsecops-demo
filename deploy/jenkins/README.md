# Jenkins setup

Download from https://www.jenkins.io/download/, then:

```bash
java -jar jenkins.war --enable-future-java --httpPort=8081
```

## Credentials (Jenkins → Manage Jenkins → Credentials)

`Jenkinsfile.cd` (and the CI pipeline) expect these credential IDs:

| ID | Kind | What to put in |
| --- | --- | --- |
| `dockerhub` | Username/Password | Docker Hub username + access token |
| `cosign-key` | Secret file | cosign **private** key (e.g. `keys/cosign.key`) |
| `cosign-pub` | Secret file | cosign **public** key (e.g. `keys/cosign.pub`) |
| `kind-kubeconfig` | Secret file | kubeconfig of the kind cluster on the node — use `deploy/jenkins/kind-kubeconfig.demo.yaml` for the local demo cluster |
| `helm-signing-key` | Secret file | GPG **private** key (armored) for Helm chart provenance signing — generate with `tools/generate-helm-signing-key.sh`; the matching public key is committed at `deploy/helm/keys/public.asc` |

Generate a fresh cosign keypair if you don't have one:

```bash
cosign generate key-pair keys/cosign.key   # keys/ is gitignored
```

## Helm chart signing key

The CD pipeline packages the in-repo Helm chart (`deploy/helm/notes-app`), GPG-signs it
(provenance), and verifies the signature with the committed public key before deploying.
Generate a key pair with:

```bash
tools/generate-helm-signing-key.sh   # writes public.asc (commit) + helm-signing-key.asc (gitignored)
```

then add `deploy/helm/keys/helm-signing-key.asc` as the `helm-signing-key` secret-file
credential and commit `deploy/helm/keys/public.asc`.

> The repo ships a demo key pair so the pipeline runs out of the box. For real use,
> regenerate with `tools/generate-helm-signing-key.sh` and update the `helm-signing-key` credential.
## Local demo cluster

`kind-kubeconfig.demo.yaml` in this directory is a ready-to-use kubeconfig for
the local kind cluster (regenerate with `kind get kubeconfig --name kind` after
recreating the cluster — the port can change). The pipeline also needs the
agent's Docker daemon to be the one running the kind node (for the DAST report
retrieval — see the `KIND_NODE` env in `Jenkinsfile.cd`).
