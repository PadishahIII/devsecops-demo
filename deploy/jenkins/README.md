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

Generate a fresh cosign keypair if you don't have one:

```bash
cosign generate key-pair keys/cosign.key   # keys/ is gitignored
```

## Local demo cluster

`kind-kubeconfig.demo.yaml` in this directory is a ready-to-use kubeconfig for
the local kind cluster (regenerate with `kind get kubeconfig --name kind` after
recreating the cluster — the port can change). The pipeline also needs the
agent's Docker daemon to be the one running the kind node (for the DAST report
retrieval — see the `KIND_NODE` env in `Jenkinsfile.cd`).
