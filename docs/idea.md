Suggested stages for a sample Java/Python app + container:

Secret scan (Gitleaks / TruffleHog)
SCA + SBOM (Syft + Grype, or OSV-Scanner / Dependabot-style)
SAST (Semgrep and/or your Java SAST direction; CodeQL if time)
IaC / manifest scan (Checkov or Trivy config on Terraform/K8s YAML)
Build image → Trivy (or Grype) → sign (Cosign demo)
DAST in pipeline or nightly (ZAP baseline, or a thin hook to your DAST thinking)
Deploy to kind/K8s with a simple gate (fail on Critical, warn on High, ticket on Medium)

**Security gate design**: severity, exploitability, reachability, exception process

- AI triage and prioritization

**Vuln Management**: https://defectdojo.com/pricing , free version

**Documentation**
produce lightweight internal-style docs (1–2 pages each):

- Secure SDLC map: where controls sit in demand → design → code → build → test → release → operate
- Tooling matrix: SAST / DAST / SCA / container / IaC / secrets / runtime — owner, gate type, noise strategy
- Vuln management flow: discover → triage → SLA → fix → verify → exception
- **Metrics**: coverage (% repos with SAST), MTTD/MTTR for Critical, false positive rate, % CI failures due to security, AI triage precision if you add it
- Threat modeling mini-practice: STRIDE on your sample app + on an “AI code-audit service”

**Pipeline**

![](../assets/2026-08-14-11-29-48.png)

Pipeline:
Jenkins
-> fmt/lint+unit tests+build image
-> {gitleaks, SAST, Syft+grype SBOM vuln check, Trivy image scan}
-> GATE: normalize -> policy -> decision, fail critical, warn high, exceptions, **Needs optimization**
-> docker buildx ONCE (provenance+SBOM) -> syft SBOM (CycloneDX) -> Trivy image scan
-> cosign sign
-> deploy to kind (or free tier cloud k8s cluster), Kyverno admission (verify images (sig+SBOM)+PSS+registry), smoke test (health)
-> DAST ZAP -> GATE (use npoc's strategies)

-> Vulns go into vuln management platform.
-> Manage metrics.

**tech stack**

- Jenkins: to run pipelines, use GKE or other free tier cloud provider to serve Jenkins
- Vuln management: Defect Dojo free tier

**Tool selection**

- linter: ruff
- unit test: pytest
- secrets: gitleaks
- SAST: semgrep
- SCA: syft+grype
- IaC check: trivy
- image-scan: trivy
- image-sign: cosign
- DAST: ZAP

**Gate**

1. read artifacts using corresponding schema
2. assess reachability/exploitability, exposure via AI (configure api key by env, injected by jenkins secret - base url+api key)
3. filter and group vulns using specific policy (configuration file, e.g. fail critical, warn high and skip exceptions)
4. generate human-readable report with reference links to the artifacts and upload to jenkins artifact
5. determine whether to fail the workflow or not

**Vuln Management**
discover → triage → SLA → fix → verify → exception

## Progress

- [ ] build the minimal pipeline with tool integration and minimal gates, run on a simple repo -> to validate it works
- [ ] Extend demo repos and design metrics
- [ ] Add AI triage and add metrics
- [ ] Design and implement more complex gates
