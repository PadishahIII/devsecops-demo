# Decisions

## 2026-08-19 — Trivy FP reduction: `--ignore-unfixed` + VEX policy

**Context**
Trivy scans surface many findings that are not actionable: vulnerabilities
with no upstream fix yet, and fixed-in-version CVEs (e.g. CVE-2024-6827 in
`gunicorn==21.2.0`) that cannot be patched forward without a breaking change
or that are not reachable in this deployment. Unfiltered, these drown the
real findings and erode scanner credibility.

**Decision**
Reduce Trivy false positives by combining two mechanisms:

1. `--ignore-unfixed` — suppress findings that have no fix available; they
   only add noise until the upstream release exists.
2. `--vex /path/to/vex.json` — maintain a VEX policy as the auditable,
   evidence-carrying way to suppress a *known, fixable* vulnerability.

   **Operation**: try **fix forward first** — upgrade the dependency or pin
   to the patched version. Resort to a VEX statement only when a forward fix
   is breaking (incompatible upgrade, no patched release) or the vulnerable
   code is not reachable, and only with a clear justification
   (`status: not_affected` + `justification` + `impact_statement`, see
   `security/trivy/vex.openvex.json` and `docs/VEX.md`).

**Gating**
- **Warn in CI** — Trivy findings in the pipeline are non-blocking; they are
  reported, triaged, and tracked (see the gate/report stage and
  `security/policy.yaml`).
- **Block in CD** — before promotion/deploy, the same policy is enforced
  hard: unexcepted findings fail the deployment gate.

**Why VEX over `.trivyignore`**
- VEX is an open standard (OpenVEX / CycloneDX / CSAF), tool-agnostic, and
  shares the decision with other scanners (Grype, OSPO tooling).
- It carries *why* (status, justification, impact statement), so the
  acceptance is auditable and expires naturally when the pin moves.
- `.trivyignore` is a bare ID list: "don't show it" with no evidence —
  a suppression, not a decision.

**Consequences**
- `docs/VEX.md` documents the scan-with/without-`--vex` demo (bd
  devsecops-demo-836) and the difference vs `.trivyignore`.
- The seeded gunicorn pin stays intentionally vulnerable so the demo shows
  the tracking story; the normal path to green remains upgrading to
  `gunicorn==22.0.0`, not accumulating VEX entries.
