# Decisions

## 2026-08-14 — DevSecOps demo: design-only session, locked decisions

- Context: User requested a devsecops demo for a role interview; after discussion they
  explicitly scoped the session to **design only** (no implementation). A partial
  implementation scaffold was written to the working tree **before** that instruction
  and remains UNCOMMITTED (user decides keep/delete).
- Decisions (Q&A confirmed): Python/Flask app (Java SAST narrative **discarded**);
  GitHub Actions; ephemeral **kind-in-CI + Kyverno** admission; **Cosign OIDC keyless**
  signing; post-process = minimal (`normalize.py` → `findings.jsonl` + `gate.py` +
  SARIF upload). Two-tier pipeline: PR checks (untrusted) vs main pipeline (trusted).
- Evidence: `docs/DESIGN.md` (full design, seed catalogue, tool rationale, demo script).
- Reuse: Any future implementation session must read `docs/DESIGN.md` first and follow
  its §3 validation-before-build order.
