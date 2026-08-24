# End-to-end showcase — step-by-step run documents

This folder walks through every pipeline run you will do in the interview demo —
normal paths and failure paths — with a screenshot for each meaningful moment.
Each file is a **fill-in scaffold**: the structure, the expected content, and the
capture checklist are already written; the screenshots are the only missing piece
(bd devsecops-demo-hrj).

| Step | File | Pipeline | Story |
| --- | --- | --- | --- |
| 01 | [step-01-ci-normal-run.md](step-01-ci-normal-run.md) | CI | The full CI run: scanners firing, gate verdicts (seeded FAILs), artifacts |
| 02 | [step-02-ci-gate-warn-and-exceptions.md](step-02-ci-gate-warn-and-exceptions.md) | CI | The yellow path: WARN → UNSTABLE, EXC-0042 applied, VEX filtering, exception audit |
| 03 | [step-03-cd-staging-path.md](step-03-cd-staging-path.md) | CD | The happy path: build once → image gate → sign → chart → staging → DAST → vuln gate → smoke |
| 04 | [step-04-cd-failure-cases.md](step-04-cd-failure-cases.md) | CD | The red paths: DAST SQLi blocks promotion; fail-closed missing artifact |
| 05 | [step-05-cd-production-promotion.md](step-05-cd-production-promotion.md) | CD | The approval: promote the SAME digest to production, evidence collection |
| 06 | [step-06-supply-chain-verification.md](step-06-supply-chain-verification.md) | CD | The trust story: cosign sign/verify + SBOM attestation, helm GPG provenance, tamper demo |

## Screenshot conventions (read before capturing)

- **Location:** `assets/screenshots/<step>-NN-<slug>.png` (e.g. `step-01-03-scanners.png`).
  Crop to the area of interest; full-stage views are allowed but a zoomed-in
  artifact screenshot is worth more in an interview.
- **Annotation:** red-box the area that matters (the gate verdict line, the failing
  stage, the verify output). No text overlay needed — the caption in the doc says it.
- **Order:** capture in the same order as the walkthrough; the checklist at the end
  of each step file must be fully ticked before the step is "done".
- **Sanity:** every screenshot must show the *identifier* that makes it evidence —
  build number in the URL/header, digest in the log line, finding fingerprint in
  the report.
- **Upload:** commit the PNGs alongside the filled step file; keep each file
  < 300 KB (optimize with `sips`/`pngquant` if needed).

## Capture checklist index

- [ ] `assets/screenshots/ci-01-stage-view.png` — CI Stage View, full build
- [ ] `assets/screenshots/cd-01-stage-view.png` — CD Stage View, staging → prod run
- [ ] all per-step screenshots listed in steps 01–06 below

## Run book (before you start recording)

1. Jenkins jobs green-ify check: CI job buildable, CD job buildable, both jobs see
   the repo (multibranch → correct branch scanned).
2. Kind cluster up, kubeconfig credential valid, agent can `docker exec kind-control-plane`.
3. Docker Hub credentials valid, repo `padishahiii/demo-web-app` exists.
4. Suggested order: 01 → 02 → 03 → 04 → 05 → 06 (02 and 04 are the failure stories —
   do them while the audience is still hooked by 01).