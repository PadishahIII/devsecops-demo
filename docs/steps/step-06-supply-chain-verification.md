# Step 06 — Supply-chain verification: cosign, SBOM attestation, Helm provenance

| | |
| --- | --- |
| Pipeline | `Jenkinsfile.cd` stages 6–8 (+ host-side demos) |
| Mode | **Deep-dive** — pick this when the audience asks "how do we know it's the same artifact?" |
| Prereqs | A CD build that reached the sign/verify/chart stages (step 03) |

## Objective

Make the trust chain visible and *provable*: image signature, SBOM attestation,
chart provenance — and the tamper cases that each one detects. Three artifacts,
three verifications, one story: **deploy what you attest, attest what you gate**.

## Walkthrough

### 1. Cosign — sign and attest (from the build log)

`Sign Image && attach SBOM attestation - cosign`:

```
cosign sign --yes --key /keys/cosign.key docker.io/…@sha256:<digest>
cosign attest --yes --type cyclonedx --predicate sbom.cdx.image.json --key … @sha256:<digest>
```

Point-out facts:

- The subject is the **digest** — signatures bind to content, not to tag names.
- The predicate is the Cyclonedx SBOM produced two stages earlier — the scanned
  artifact and the attested artifact are the same bytes.
- Credentials: private key is a Jenkins File credential, mounted read-only into
  the container; Hub login uses `--password-stdin` (never the CLI arg).

🖼 `assets/screenshots/step-06-01-sign-attest.png` — the two cosign command lines
with the digest subject + predicate path.

### 2. Cosign — verify (self-check)

`Verify signature and attestation - cosign` — public key credential:

```
cosign verify --key /keys/cosign.pub …@sha256:<digest>
cosign verify-attestation --key /keys/cosign.pub …@sha256:<digest>
```

Both must print OK. The demo loop is closed **inside the pipeline**: we signed,
we proved the signature verifies, THEN the chart/deploy stages run.

🖼 `assets/screenshots/step-06-02-verify.png` — verify output (signature
matches / attestation verified lines).

### 3. Host-side tamper demo (5 minutes, high impact)

```bash
# pull the digested image and re-tag under a FAKE digest
docker pull docker.io/padishahiii/demo-web-app@sha256:<digest>
docker tag  <that image>  docker.io/padishahiii/demo-web-app:attacker-tampered
docker push docker.io/padishahiii/demo-web-app:attacker-tampered
# cosign verify against the REAL digest must fail
cosign verify --key keys/cosign.pub docker.io/padishahiii/demo-web-app@sha256:<real-digest>
```

`Error: no matching signatures` — because the real digest has the signature; the
tampered tag is a different digest with none. The deploy path uses the digest, so
the tamper never reaches a cluster.

🖼 `assets/screenshots/step-06-03-tamper.png` — the verify error against the
tampered tag.

### 4. Helm chart provenance

`Package & Sign Chart`:

```
helm package --sign --key "<identity>" --keyring rendered/secring.gpg deploy/helm/notes-app/
helm verify notes-app-<ver>.tgz --keyring rendered/pubring.gpg
```

The verify uses the **committed** public key (`deploy/helm/keys/public.asc`) —
no secret key material exists in the repo; the private key is the
`helm-signing-key` credential. Output ends with the chart hash verified.

🖼 `assets/screenshots/step-06-04-chart-verify.png` — `helm verify` output
("Chart Hash Verified").

### 5. Chart tamper demo

```bash
cp notes-app-<ver>.tgz tampered.tgz
printf 'x' >> tampered.tgz
helm verify tampered.tgz --keyring rendered/pubring.gpg
# → Error: sha256 sum does not match
```

🖼 `assets/screenshots/step-06-05-chart-tamper.png` — the mismatch error.

### 6. The archived evidence

From the build artifacts: `notes-app-*.tgz.prov` (the signature), `reports/
sbom.cdx.image.json`, `reports/digest.txt`. These travel with the build — the
audit story is "every artifact I deployed has a verification record".

🖼 `assets/screenshots/step-06-06-evidence.png` — artifacts list view.

## What to point out (interview callouts)

- **Three separate artifacts**: signature (identity) ≠ SBOM (inventory) ≠ chart
  .prov (deploy-unit authenticity) — conflating them is a classic supply-chain
  mistake; this pipeline keeps them distinct and verifies each.
- **Key material hygiene**: private keys exist ONLY as Jenkins credentials;
  the repo ships public keys only (`deploy/helm/keys/public.asc` is committed,
  the secret pair is gitignored).
- **Digest-pinned deploys are the enforcement** — signing alone is ceremony
  without `@sha256:` deploys + `verify-images`-class admission (bd
  devsecops-demo-e1g wires the Kyverno admission half).
- **Upgrade path**: the design's keyless OIDC variant (`docs/DESIGN.md`) removes
  even the key-based trust anchor; this repo chose key-based cosign for
  reproducibility on a plain Jenkins agent.

## Verification checklist

- [ ] sign + attest subject is the digest; predicate = step-03 SBOM
- [ ] verify + verify-attestation both OK in the build log
- [ ] image tamper demo: cosign verify fails against the tampered tag
- [ ] helm verify OK in the build log; tamper demo shows sha mismatch
- [ ] `.tgz.prov` + SBOM + digest.txt archived
- [ ] screenshots captured and committed

## Capture checklist

- [ ] `step-06-01-sign-attest.png`
- [ ] `step-06-02-verify.png`
- [ ] `step-06-03-tamper.png`
- [ ] `step-06-04-chart-verify.png`
- [ ] `step-06-05-chart-tamper.png`
- [ ] `step-06-06-evidence.png`