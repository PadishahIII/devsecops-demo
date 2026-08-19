# VEX with Trivy — ignoring the seeded gunicorn CVE

This demo shows the **Vulnerability Exploitability Exchange (VEX)** workflow:
Trivy scans the app, finds the seeded gunicorn vulnerability, and the VEX
document tells it "we know, and it is `not_affected` here" — so Trivy filters
the finding out of the report while the evidence stays in the VEX.

Reference: <https://trivy.dev/docs/v0.51/guide/supply-chain/vex/>

## 1. The seed

`app/requirements.txt` pins `gunicorn==21.2.0`, which is affected by
**CVE-2024-6827** (TE.CL HTTP request smuggling, fixed in 22.0.0 — the
previous pin). Trivy's fs target (filesystem/code repository) detects it:

```bash
trivy fs --scanners vuln --severity CRITICAL,HIGH app/requirements.txt
```

Expected: CVE-2024-6827 listed as **CRITICAL** with `fixed 22.0.0`.

## 2. The VEX document

`security/trivy/vex.openvex.json` is an **OpenVEX** document
(https://openvex.dev). It says that CVE-2024-6827, as it applies to
`pkg:pypi/gunicorn@21.2.0`, is `not_affected`:

- `products` — the exact package-URL (PURL) the statement covers
- `status: not_affected` — Trivy then suppresses the detection
- `justification: vulnerable_code_not_in_execute_path` — the machine-readable
  reason, surfaced in the scan log
- `impact_statement` — the human-readable reason, reviewed by humans

## 3. Scanning with the VEX

```bash
trivy fs \
  --scanners vuln \
  --severity CRITICAL,HIGH \
  --vex security/trivy/vex.openvex.json \
  app/requirements.txt
```

The scan log shows the filter working:

```
INFO  Filtered out the detected vulnerability {"VEX format": "OpenVEX",
      "vulnerability-id": "CVE-2024-6827", "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"}
```

Without `--vex`, the finding is present; with `--vex`, it is gone from the
report — same scan, same package, the VEX is the only difference.

## 4. Why VEX instead of a `.trivyignore`

| | `.trivyignore` | VEX (`--vex`) |
| --- | --- | --- |
| Format | ad-hoc ID list, local to one tool | open standard (OpenVEX / CycloneDX / CSAF), tool-agnostic |
| Statement | "don't show it" | "affected, but not_affected **because**…" (status + justification) |
| Auditable | no — a future scanner cannot see the reasoning | yes — `impact_statement` carries the risk decision |
| Sharing | stays in this repo | can be published and consumed by other scanners (Grype, OSPO tooling) |

The VEX is a *decision with evidence*, not a suppression list.

## 5. Notes

- OpenVEX works for the `fs` / `repo` targets; a CycloneDX VEX instead needs
  an SBOM generated from the same image (`trivy image --format cyclonedx`)
  and BOM-Links in `affects.ref`.
- The seeded pin is **intentional** (docs/DESIGN.md §4.1 seed #5, bd
  devsecops-demo-836): the demo shows how the team tracks, explains, and
  gates an accepted risk. The normal path to green is upgrading to
  `gunicorn==22.0.0`, not accumulating VEX entries.
