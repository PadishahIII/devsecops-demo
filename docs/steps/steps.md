**Note:**
- The report viewers (like SBOM viewer, sarif viewer) are out of scope of this project, you can use whatever viewer applicable.
- We use deliberately vulnerable application to show case the fail cases here.

# CI

## Source Clone
<img width="1082" height="624" alt="image" src="https://github.com/user-attachments/assets/9360992c-fad9-4152-adf3-40a3f9fb7384" />


## Fmt && Lint && Unit-test
<img width="1101" height="588" alt="image" src="https://github.com/user-attachments/assets/2838b3b4-6dbb-4502-917f-975ef94347d0" />


## Secret Scan
- Redacted to avoid making Jenkins log the second leakage place

Secret leak FAILs the pipeline in the gating stage (best-effort).
<img width="1096" height="532" alt="image" src="https://github.com/user-attachments/assets/1896b7a9-d37d-4095-8a21-816a262f6290" />


## SAST Scan (Semgrep)

<img width="1091" height="690" alt="image" src="https://github.com/user-attachments/assets/ed6506d9-d68f-4a33-9213-0e003960c3c1" />

View the sarif:
<img width="1445" height="595" alt="image" src="https://github.com/user-attachments/assets/05c5fc18-f2a0-43ac-a30d-cabfb6b61ba9" />


## SCA (syft+grype) - Dependency Report
<img width="1094" height="398" alt="image" src="https://github.com/user-attachments/assets/1d9dcaa2-a9b3-4989-9706-f444e2034fdc" />

View the dependency report:
<img width="722" height="594" alt="image" src="https://github.com/user-attachments/assets/29729b10-bd1e-4478-967d-651eb192f50d" />

Check supply chain vulns:
<img width="536" height="434" alt="image" src="https://github.com/user-attachments/assets/525a86b0-b26a-42c1-997d-3a7da1d0c37b" />


## IaC (trivy)

<img width="1103" height="355" alt="image" src="https://github.com/user-attachments/assets/e12cc52f-e757-4ff4-84a6-021623aab2b2" />

View the sarif:
<img width="1401" height="355" alt="image" src="https://github.com/user-attachments/assets/cab50095-7abd-435e-b6b7-9456ac2df122" />


## Gate
This is our decision gate, using custom policy - fail critical and categorical(gitleaks), warn high.
<img width="1170" height="623" alt="image" src="https://github.com/user-attachments/assets/fa3a20be-b7c1-47db-8302-b5feeb6de4d8" />


# CD

## Build and Push Image

## Image SBOM (syft)

## Image Scan (tryvy)

## Gate

## Image Sign && Attestation

## Sign Helm Chart

## Deploy

## DAST (ZAP baseline)

## Vuln Gate

## Post-Deploy Verification

## Production Deployment
