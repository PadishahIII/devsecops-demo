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
<img width="1081" height="636" alt="image" src="https://github.com/user-attachments/assets/23343a93-8d1d-4444-9e56-129adecdc0af" />
<img width="1089" height="608" alt="image" src="https://github.com/user-attachments/assets/d044dc1d-2f9b-42a6-bdb7-bc0b991cdccf" />


## Image SBOM (syft)

<img width="1102" height="442" alt="image" src="https://github.com/user-attachments/assets/991ea042-58a6-4a4f-8aca-8949b289c628" />

View sbom:

<img width="1141" height="612" alt="image" src="https://github.com/user-attachments/assets/6854c6bb-87f4-4393-8bf8-6274bbd4629c" />


## Image Scan (tryvy)
- Custom VEX filter: to ignore vuln with specific reason
- Best-effort: we don't fail the build here - using gate to determine

<img width="1085" height="570" alt="image" src="https://github.com/user-attachments/assets/587b61c9-54e0-4946-9324-4c6faf8106bd" />

View sarif:

<img width="1409" height="688" alt="image" src="https://github.com/user-attachments/assets/dcc85ea3-0334-42c2-9c2d-2d5f9d33fcd6" />


## Gate

<img width="1097" height="390" alt="image" src="https://github.com/user-attachments/assets/df1bf113-ad32-42d4-928d-99d045d4e944" />


## Image Sign && Attestation (cosign)
- Sign the image and the generated SBOM

<img width="1102" height="554" alt="image" src="https://github.com/user-attachments/assets/fd7a0446-251a-4c7e-81b6-aa727b3b273b" />

Verify the registry's image signature and attestation:

<img width="1090" height="135" alt="image" src="https://github.com/user-attachments/assets/cefce2a7-0438-4d22-aa50-44ec9c2062cd" />


## Sign Helm Chart

<img width="1101" height="271" alt="image" src="https://github.com/user-attachments/assets/6f6c6c1e-c3b9-4d98-89c1-28d044f0a1f4" />


## Deploy (Helm)

<img width="1091" height="676" alt="image" src="https://github.com/user-attachments/assets/71db331f-989e-4e01-83fb-06b06cc5b872" />


## DAST (ZAP baseline)

<img width="1139" height="684" alt="image" src="https://github.com/user-attachments/assets/6e2402b9-88fd-4176-bd23-a56b3e5f0082" />


## Vuln Gate
- DAST policy: fail critical/high, warn medium, pass low, and pattern-based fail rules (sqli here)

<img width="1099" height="437" alt="image" src="https://github.com/user-attachments/assets/3677d2ec-cfd8-4d83-978b-b421f3e08f28" />


## Post-Deploy Verification
- Smoke CRUD test

<img width="1087" height="681" alt="image" src="https://github.com/user-attachments/assets/a6b97aae-99f1-414c-8101-9e49d87c5bcb" />


## Production Deployment
- Manual approval

<img width="1092" height="333" alt="image" src="https://github.com/user-attachments/assets/7087d7ba-90cb-4cbc-8547-492578e9ad34" />

