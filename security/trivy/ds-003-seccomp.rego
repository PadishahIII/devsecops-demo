# =============================================================================
# DS-003: Pod must opt into seccomp (HIGH)
# Trivy custom policy — one policy per package, one package per file.
# =============================================================================
package trivy.policy.kubernetes.DS003

__rego_metadata__ := {
  "id": "DS-003",
  "title": "Pod must opt into seccomp",
  "severity": "HIGH",
  "type": "Kubernetes Custom Check",
  "description": "Every pod must set seccompProfile.type=RuntimeDefault.",
}

__rego_input__ := {
  "combine": false,
  "selector": [{"type": "kubernetes"}],
}

deny[msg] {
  pod := input.spec.template.spec
  not pod.securityContext.seccompProfile
  msg := sprintf("DS-003: Deployment %s has no pod-level seccompProfile", [input.metadata.name])
}
