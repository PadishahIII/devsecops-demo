# =============================================================================
# DS-002: Containers must run as non-root (HIGH)
# Trivy custom policy — one policy per package, one package per file.
# =============================================================================
package trivy.policy.kubernetes.DS002

__rego_metadata__ := {
  "id": "DS-002",
  "title": "Containers must run as non-root",
  "severity": "HIGH",
  "type": "Kubernetes Custom Check",
  "description": "runAsNonRoot must be explicitly set to true on every container.",
}

__rego_input__ := {
  "combine": false,
  "selector": [{"type": "kubernetes"}],
}

deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf("DS-002: Deployment %s has a container without runAsNonRoot=true", [input.metadata.name])
}
