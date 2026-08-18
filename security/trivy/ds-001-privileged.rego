# =============================================================================
# DS-001: Privileged containers are forbidden (CRITICAL)
# Trivy custom policy — one policy per package, one package per file.
# =============================================================================
package trivy.policy.kubernetes.DS001

__rego_metadata__ := {
  "id": "DS-001",
  "title": "Privileged containers are forbidden",
  "severity": "CRITICAL",
  "type": "Kubernetes Custom Check",
  "description": "Containers running privileged bypass most kernel isolation. Org policy: forbidden in all environments.",
}

__rego_input__ := {
  "combine": false,
  "selector": [{"type": "kubernetes"}],
}

deny[msg] {
  container := input.spec.template.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("DS-001: Deployment %s runs privileged containers", [input.metadata.name])
}
