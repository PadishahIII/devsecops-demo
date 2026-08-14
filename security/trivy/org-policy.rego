# =============================================================================
# Custom Trivy config policies (policy-as-code in Rego).
# Trivy runs its built-in library PLUS these org rules on every config scan.
# Org severity overrides vendor severity — that is the point of policy-as-code:
# we classify privileged containers as CRITICAL, not High.
# =============================================================================
package trivy.policy.kubernetes

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
  some container
  container := input.spec.template.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("DS-001: Deployment %s runs privileged containers", [input.metadata.name])
}

# -----------------------------------------------------------------------------
package trivy.policy.kubernetes

__rego_metadata__ := {
  "id": "DS-002",
  "title": "Containers must run as non-root",
  "severity": "HIGH",
  "type": "Kubernetes Custom Check",
  "description": "runAsNonRoot must be explicitly set to true on every container.",
}

deny[msg] {
  some container
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf("DS-002: Deployment %s has a container without runAsNonRoot=true", [input.metadata.name])
}

# -----------------------------------------------------------------------------
package trivy.policy.kubernetes

__rego_metadata__ := {
  "id": "DS-003",
  "title": "Pod must opt into seccomp",
  "severity": "HIGH",
  "type": "Kubernetes Custom Check",
  "description": "Every pod must set seccompProfile.type=RuntimeDefault.",
}

deny[msg] {
  pod := input.spec.template.spec
  not pod.securityContext.seccompProfile
  msg := sprintf("DS-003: Deployment %s has no pod-level seccompProfile", [input.metadata.name])
}
