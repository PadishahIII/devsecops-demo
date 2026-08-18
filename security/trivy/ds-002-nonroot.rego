# =============================================================================
# DS-002: Containers must run as non-root (HIGH)
# Trivy custom policy — one policy per package, one package per file.
# =============================================================================
# METADATA
# title: "Containers must run as non-root"
# description: "runAsNonRoot must be explicitly set to true on every container."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: DS-002
#   severity: HIGH
#   recommended_action: "Set 'securityContext.runAsNonRoot: true' on every container."
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.DS002

import rego.v1

deny contains res if {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf("DS-002: Deployment %s has a container without runAsNonRoot=true", [input.metadata.name])
  res := result.new(msg, container)
}
