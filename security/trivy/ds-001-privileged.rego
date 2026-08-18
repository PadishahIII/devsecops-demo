# =============================================================================
# DS-001: Privileged containers are forbidden (CRITICAL)
# Trivy custom policy — one policy per package, one package per file.
# =============================================================================
# METADATA
# title: "Privileged containers are forbidden"
# description: "Containers running privileged bypass most kernel isolation. Org policy: forbidden in all environments."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: DS-001
#   severity: CRITICAL
#   recommended_action: "Remove 'privileged: true' from container securityContext."
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.DS001

import rego.v1

deny contains res if {
  container := input.spec.template.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("DS-001: Deployment %s runs privileged containers", [input.metadata.name])
  res := result.new(msg, container)
}
