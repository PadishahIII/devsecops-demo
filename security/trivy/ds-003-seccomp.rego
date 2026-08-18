# =============================================================================
# DS-003: Pod must opt into seccomp (HIGH)
# Trivy custom policy — one policy per package, one package per file.
# =============================================================================
# METADATA
# title: "Pod must opt into seccomp"
# description: "Every pod must set seccompProfile.type=RuntimeDefault."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: DS-003
#   severity: HIGH
#   recommended_action: "Set 'spec.securityContext.seccompProfile.type: RuntimeDefault'."
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.DS003

import rego.v1

deny contains res if {
  pod := input.spec.template.spec
  not pod.securityContext.seccompProfile
  msg := sprintf("DS-003: Deployment %s has no pod-level seccompProfile", [input.metadata.name])
  res := result.new(msg, pod)
}
