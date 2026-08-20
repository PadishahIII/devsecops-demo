# Rendered by Jenkinsfile.cd (renderManifest) — do not edit generated output.
# Docker Hub pull secret, built from the `dockerhub` Jenkins credential at
# render time (${DOCKERCONFIGJSON_B64} = base64 docker config.json).
apiVersion: v1
kind: Secret
metadata:
  name: regcred
  namespace: ${NS}
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: ${DOCKERCONFIGJSON_B64}