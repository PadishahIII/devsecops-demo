# Rendered by Jenkinsfile.cd (renderManifest) — do not edit generated output.
apiVersion: v1
kind: Namespace
metadata:
  name: ${NS}
  labels:
    environment: ${ENV}
    app.kubernetes.io/part-of: devsecops-demo
    managed-by: jenkins-cd