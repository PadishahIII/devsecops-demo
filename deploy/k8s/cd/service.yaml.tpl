# Rendered by Jenkinsfile.cd (renderManifest) — do not edit generated output.
# ClusterIP service — the DAST scanner Job targets it in-cluster at
# http://notes.<ns>.svc.cluster.local:80 (no ingress needed on the kind node).
apiVersion: v1
kind: Service
metadata:
  name: notes
  namespace: ${NS}
  labels:
    app: notes
    environment: ${ENV}
spec:
  selector:
    app: notes
  ports:
    - name: http
      port: 80
      targetPort: http