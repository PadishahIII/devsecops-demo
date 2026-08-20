# Rendered by Jenkinsfile.cd (renderManifest) — do not edit generated output.
# Post-deployment smoke test, run as an in-cluster Job: health + CRUD + search
# against the ClusterIP service (no port-forward needed). The Job fails (and
# the pipeline with it) if any check fails; `kubectl logs job/smoke-test`
# surfaces the failing step.
apiVersion: batch/v1
kind: Job
metadata:
  name: smoke-test
  namespace: ${NS}
  labels:
    app: smoke-test
    environment: ${ENV}
    pipeline: cd-${BUILD_NUMBER}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    metadata:
      labels:
        job-name: smoke-test
    spec:
      restartPolicy: Never
      containers:
        - name: smoke
          image: curlimages/curl:8.12.1
          command: ["/bin/sh", "-c"]
          args:
            - |
              set -eu
              echo "smoke: health"
              curl -fsS -m 10 http://${SVC_URL}/health >/dev/null
              echo "smoke: create note"
              curl -fsS -m 10 -X POST -d "title=smoke-$(date +%s)&content=ok" http://${SVC_URL}/notes >/dev/null
              echo "smoke: search"
              curl -fsS -m 10 "http://${SVC_URL}/search?q=smoke" | grep -q "smoke"
              echo "smoke tests passed"