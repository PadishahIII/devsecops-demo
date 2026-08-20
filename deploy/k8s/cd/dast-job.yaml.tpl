# Rendered by Jenkinsfile.cd (renderManifest) — do not edit generated output.
#
# In-cluster ZAP baseline scan of the freshly deployed service. Run as a k8s
# Job so the scanner shares the cluster network with the app (no port-forward,
# no host.docker.internal gymnastics).
#
# Notes on the design:
#   * the scan script is invoked by relative name — the zaproxy:stable image
#     puts zap-baseline.py in /zap/ which is on PATH (Dockerfile-stable).
#   * the container exits 0 even when ZAP reports findings: the scan's own
#     verdict is captured to zap-exit.txt and the PIPELINE GATE decides.
#     backoffLimit 0 means we never silently retry a broken scan; a missing
#     zap-report.json makes the pipeline fail closed.
#   * default image user is `zap` (uid 1000); runAsUser matches it so the
#     mounted /zap/wrk emptyDir (world-writable) is usable.
apiVersion: batch/v1
kind: Job
metadata:
  name: dast-scan
  namespace: ${NS}
  labels:
    app: dast-scan
    environment: ${ENV}
    pipeline: cd-${BUILD_NUMBER}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    metadata:
      labels:
        job-name: dast-scan
    spec:
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: zap
          image: ghcr.io/zaproxy/zaproxy:stable
          command: ["/bin/sh", "-c"]
          args:
            - |
              set -u
              mkdir -p /zap/wrk
              zap-baseline.py -t ${DAST_URL} -l WARN \
                -J /zap/wrk/zap-report.json -r /zap/wrk/zap-report.html \
                || echo "zap exit=$? (gate decides)" | tee /zap/wrk/zap-exit.txt
          volumeMounts:
            - name: wrk
              mountPath: /zap/wrk
          resources:
            requests:
              cpu: 250m
              memory: 512Mi
            limits:
              cpu: 1
              memory: 1Gi
      volumes:
        - name: wrk
          emptyDir: {}