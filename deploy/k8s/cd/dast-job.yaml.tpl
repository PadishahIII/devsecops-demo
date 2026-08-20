# Rendered by Jenkinsfile.cd (renderManifest) — do not edit generated output.
#
# In-cluster ZAP baseline scan of the freshly deployed service. Run as a k8s
# Job so the scanner shares the cluster network with the app (no port-forward,
# no host.docker.internal gymnastics).
#
# Notes on the design:
#   * the scan script is invoked by relative name — the zaproxy image puts
#     zap-baseline.py in /zap/ which is on PATH (Dockerfile-stable).
#   * the container exits 0 even when ZAP reports findings: the scan's own
#     verdict is captured to zap-exit.txt and the PIPELINE GATE decides.
#     backoffLimit 0 means we never silently retry a broken scan; a missing
#     zap-report.json makes the pipeline fail closed.
#   * REPORT RETRIEVAL: /zap/wrk is a hostPath dir INSIDE the kind node
#     container (${DAST_REPORTS_HOST_DIR}) — in kind, hostPath resolves in the
#     node container's fs, not the physical host. kubectl cp is exec-based and
#     CANNOT read from a completed pod (kubernetes#111045), so the report must
#     survive container exit; the Jenkinsfile pulls it out of the node container
#     with `docker cp` (agent and node share the host). The Jenkinsfile also
#     pre-creates the dir (mode 777) so the zap user (uid 1000) can write it.
#   * default image user is `zap` (uid 1000); runAsUser matches it.
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
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: zap
          # pinned by digest (the :stable tag is a moving target)
          image: ghcr.io/zaproxy/zaproxy:stable@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef
          command: ["/bin/sh", "-c"]
          args:
            - |
              set -u
              mkdir -p /zap/wrk
              zap-baseline.py -t ${DAST_URL} -l WARN \
                -J /zap/wrk/zap-report.json -r /zap/wrk/zap-report.html \
                || echo "zap exit=$? (gate decides)" | tee /zap/wrk/zap-exit.txt
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
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
          hostPath:
            path: ${DAST_REPORTS_HOST_DIR}
            type: DirectoryOrCreate
