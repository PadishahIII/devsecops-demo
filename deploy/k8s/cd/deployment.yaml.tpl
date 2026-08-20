# Rendered by Jenkinsfile.cd (renderManifest) — do not edit generated output.
# The image is ALWAYS digest-pinned (${IMAGE} = registry/repo@sha256:...) —
# build once, promote the same digest (docs/DESIGN.md design decision #4).
apiVersion: apps/v1
kind: Deployment
metadata:
  name: notes
  namespace: ${NS}
  labels:
    app: notes
    environment: ${ENV}
    version: ${APP_VERSION}
    pipeline: cd-${BUILD_NUMBER}
spec:
  replicas: ${REPLICAS}
  selector:
    matchLabels:
      app: notes
  template:
    metadata:
      labels:
        app: notes
        environment: ${ENV}
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: notes
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          ports:
            - name: http
              containerPort: 8000
          envFrom:
            - secretRef:
                name: notes-secret
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 65532
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 250m
              memory: 256Mi
          readinessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 3
            periodSeconds: 5
          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
      imagePullSecrets:
        - name: regcred