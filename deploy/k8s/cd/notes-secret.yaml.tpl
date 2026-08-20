# Rendered by Jenkinsfile.cd (renderManifest) — do not edit generated output.
# Runtime secrets for the notes app (env-driven, see app/config.py). Values are
# base64-encoded from the Jenkins secret-text credentials `app-secret-key` and
# `admin-password-hash` at render time.
apiVersion: v1
kind: Secret
metadata:
  name: notes-secret
  namespace: ${NS}
type: Opaque
data:
  app-secret-key: ${APP_SECRET_KEY_B64}
  admin-password-hash: ${ADMIN_PASSWORD_HASH_B64}