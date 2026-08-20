set -e
# DOCKERHUB_PASSWORD is an env var (not a file) — feed it via stdin, never the CLI
printf %s "$DOCKERHUB_PASSWORD" | cosign login docker.io -u "$DOCKERHUB_USERNAME" --password-stdin
cosign sign --yes --key "$COSIGN_KEY" "${DOCKER_IMAGE}@${DIGEST}"
cosign attest --yes --type cyclonedx --predicate ${PREDICATE} --key "$COSIGN_KEY" "${DOCKER_IMAGE}@${DIGEST}"
