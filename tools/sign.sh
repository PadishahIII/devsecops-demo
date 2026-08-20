set -e
cosign login docker.io -u "$DOCKERHUB_USERNAME" -p "$DOCKERHUB_PASSWORD"
cosign sign --yes --key "$COSIGN_KEY" "${DOCKER_IMAGE}@${DIGEST}"
cosign attest --yes --type cyclonedx --predicate ${PREDICATE} --key "$COSIGN_KEY" "${DOCKER_IMAGE}@${DIGEST}"
