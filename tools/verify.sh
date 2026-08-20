set -e
cosign login docker.io -u "$DOCKERHUB_USERNAME" -p "$DOCKERHUB_PASSWORD"
cosign verify --key "$COSIGN_KEY_PUB" "${DOCKER_IMAGE}@${DIGEST}"
cosign verify-attestation --type cyclonedx --key "$COSIGN_KEY_PUB" "${DOCKER_IMAGE}@${DIGEST}"

