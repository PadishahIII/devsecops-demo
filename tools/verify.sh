set -e
# password via stdin — never on the command line (visible in process list / docker inspect)
printf %s "$DOCKERHUB_PASSWORD" | cosign login docker.io -u "$DOCKERHUB_USERNAME" --password-stdin
cosign verify --key "$COSIGN_KEY_PUB" "${DOCKER_IMAGE}@${DIGEST}"
cosign verify-attestation --type cyclonedx --key "$COSIGN_KEY_PUB" "${DOCKER_IMAGE}@${DIGEST}"
