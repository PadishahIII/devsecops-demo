set -e
cat "$DOCKERHUB_PASSWORD" | cosign login docker.io -u "$DOCKERHUB_USERNAME" --password-stdin 
cosign sign --yes --key "$COSIGN_KEY" "${DOCKER_IMAGE}@${DIGEST}"
cosign attest --yes --type cyclonedx --predicate ${PREDICATE} --key "$COSIGN_KEY" "${DOCKER_IMAGE}@${DIGEST}"
