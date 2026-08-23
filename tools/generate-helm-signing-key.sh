#!/usr/bin/env bash
# Generate a GPG key pair for Helm chart provenance signing.
#
# The PRIVATE key becomes a Jenkins File credential (id `helm-signing-key`) used
# by the CD pipeline to sign the chart. The PUBLIC key is committed to the repo
# (deploy/helm/keys/public.asc) and used to verify the signature on deploy.
#
# How the pipeline uses them (see Jenkinsfile.cd buildSignedChart):
#   * Helm 4 signs with a built-in Go openpgp library that reads the OLD binary
#     keyring format, so the pipeline DEARMORS the armored keys first.
#   * `helm package --sign --key <identity>` matches the key's identity NAME
#     (e.g. "Name <email>"), which the pipeline derives from the public key.
#
# Usage:
#   tools/generate-helm-signing-key.sh [name] [email]
#
# Defaults: name="devsecops-demo", email="devsecops-demo@localhost"
#
# After running:
#   1. Add the private key as a Jenkins File credential (id: helm-signing-key)
#   2. Commit deploy/helm/keys/public.asc
#   3. Delete the private key file (it is now in Jenkins)
set -euo pipefail

command -v gpg >/dev/null || {
	echo 'ERROR: gpg not found — install it first (e.g. brew install gnupg)' >&2
	exit 1
}

NAME="${1:-devsecops-demo}"
EMAIL="${2:-devsecops-demo@localhost}"
KEYDIR="$(mktemp -d)"
trap 'rm -rf "$KEYDIR"' EXIT

echo "==> Generating an ed25519 GPG key pair (no passphrase, for CI)..."
gpg --homedir "$KEYDIR" --batch --pinentry-mode loopback --passphrase '' \
    --quick-gen-key "$NAME <$EMAIL>" ed25519 sign never 2>/dev/null

# Derive the fingerprint and export both keys (armored).
FPR="$(gpg --homedir "$KEYDIR" --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')"
echo "==> Key fingerprint: $FPR"

mkdir -p deploy/helm/keys
gpg --homedir "$KEYDIR" --batch --pinentry-mode loopback --passphrase '' \
    --armor --export "$FPR" > deploy/helm/keys/public.asc
echo "==> Public key written to deploy/helm/keys/public.asc (commit this)"

# Private key: gitignored (deploy/helm/keys/* except public.asc). Import it into
# Jenkins, then delete it.
gpg --homedir "$KEYDIR" --batch --pinentry-mode loopback --passphrase '' \
    --armor --export-secret-keys "$FPR" > deploy/helm/keys/helm-signing-key.asc
echo "==> Private key written to deploy/helm/keys/helm-signing-key.asc (gitignored)"
echo ""
echo "Next steps:"
echo "  1. In Jenkins: Credentials -> Add -> Secret file"
echo "     id: helm-signing-key   file: deploy/helm/keys/helm-signing-key.asc"
echo "  2. Commit deploy/helm/keys/public.asc"
echo "  3. Delete deploy/helm/keys/helm-signing-key.asc (it is now in Jenkins)"
echo ""
echo "Verify the public key parses (the pipeline derives the signing identity from it):"
echo "  gpg --show-keys --with-colons deploy/helm/keys/public.asc | awk -F: '/^uid/{print \$10; exit}'"
