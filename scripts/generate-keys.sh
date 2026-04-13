#!/usr/bin/env bash
# Generates an RSA-2048 keypair for JWT RS256 signing.
# Private key stays local (never committed). Public key is safe to share.
set -euo pipefail

SECRETS_DIR="$(dirname "$0")/../secrets"
mkdir -p "$SECRETS_DIR"

if [ -f "$SECRETS_DIR/jwt_private_key.pem" ]; then
  echo "Keys already exist in secrets/ — skipping generation."
  exit 0
fi

echo "Generating RSA-2048 private key..."
openssl genrsa -out "$SECRETS_DIR/jwt_private_key.pem" 2048

echo "Extracting public key..."
openssl rsa -in "$SECRETS_DIR/jwt_private_key.pem" \
            -pubout \
            -out "$SECRETS_DIR/jwt_public_key.pem"

# Permissions: private key readable only by owner
chmod 600 "$SECRETS_DIR/jwt_private_key.pem"
chmod 644 "$SECRETS_DIR/jwt_public_key.pem"

echo ""
echo "Keys written to secrets/"
echo "  Private: secrets/jwt_private_key.pem  (NEVER commit this)"
echo "  Public:  secrets/jwt_public_key.pem"
echo ""
echo "In production these live in AWS Secrets Manager."
echo "secrets/ is in .gitignore."
