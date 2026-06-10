#!/usr/bin/env bash
set -euo pipefail

# sign-release.sh — Sign a release artifact with Origin
#
# Usage: ./sign-release.sh <artifact-path> [<key-file>]
#
# If no key file is specified, uses origin-secret.key in the current directory.
# Produces <artifact>.origin next to the artifact.

ARTIFACT="${1:?Usage: $0 <artifact-path> [<key-file>]}"
KEY="${2:-origin-secret.key}"

if [ ! -f "$ARTIFACT" ]; then
    echo "Error: artifact not found: $ARTIFACT"
    exit 1
fi

if [ ! -f "$KEY" ]; then
    echo "Error: key not found: $KEY"
    echo ""
    echo "Generate a key pair first:"
    echo "  origin keygen"
    exit 1
fi

echo "Signing $ARTIFACT..."
origin sign "$ARTIFACT" --key "$KEY"

echo ""
echo "Verifying..."
origin verify "${ARTIFACT}.origin" "$ARTIFACT" --consistency-only

echo ""
echo "Done. Statement written to ${ARTIFACT}.origin"
