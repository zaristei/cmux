#!/usr/bin/env bash
set -euo pipefail

# Cross-compile the cmuxd-remote Go CLI for Linux containers.
# Produces statically-linked binaries that work in any Linux container.
#
# Usage:
#   scripts/build-container-cli.sh [--output-dir <dir>]
#
# Output (default: ~/.local/share/cmux/bin/):
#   cmux-linux-amd64
#   cmux-linux-arm64

OUTPUT_DIR="${HOME}/.local/share/cmux/bin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    *)
      echo "Unknown flag: $1" >&2
      exit 1
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REMOTE_DIR="${SCRIPT_DIR}/../daemon/remote"

if ! command -v go &>/dev/null; then
  echo "Error: Go is not installed. Install it with: brew install go" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

echo "Building cmux container CLI for Linux..."

echo "  linux/amd64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-s -w" \
  -o "${OUTPUT_DIR}/cmux-linux-amd64" \
  "${REMOTE_DIR}/cmd/cmuxd-remote/"

echo "  linux/arm64..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -ldflags="-s -w" \
  -o "${OUTPUT_DIR}/cmux-linux-arm64" \
  "${REMOTE_DIR}/cmd/cmuxd-remote/"

echo ""
echo "Built container CLI binaries:"
ls -lh "${OUTPUT_DIR}/cmux-linux-amd64" "${OUTPUT_DIR}/cmux-linux-arm64"
echo ""
echo "These binaries can be mounted into containers for cmux socket access."
