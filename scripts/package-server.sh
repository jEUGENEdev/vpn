#!/usr/bin/env bash
# Run on the CI runner or developer machine, never on the VPN server.
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/build-server.sh
tar -czf build/linevpn-server-bundle.tar.gz \
  --exclude='__pycache__' --exclude='*.pyc' -T deploy/source-files.txt \
  build/linevpn-server-linux-amd64 build/linevpn-keygen-linux-amd64 build/SHA256SUMS
