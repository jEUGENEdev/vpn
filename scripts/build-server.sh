#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o build/linevpn-server-linux-amd64 ./cmd/linevpn-server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o build/linevpn-keygen-linux-amd64 ./cmd/linevpn-keygen
python3 - <<'PY'
import hashlib
from pathlib import Path
names = ['linevpn-server-linux-amd64', 'linevpn-keygen-linux-amd64']
with Path('build/SHA256SUMS').open('w') as output:
    for name in names:
        with (Path('build') / name).open('rb') as binary:
            output.write(hashlib.file_digest(binary, 'sha256').hexdigest() + '  ' + name + '\n')
PY
