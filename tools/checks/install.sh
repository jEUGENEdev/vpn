#!/usr/bin/env bash
# Pinned, local CLI tools; no hosted scanner or repository API token required.
set -euo pipefail
go install github.com/zricethezav/gitleaks/v8@v8.30.1
go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.1
