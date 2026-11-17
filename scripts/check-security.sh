#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
for tool in actionlint gitleaks osv-scanner python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Missing %s; see docs/security-quality.md\n' "$tool" >&2
    exit 1
  fi
done

# actionlint validates workflow semantics. Shell syntax is checked by check.sh;
# optional host shellcheck/pyflakes must not change this gate between machines.
actionlint -shellcheck='' -pyflakes=''
python3 scripts/test-secret-scanning.py
# Scan the working tree, including new files, with all secret values redacted.
# History is a separate investigation; this result is not a history-clean claim.
gitleaks dir . --redact --config .gitleaks.toml
# Do not omit dev dependencies: they include Electron and installer build tools.
# Download whole public ecosystem databases; --offline keeps dependency names
# and versions local (no registry audit, OSV query or deps.dev request).
osv-scanner scan source --offline --download-offline-databases \
  --lockfile go.mod --lockfile apps/desktop/package-lock.json \
  --lockfile tools/ui-tests/package-lock.json --lockfile tools/checks/requirements.txt \
  --lockfile deploy/requirements.txt --lockfile deploy/remote-requirements.txt
printf '\nPASS: workflow lint, source secret scan and dependency audits\n'
