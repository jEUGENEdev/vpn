#!/usr/bin/env bash
# Run from a checkout or an extracted repository archive, from any directory.
set -euo pipefail
repo_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'Python 3.12+ is required. Ubuntu/WSL: sudo apt-get install python3 python3-venv' >&2
  exit 1
fi
exec python3 "$repo_dir/scripts/deploy-manual.py" "$@"
