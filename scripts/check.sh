#!/usr/bin/env bash
# Repository checks. Never installs a service or changes the host network.
set -euo pipefail
cd "$(dirname "$0")/.."
suite="${1:-all}"
case "$suite" in all|go|portable|ui|desktop) ;; *) printf 'Usage: %s [all|go|portable|ui|desktop]\n' "$0" >&2; exit 2;; esac

if [[ "$suite" == all || "$suite" == go ]]; then
  printf '\nChecking Go formatting, module integrity, race tests and vet\n'
  unformatted="$(git ls-files -z '*.go' | xargs -0 gofmt -l)"
  if [[ -n "$unformatted" ]]; then
    printf 'Run gofmt on:\n%s\n' "$unformatted" >&2
    exit 1
  fi
  go mod verify
  go test -count=1 -race -tags with_gvisor ./...
  go vet -tags with_gvisor ./...
fi

if [[ "$suite" == all || "$suite" == portable ]]; then
  printf '\nChecking scripts, generated installers and local deployment fixtures\n'
  for tool in node ssh ansible-playbook; do
    command -v "$tool" >/dev/null || { printf 'Missing %s; see docs/security-quality.md\n' "$tool" >&2; exit 1; }
  done
  python3 -c 'import yaml, paramiko'
  git diff --check
  git diff --cached --check
  while IFS= read -r -d '' source; do bash -n "$source"; done < <(git ls-files -z '*.sh')
  while IFS= read -r -d '' source; do node --check "$source"; done < <(git ls-files -z '*.js' '*.cjs')
  python3 scripts/test-network-packaging.py
  python3 scripts/package_version.py --check-consistent
  python3 scripts/test-installer-upgrade.py
  python3 scripts/test-deploy-actions.py
  python3 scripts/test-deploy-manual.py
  python3 scripts/test-deploy-ssh.py
fi

if [[ "$suite" == all || "$suite" == desktop ]]; then
  printf '\nChecking Electron build dependency compatibility\n'
  node scripts/test-desktop-globs.cjs
  node scripts/test-desktop-control.cjs
  node scripts/test-desktop-startup.cjs
  python3 scripts/test-branding.py
fi

if [[ "$suite" == all || "$suite" == ui ]]; then
  printf '\nChecking actual client/admin UI code in DOM and Chromium\n'
  export JSDOM_MODULE="${JSDOM_MODULE:-$PWD/tools/ui-tests/node_modules/jsdom}"
  export PLAYWRIGHT_MODULE="${PLAYWRIGHT_MODULE:-$PWD/tools/ui-tests/node_modules/playwright}"
  node scripts/test-ui-dom.cjs
  node scripts/test-ui.cjs
fi
printf '\nPASS: %s checks (native OS acceptance is separate)\n' "$suite"
