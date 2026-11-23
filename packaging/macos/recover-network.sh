#!/bin/bash
# Explicit emergency escape. Running this disables VPN protection.
set -euo pipefail
if [[ "$EUID" -ne 0 ]]; then echo 'Run with sudo. This disables protection.' >&2; exit 1; fi
/bin/bash "$(dirname "$0")/stop-service.sh"
exec '/Library/Application Support/LineVPN/linevpn-agent' -data /var/lib/linevpn -recover-network
