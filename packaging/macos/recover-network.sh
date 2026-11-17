#!/bin/bash
# Explicit emergency escape. Running this disables VPN protection.
set -euo pipefail
if [[ "$EUID" -ne 0 ]]; then echo 'Run with sudo. This disables protection.' >&2; exit 1; fi
/bin/launchctl bootout system/dev.linevpn.agent 2>/dev/null || true
exec '/Library/Application Support/LineVPN/linevpn-agent' -data /var/lib/linevpn -recover-network
