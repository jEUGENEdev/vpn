#!/bin/bash
# launchd owns this root supervisor; the network worker still drops its UID.
# Recovery also runs when the worker crashes, before launchd restarts it.
set -u
vpn_base='/Library/Application Support/LineVPN'
vpn_agent="$vpn_base/linevpn-agent"
vpn_pid=''
cleanup() { "$vpn_agent" -data /var/lib/linevpn -recover-network; }
stop_worker() {
  if [[ -n "$vpn_pid" ]]; then
    kill -TERM "$vpn_pid" 2>/dev/null || true
    ( sleep 10; kill -KILL "$vpn_pid" 2>/dev/null || true ) &
    vpn_watchdog=$!
    wait "$vpn_pid" 2>/dev/null || true
    kill "$vpn_watchdog" 2>/dev/null || true
    wait "$vpn_watchdog" 2>/dev/null || true
  fi
  exit 0
}
trap cleanup EXIT
trap stop_worker TERM INT HUP
"$vpn_agent" -data /var/lib/linevpn &
vpn_pid=$!
vpn_missing=0
while kill -0 "$vpn_pid" 2>/dev/null; do
  if [[ -d /Applications/LineVPN.app ]]; then
    [[ -f "$vpn_base/app-was-installed" ]] || touch "$vpn_base/app-was-installed"
    vpn_missing=0
  elif [[ -f "$vpn_base/app-was-installed" ]]; then
    vpn_missing=$((vpn_missing + 1))
    # Allow atomic updates/moves a grace period. Removing the app must not
    # leave a hidden daemon capturing traffic forever, including after reboot.
    if [[ "$vpn_missing" -ge 15 ]]; then
      /bin/launchctl disable system/dev.linevpn.agent || true
      stop_worker
    fi
  fi
  sleep 2
done
wait "$vpn_pid"
