#!/usr/bin/env bash
# Disposable CI machine only; never leave its network blocked after a test.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo 'Use isolated CI' >&2; exit 1; }
cd "$(dirname "$0")/.."
recover() {
  local vpn_test_status=$?
  if [[ "$vpn_test_status" -ne 0 ]]; then
    {
      sudo /sbin/pfctl -a linevpn -sr -v
      /sbin/route -n get 127.0.0.1
      /sbin/route -n get 1.1.1.1
      sudo /usr/sbin/lsof -n -P -iTCP:17891
      /bin/ps -axo uid,pid,command | grep linevpn-agent
    } > build/macos-network.log 2>&1 || true
    sudo /usr/bin/pkill -QUIT -x linevpn-agent || true
  fi
  sudo '/Library/Application Support/LineVPN/recover-network.sh' || true
  sudo tail -n 160 /var/log/install.log > build/macos-package.log 2>/dev/null || true
  sudo cat /var/log/linevpn-error.log > build/macos-service.log 2>/dev/null || true
  cat build/macos-service.log
  if [[ -f build/macos-network.log ]]; then cat build/macos-network.log; fi
}
trap recover EXIT
sudo installer -pkg apps/desktop/assets/Install-LineVPN-Service.pkg -target / > build/macos-install.log
vpn_ready=false
for ((i=0; i<20; i++)); do
  if [[ -f /var/lib/linevpn/ui-token ]]; then
    vpn_token="$(cat /var/lib/linevpn/ui-token)"
    if curl --noproxy '*' -fsS --max-time 2 -H "Authorization: Bearer $vpn_token" http://127.0.0.1:17891/local/state > build/macos-state.json; then vpn_ready=true; break; fi
  fi
  sleep 1
done
if [[ "$vpn_ready" != true ]]; then echo "Local service API never became ready" >&2; exit 1; fi
python3 -c 'import json; v=json.load(open("build/macos-state.json")); assert v["tunnel"] and v["guard"]'
dig +short +time=2 +tries=1 @172.29.255.2 example.com A | grep -Eq '^198\.(18|19)\.'
curl --noproxy '*' -s --output /dev/null --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace
curl --noproxy '*' -s --max-time 3 -H "Authorization: Bearer $vpn_token" -H 'Content-Type: application/json' --data '{"target":"1.1.1.1","action":"approve","revision":0}' http://127.0.0.1:17891/local/rules > /dev/null || true
curl --noproxy '*' -fsS --max-time 2 -H "Authorization: Bearer $vpn_token" http://127.0.0.1:17891/local/state > build/macos-state.json
python3 -c 'import json; assert "1.1.1.1" in json.load(open("build/macos-state.json"))["pending_protection"]'
if curl --noproxy '*' -s --output /dev/null --connect-timeout 2 --max-time 3 http://1.1.1.1/cdn-cgi/trace; then echo 'Approved IP escaped without VPN' >&2; exit 1; fi
sudo launchctl bootout system/dev.linevpn.agent
if curl --noproxy '*' -s --output /dev/null --connect-timeout 2 --max-time 3 http://1.1.1.1/cdn-cgi/trace; then echo 'PF guard disappeared with service' >&2; exit 1; fi
printf 'PASS: PKG install, TUN DNS, direct connection, approval block and PF after service stop\n' > build/macos-native.txt
