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
  if [[ -f '/Library/Application Support/LineVPN/recover-network.sh' ]]; then
    sudo '/Library/Application Support/LineVPN/recover-network.sh' || true
  fi
  sudo tail -n 160 /var/log/install.log > build/macos-package.log 2>/dev/null || true
  sudo cat /var/log/linevpn-error.log > build/macos-service.log 2>/dev/null || true
  cat build/macos-service.log
  if [[ -f build/macos-network.log ]]; then cat build/macos-network.log; fi
}
trap recover EXIT
sudo installer -pkg build/macos-tested-service.pkg -target / > build/macos-install.log
vpn_ready=false
for ((i=0; i<20; i++)); do
  if [[ -f /var/lib/linevpn/ui-token ]]; then
    vpn_token="$(cat /var/lib/linevpn/ui-token)"
    if curl --noproxy '*' -fsS --max-time 2 -H "Authorization: Bearer $vpn_token" http://127.0.0.1:17891/local/state > build/macos-state.json; then vpn_ready=true; break; fi
  fi
  sleep 1
done
if [[ "$vpn_ready" != true ]]; then echo "Local service API never became ready" >&2; exit 1; fi
python3 -c 'import json; v=json.load(open("build/macos-state.json")); assert v["tunnel"] and not v["guard"]'
# Launch the signed app copied from the final DMG, after the packaged service is ready.
python3 - <<'PYGUI'
import os, pathlib, subprocess
report = pathlib.Path('build/macos-gui.txt').resolve()
report.unlink(missing_ok=True)
env = dict(os.environ, LINEVPN_SMOKE_TEST_REPORT=str(report))
subprocess.run(['build/macos-smoke/LineVPN.app/Contents/MacOS/LineVPN', '--background'], env=env, check=True, timeout=45)
assert report.read_text().startswith('PASS:'), 'Packaged Electron did not load the client UI'
PYGUI
dig +short +time=2 +tries=1 @172.29.255.2 example.com A | grep -Eq '^198\.(18|19)\.'
curl --noproxy '*' -s --output /dev/null --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace
# The privileged lookup helper must still identify curl after the agent drops UID.
curl --noproxy '*' -fsS --max-time 3 -H "Authorization: Bearer $vpn_token" http://127.0.0.1:17891/local/state > build/macos-state.json
vpn_curl_app="$(python3 -c 'import json; s=json.load(open("build/macos-state.json")); assert not any(r["target"]=="1.1.1.1" for r in s["requests"]); print(next(a["id"] for a in s["applications"] if a["name"]=="curl"))')"
curl --noproxy '*' -fsS --max-time 3 -H "Authorization: Bearer $vpn_token" -H 'Content-Type: application/json' --data "{\"id\":\"$vpn_curl_app\",\"decision\":\"trusted\"}" http://127.0.0.1:17891/local/applications > /dev/null
curl --noproxy '*' -fsS --output /dev/null --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace
curl --noproxy '*' -fsS --max-time 3 -H "Authorization: Bearer $vpn_token" -H 'Content-Type: application/json' --data "{\"id\":\"$vpn_curl_app\",\"decision\":\"addresses\"}" http://127.0.0.1:17891/local/applications > /dev/null
curl --noproxy '*' -s --max-time 3 -H "Authorization: Bearer $vpn_token" -H 'Content-Type: application/json' --data '{"target":"1.1.1.1","action":"approve","revision":0}' http://127.0.0.1:17891/local/rules > /dev/null || true
curl --noproxy '*' -fsS --max-time 2 -H "Authorization: Bearer $vpn_token" http://127.0.0.1:17891/local/state > build/macos-state.json
python3 -c 'import json; assert "1.1.1.1" in json.load(open("build/macos-state.json"))["pending_protection"]'
curl --noproxy '*' -fsS --output /dev/null --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace
python3 scripts/test-desktop-power.py
sudo env GITHUB_ACTIONS=true python3 scripts/test-desktop-update.py build/macos-tested-service.pkg
# Abrupt worker death must release the native interface and permit direct traffic.
sudo /usr/bin/pkill -KILL -x linevpn-agent
sleep 2
curl --noproxy '*' -fsS --output /dev/null --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace
sudo launchctl bootout system/dev.linevpn.agent
vpn_dns_keys="$(printf 'list State:/Network/Service/dev.linevpn.*/DNS\n' | /usr/sbin/scutil)"
if [[ "$vpn_dns_keys" == *'subKey'* ]]; then echo 'Temporary DNS survived service stop' >&2; exit 1; fi
curl --noproxy '*' -fsS --output /dev/null --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace
sudo '/Library/Application Support/LineVPN/uninstall.sh'
[[ ! -f /Library/LaunchDaemons/dev.linevpn.agent.plist ]]
[[ ! -e '/Library/Application Support/LineVPN/linevpn-agent' ]]
curl --noproxy '*' -fsS --output /dev/null --connect-timeout 4 --max-time 8 http://example.com
printf 'PASS: PKG install, DNS, direct fallback, off/on, process termination, service stop and uninstall recovery\n' > build/macos-native.txt
