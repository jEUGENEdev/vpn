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
  sudo /bin/bash build/macos-tested-setup.app/Contents/Resources/stop-service.sh || true
  vpn_native_arch=x64
  [[ "$(uname -m)" != arm64 ]] || vpn_native_arch=arm64
  sudo "build/macos-tested-setup.app/Contents/Resources/recovery-$vpn_native_arch" -data /var/lib/linevpn -recover-network || true
  sudo tail -n 160 /var/log/install.log > build/macos-package.log 2>/dev/null || true
  sudo cat /var/log/linevpn-error.log > build/macos-service.log 2>/dev/null || true
  cat build/macos-service.log
  if [[ -f build/macos-network.log ]]; then cat build/macos-network.log; fi
}
trap recover EXIT
sudo /bin/bash build/macos-tested-setup.app/Contents/Resources/manage.sh install > build/macos-install.log
vpn_ready=false
for ((i=0; i<20; i++)); do
  if [[ -f /var/lib/linevpn/ui-token ]]; then
    vpn_token="$(cat /var/lib/linevpn/ui-token)"
    if python3 scripts/desktop_control_fixture.py state > build/macos-state.json; then vpn_ready=true; break; fi
  fi
  sleep 1
done
if [[ "$vpn_ready" != true ]]; then echo "Local service API never became ready" >&2; exit 1; fi
python3 -c 'import json; v=json.load(open("build/macos-state.json")); assert v["tunnel"] and v["guard"]'
# Launch the app installed with the service, after the packaged service is ready.
python3 - <<'PYGUI'
import os, pathlib, subprocess
report = pathlib.Path('build/macos-gui.txt').resolve()
report.unlink(missing_ok=True)
env = dict(os.environ, LINEVPN_SMOKE_TEST_REPORT=str(report))
subprocess.run(['/Applications/Сеть.app/Contents/MacOS/LineVPN', '--background'], env=env, check=True, timeout=45)
assert report.read_text().startswith('PASS:'), 'Packaged Electron did not load the client UI'
PYGUI
dig +short +time=2 +tries=1 @172.29.255.2 example.com A | grep -Eq '^198\.(18|19)\.'
curl --noproxy '*' -s --output /dev/null --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace
# The privileged lookup helper must still identify curl after the agent drops UID.
python3 scripts/desktop_control_fixture.py state > build/macos-state.json
vpn_curl_app="$(python3 -c 'import json; s=json.load(open("build/macos-state.json")); assert not any(r["target"]=="1.1.1.1" for r in s["requests"]); print(next(a["id"] for a in s["applications"] if a["name"]=="curl"))')"
python3 scripts/desktop_control_fixture.py applications "{\"id\":\"$vpn_curl_app\",\"decision\":\"trusted\"}" > /dev/null
if curl --noproxy '*' -fsS --output /dev/null --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace; then echo "Protected connection escaped VPN" >&2; exit 1; fi
python3 scripts/desktop_control_fixture.py applications "{\"id\":\"$vpn_curl_app\",\"decision\":\"addresses\"}" > /dev/null
python3 scripts/desktop_control_fixture.py rules '{"target":"1.1.1.1","action":"approve","revision":0}' > /dev/null || true
python3 scripts/desktop_control_fixture.py state > build/macos-state.json
python3 -c 'import json; assert "1.1.1.1" in json.load(open("build/macos-state.json"))["pending_protection"]'
if curl --noproxy '*' -fsS --output /dev/null --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace; then echo "Protected connection escaped VPN" >&2; exit 1; fi
python3 scripts/test-desktop-power.py
# Abrupt worker death must retain the firewall, including existing PF states.
sudo /usr/bin/pkill -KILL -x linevpn-agent
sleep 2
if curl --noproxy '*' -fsS --output /dev/null --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace; then echo "Protected connection escaped VPN" >&2; exit 1; fi
sudo launchctl bootout system/dev.linevpn.agent
vpn_dns_keys="$(printf 'list State:/Network/Service/dev.linevpn.*/DNS\n' | /usr/sbin/scutil)"
if [[ "$vpn_dns_keys" == *'subKey'* ]]; then echo 'Temporary DNS survived service stop' >&2; exit 1; fi
if curl --noproxy '*' -fsS --output /dev/null --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace; then echo "Protected connection escaped VPN" >&2; exit 1; fi
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.linevpn.agent.plist
sudo env GITHUB_ACTIONS=true python3 scripts/test-desktop-clean-install.py build/macos-tested.pkg
# The ordinary user must also reach the newly created session.
python3 - <<'PYGUI'
import os, pathlib, subprocess
report = pathlib.Path('build/macos-gui.txt').resolve()
report.unlink(missing_ok=True)
env = dict(os.environ, LINEVPN_SMOKE_TEST_REPORT=str(report))
subprocess.run(['/Applications/Сеть.app/Contents/MacOS/LineVPN', '--background'], env=env, check=True, timeout=45)
assert report.read_text().startswith('PASS:'), 'Packaged Electron did not load the client UI'
PYGUI
sudo /bin/bash build/macos-tested-setup.app/Contents/Resources/manage.sh uninstall
[[ ! -f /Library/LaunchDaemons/dev.linevpn.agent.plist ]]
[[ ! -e '/Library/Application Support/LineVPN/linevpn-agent' ]]
curl --noproxy '*' -fsS --output /dev/null --connect-timeout 4 --max-time 8 http://example.com
printf 'PASS: unified PKG uninstall/fresh install clears state, installed UI, DNS, protected failures, off/on, process termination, service stop and uninstall recovery\n' > build/macos-native.txt
