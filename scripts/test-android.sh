#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/native-probe
printf 'linevpn-native-ok\n' > build/native-probe/probe
vpn_logcat_pid=''
vpn_probe_pid=''
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  timeout 10s adb shell dumpsys connectivity > build/android-connectivity.txt 2>&1
  timeout 10s adb shell 'ip -s addr; ip rule; ip route show table all' > build/android-network.txt 2>&1
  if [[ -n "$vpn_logcat_pid" ]]; then
    kill "$vpn_logcat_pid" 2>/dev/null
    wait "$vpn_logcat_pid" 2>/dev/null
  fi
  if [[ -n "$vpn_probe_pid" ]]; then
    kill "$vpn_probe_pid" 2>/dev/null
    wait "$vpn_probe_pid" 2>/dev/null
  fi
  exit "$status"
}
trap cleanup EXIT
# Stream from the start: a final `logcat -t 600` loses the actual failure
# while instrumentation is shutting down a busy cold-boot emulator.
adb logcat -c
adb logcat -v threadtime > build/android-logcat.txt 2>&1 &
vpn_logcat_pid=$!
# Use one physical uplink for strict first-request assertions. The emulator's
# background Wi-Fi/cellular handover can reset an in-flight HTTP connection;
# that is independent of replacing the VPN interface under test. The fixture
# below still waits for an actual successful host connection before starting.
adb shell svc data disable
adb shell svc wifi enable
python3 -u -m http.server 8765 --bind 0.0.0.0 --directory build/native-probe > build/android-probe-server.txt 2>&1 &
vpn_probe_pid=$!
# Fail as a fixture error if the host server never became ready.
curl --noproxy '*' --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 --max-time 2 \
  http://127.0.0.1:8765/probe > build/native-probe/host-response
cmp build/native-probe/probe build/native-probe/host-response
kill -0 "$vpn_probe_pid"
adb install -r apps/android/app/build/outputs/apk/debug/app-debug.apk
adb install -r apps/android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
vpn_smoke_runs="${ANDROID_SMOKE_RUNS:-3}"
[[ "$vpn_smoke_runs" =~ ^[1-9][0-9]*$ ]] || { echo 'ANDROID_SMOKE_RUNS must be a positive integer' >&2; exit 1; }
for ((vpn_run=1; vpn_run<=vpn_smoke_runs; vpn_run++)); do
  echo "Android native scenario $vpn_run/$vpn_smoke_runs (fresh app state)"
  # Every run must pass. Never retry a failed scenario or retain its approvals.
  adb shell pm clear dev.linevpn.app
  adb shell pm grant dev.linevpn.app android.permission.POST_NOTIFICATIONS
  adb shell appops set dev.linevpn.app ACTIVATE_VPN allow
  # Stop the unrelated Pixel launcher on this disposable emulator; cold-boot ANRs
  # must not cover the Activity under test. The test asserts its own window focus.
  adb shell am force-stop com.google.android.apps.nexuslauncher
  adb shell am instrument -w dev.linevpn.app.test/androidx.test.runner.AndroidJUnitRunner | tee "build/android-instrumentation-$vpn_run.txt"
  grep -q '^OK (1 test)' "build/android-instrumentation-$vpn_run.txt"
  kill -0 "$vpn_probe_pid"
  # Check fixture health outside Android after each scenario. A fixture outage
  # must not invalidate the connectivity assertions; do not retry this control probe.
  curl --noproxy '*' --fail --silent --show-error --max-time 2 \
    http://127.0.0.1:8765/probe > build/native-probe/host-response
  cmp build/native-probe/probe build/native-probe/host-response
  adb exec-out run-as dev.linevpn.app cat files/native-preview.png > build/android-native.png
done

# Reinstall over populated application data; never clear it in this scenario.
adb shell am force-stop dev.linevpn.app
for vpn_file in profile.json applications.json; do
  adb exec-out run-as dev.linevpn.app cat "files/core/$vpn_file" > "build/android-before-$vpn_file"
  test -s "build/android-before-$vpn_file"
done
for vpn_reinstall in 1 2; do
  adb install -r apps/android/app/build/outputs/apk/debug/app-debug.apk
  for vpn_file in profile.json applications.json; do
    adb exec-out run-as dev.linevpn.app cat "files/core/$vpn_file" > "build/android-after-$vpn_file"
    cmp "build/android-before-$vpn_file" "build/android-after-$vpn_file"
  done
done
printf 'PASS: repeated APK installation preserves profile and application decisions\n' > build/android-update.txt

# Package removal must leave ordinary networking without recovery commands.
adb uninstall dev.linevpn.app
adb shell ping -c 1 -W 5 10.0.2.2

# Explicit uninstall must also allow a fresh installation without old state.
adb install apps/android/app/build/outputs/apk/debug/app-debug.apk
# exec-out does not propagate the remote process exit code. Use shell v2 so a
# missing file is distinguished from a successful cat of an old profile.
adb shell run-as dev.linevpn.app test ! -e files/core/profile.json
adb shell pm grant dev.linevpn.app android.permission.POST_NOTIFICATIONS
adb shell appops set dev.linevpn.app ACTIVATE_VPN allow
adb shell am instrument -w dev.linevpn.app.test/androidx.test.runner.AndroidJUnitRunner | tee build/android-clean-install.txt
grep -q '^OK (1 test)' build/android-clean-install.txt
adb uninstall dev.linevpn.app
adb shell ping -c 1 -W 5 10.0.2.2
