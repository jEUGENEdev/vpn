#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/native-probe
printf 'linevpn-native-ok\n' > build/native-probe/probe
python3 -m http.server 8765 --bind 0.0.0.0 --directory build/native-probe > build/native-probe/server.log 2>&1 &
vpn_probe_pid=$!
trap 'kill "$vpn_probe_pid" 2>/dev/null || true' EXIT
adb install -r apps/android/app/build/outputs/apk/debug/app-debug.apk
adb install -r apps/android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell pm grant dev.linevpn.app android.permission.POST_NOTIFICATIONS
adb shell appops set dev.linevpn.app ACTIVATE_VPN allow
# Stop the unrelated Pixel launcher on this disposable emulator; cold-boot ANRs
# must not cover the Activity under test. The test asserts its own window focus.
adb shell am force-stop com.google.android.apps.nexuslauncher
adb shell am instrument -w dev.linevpn.app.test/androidx.test.runner.AndroidJUnitRunner | tee build/android-instrumentation.txt
if ! grep -q 'OK (1 test)' build/android-instrumentation.txt; then
  adb logcat -d -t 600 > build/android-logcat.txt
  exit 1
fi
adb exec-out run-as dev.linevpn.app cat files/native-preview.png > build/android-native.png
