#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?Android SDK required}"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.0.13004108"
mkdir -p apps/android/app/libs
python3 scripts/collect-licenses.py apps/android/app/src/main/assets/THIRD_PARTY_NOTICES.txt
go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20261011034528-197770444867
go install golang.org/x/mobile/cmd/gobind@v0.0.0-20261011034528-197770444867
# Matches Xray's Android build: anet accesses the pinned Go net zone cache.
gomobile bind -ldflags='-checklinkname=0 -s -w' -tags with_gvisor -target android/arm64,android/amd64 -androidapi 29 -o apps/android/app/libs/core.aar ./mobile
cd apps/android
if [[ -n "${ANDROID_KEYSTORE:-}" ]]; then
  gradle --no-daemon assembleRelease
  vpn_apk=app/build/outputs/apk/release/app-release.apk
else
  gradle --no-daemon assembleDebug
  vpn_apk=app/build/outputs/apk/debug/app-debug.apk
fi
# Ephemeral debug keys are acceptable only for local/PR tests, never updates.
if [[ "${LINEVPN_ANDROID_TEST_ONLY:-0}" != 1 ]]; then
  python3 ../../scripts/verify-android-update.py "$vpn_apk"
fi
