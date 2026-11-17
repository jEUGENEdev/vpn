#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?Android SDK required}"
python3 scripts/package_version.py --check-newer
# Check before the expensive Go/Gradle build. A runner's generated debug key
# cannot replace the APK already installed on the user's devices.
python3 scripts/verify_android_update.py
vpn_variant="${LINEVPN_ANDROID_VARIANT:-release}"
case "$vpn_variant" in debug) vpn_task=assembleDebug;; release) vpn_task=assembleRelease;; *) echo 'Use debug or release' >&2; exit 1;; esac
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.0.13004108"
mkdir -p apps/android/app/libs
python3 scripts/collect-licenses.py apps/android/app/src/main/assets/THIRD_PARTY_NOTICES.txt
go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20261011034528-197770444867
go install golang.org/x/mobile/cmd/gobind@v0.0.0-20261011034528-197770444867
# Matches Xray's Android build: anet accesses the pinned Go net zone cache.
gomobile bind -ldflags='-checklinkname=0 -s -w' -tags with_gvisor -target android/arm64,android/amd64 -androidapi 29 -o apps/android/app/libs/core.aar ./mobile
(cd apps/android && gradle --no-daemon "$vpn_task")
python3 scripts/verify_android_update.py "apps/android/app/build/outputs/apk/$vpn_variant/app-$vpn_variant.apk"
