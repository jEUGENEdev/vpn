#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?Android SDK required}"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.0.13004108"
go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20261011034528-197770444867
go install golang.org/x/mobile/cmd/gobind@v0.0.0-20261011034528-197770444867
gomobile bind -tags with_gvisor -target android/arm64,android/amd64 -androidapi 29 -o apps/android/app/libs/core.aar ./mobile
cd apps/android
if [[ -n "${ANDROID_KEYSTORE:-}" ]]; then gradle --no-daemon assembleRelease; else gradle --no-daemon assembleDebug; fi
