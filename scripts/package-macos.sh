#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin ]] || { echo 'Build macOS installers on a Mac.' >&2; exit 1; }
vpn_version="$(python3 scripts/package_version.py --check-newer)"
export LINEVPN_MACOS_SIGNING="${LINEVPN_MACOS_SIGNING:-preview}"
# One download supports both architectures; users never choose service tools.
rm -rf build/macos-payloads build/macos-setup-image
bash scripts/package-macos-payload.sh arm64
bash scripts/package-macos-payload.sh amd64
vpn_setup='build/macos-setup-image/Установщик Сеть.app'
python3 scripts/prepare-macos-installer.py build/macos-payloads "$vpn_setup"
for vpn_arch in arm64 amd64; do
  GOOS=darwin GOARCH="$vpn_arch" CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "build/macos-setup-$vpn_arch" ./cmd/linevpn-setup
done
lipo -create build/macos-setup-arm64 build/macos-setup-amd64 -output "$vpn_setup/Contents/MacOS/SetSetup"
vpn_sign_args=(--force --sign -)
if [[ "$LINEVPN_MACOS_SIGNING" == release ]]; then
  vpn_sign_args=(--force --sign "$LINEVPN_MACOS_APP_IDENTITY" --options runtime --timestamp)
fi
codesign "${vpn_sign_args[@]}" "$vpn_setup"
codesign --verify --deep --strict "$vpn_setup"
if [[ "$LINEVPN_MACOS_SIGNING" == release ]]; then
  ditto -c -k --keepParent "$vpn_setup" build/macos-setup-notary.zip
  xcrun notarytool submit build/macos-setup-notary.zip --keychain-profile "$LINEVPN_MACOS_NOTARY_PROFILE" --wait
  xcrun stapler staple "$vpn_setup"
fi
vpn_dmg="apps/desktop/dist/Сеть-$vpn_version-macos-universal.dmg"
hdiutil create -volname "Сеть $vpn_version" -srcfolder build/macos-setup-image -format UDZO -ov "$vpn_dmg"
if [[ "$LINEVPN_MACOS_SIGNING" == release ]]; then
  codesign "${vpn_sign_args[@]}" "$vpn_dmg"
  xcrun notarytool submit "$vpn_dmg" --keychain-profile "$LINEVPN_MACOS_NOTARY_PROFILE" --wait
  xcrun stapler staple "$vpn_dmg"
  xcrun stapler validate "$vpn_dmg"
fi
scripts/test-macos-package.sh "$vpn_dmg" "$LINEVPN_MACOS_SIGNING"
