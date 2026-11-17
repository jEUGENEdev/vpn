#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin ]] || { echo 'Build macOS installers on a Mac.' >&2; exit 1; }
vpn_arch="${1:-arm64}"
case "$vpn_arch" in arm64) vpn_electron_arch=arm64;; amd64) vpn_electron_arch=x64;; *) echo 'Use arm64 or amd64' >&2; exit 1;; esac
export LINEVPN_MACOS_SIGNING="${LINEVPN_MACOS_SIGNING:-preview}"
vpn_sign_args=(--force --sign -)
vpn_pkg_args=()
vpn_builder_args=(-c.mac.identity=- -c.mac.entitlements=../../packaging/macos/entitlements.preview.plist -c.mac.entitlementsInherit=../../packaging/macos/entitlements.preview.plist)
case "$LINEVPN_MACOS_SIGNING" in
  preview) export CSC_IDENTITY_AUTO_DISCOVERY=false;;
  release)
    : "${LINEVPN_MACOS_APP_IDENTITY:?Developer ID Application identity is required}"
    : "${LINEVPN_MACOS_INSTALLER_IDENTITY:?Developer ID Installer identity is required}"
    : "${LINEVPN_MACOS_NOTARY_PROFILE:?notarytool keychain profile is required}"
    export CSC_IDENTITY_AUTO_DISCOVERY=true
    vpn_sign_args=(--force --sign "$LINEVPN_MACOS_APP_IDENTITY" --options runtime --timestamp)
    vpn_pkg_args=(--sign "$LINEVPN_MACOS_INSTALLER_IDENTITY" --timestamp)
    # electron-builder selects the certificate type itself and rejects its prefix.
    vpn_builder_identity="${LINEVPN_MACOS_APP_IDENTITY#Developer ID Application: }"
    vpn_builder_args=("-c.mac.identity=$vpn_builder_identity" -c.mac.type=distribution -c.forceCodeSigning=true -c.mac.entitlements=../../packaging/macos/entitlements.release.plist -c.mac.entitlementsInherit=../../packaging/macos/entitlements.release.plist)
    ;;
  *) echo 'LINEVPN_MACOS_SIGNING must be preview or release' >&2; exit 1;;
esac
# Eliminate stale architecture/signature artifacts before preparing this payload.
rm -rf build/macos-root build/macos-scripts apps/desktop/assets apps/desktop/dist
mkdir -p build/macos-root/Library/LaunchDaemons 'build/macos-root/Library/Application Support/LineVPN' build/macos-scripts apps/desktop/assets
python3 scripts/collect-licenses.py apps/desktop/assets/THIRD_PARTY_NOTICES.txt
GOOS=darwin GOARCH="$vpn_arch" CGO_ENABLED=0 go build -tags with_gvisor -trimpath -ldflags='-s -w' -o 'build/macos-root/Library/Application Support/LineVPN/linevpn-agent' ./cmd/linevpn-agent
cp packaging/macos/dev.linevpn.agent.plist build/macos-root/Library/LaunchDaemons/
cp packaging/macos/postinstall build/macos-scripts/postinstall
cp packaging/macos/recover-network.sh 'build/macos-root/Library/Application Support/LineVPN/'
chmod 755 build/macos-scripts/postinstall 'build/macos-root/Library/Application Support/LineVPN/'*
codesign "${vpn_sign_args[@]}" 'build/macos-root/Library/Application Support/LineVPN/linevpn-agent'
codesign --verify --strict 'build/macos-root/Library/Application Support/LineVPN/linevpn-agent'
pkgbuild --root build/macos-root --scripts build/macos-scripts --identifier dev.linevpn.service --version 0.2.0 --install-location / "${vpn_pkg_args[@]}" apps/desktop/assets/Install-LineVPN-Service.pkg
if [[ "$LINEVPN_MACOS_SIGNING" == release ]]; then
  pkgutil --check-signature apps/desktop/assets/Install-LineVPN-Service.pkg
  xcrun notarytool submit apps/desktop/assets/Install-LineVPN-Service.pkg --keychain-profile "$LINEVPN_MACOS_NOTARY_PROFILE" --wait
  xcrun stapler staple apps/desktop/assets/Install-LineVPN-Service.pkg
  xcrun stapler validate apps/desktop/assets/Install-LineVPN-Service.pkg
fi
cat > apps/desktop/assets/Install-Service.command <<'COMMAND'
#!/bin/bash
open "$(dirname "$0")/Install-LineVPN-Service.pkg"
COMMAND
chmod 755 apps/desktop/assets/Install-Service.command
(
  cd apps/desktop
  npm ci
  npx electron-builder --mac dmg --"$vpn_electron_arch" --publish never "${vpn_builder_args[@]}"
)
vpn_dmg="apps/desktop/dist/LineVPN-0.2.0-macos-$vpn_electron_arch.dmg"
if [[ "$LINEVPN_MACOS_SIGNING" == release ]]; then
  codesign "${vpn_sign_args[@]}" "$vpn_dmg"
  xcrun notarytool submit "$vpn_dmg" --keychain-profile "$LINEVPN_MACOS_NOTARY_PROFILE" --wait
  xcrun stapler staple "$vpn_dmg"
  xcrun stapler validate "$vpn_dmg"
fi
scripts/test-macos-package.sh "$vpn_dmg" "$vpn_electron_arch" "$LINEVPN_MACOS_SIGNING"
