#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin ]] || { echo 'Build macOS installers on a Mac.' >&2; exit 1; }
vpn_version="$(python3 scripts/package_version.py --check-newer)"
vpn_arch="${1:-arm64}"
case "$vpn_arch" in arm64) vpn_electron_arch=arm64;; amd64) vpn_electron_arch=x64;; *) echo 'Use arm64 or amd64' >&2; exit 1;; esac
export LINEVPN_MACOS_SIGNING="${LINEVPN_MACOS_SIGNING:-preview}"
vpn_sign_args=(--force --sign -)
vpn_pkg_command=(pkgbuild)
vpn_builder_args=(-c.mac.identity=- -c.mac.entitlements=../../packaging/macos/entitlements.preview.plist -c.mac.entitlementsInherit=../../packaging/macos/entitlements.preview.plist)
case "$LINEVPN_MACOS_SIGNING" in
  preview)
    # PR packages still need a valid ad-hoc signature after Electron is renamed.
    # This path never imports a certificate or uses a signing secret.
    unset CSC_LINK CSC_KEY_PASSWORD CSC_INSTALLER_LINK CSC_INSTALLER_KEY_PASSWORD CSC_NAME CSC_KEYCHAIN
    export CSC_IDENTITY_AUTO_DISCOVERY=false CSC_FOR_PULL_REQUEST=true
    ;;
  release)
    : "${LINEVPN_MACOS_APP_IDENTITY:?Developer ID Application identity is required}"
    : "${LINEVPN_MACOS_INSTALLER_IDENTITY:?Developer ID Installer identity is required}"
    : "${LINEVPN_MACOS_NOTARY_PROFILE:?notarytool keychain profile is required}"
    export CSC_IDENTITY_AUTO_DISCOVERY=true
    vpn_sign_args=(--force --sign "$LINEVPN_MACOS_APP_IDENTITY" --options runtime --timestamp)
    vpn_pkg_command+=(--sign "$LINEVPN_MACOS_INSTALLER_IDENTITY" --timestamp)
    # electron-builder selects the certificate type itself and rejects its prefix.
    vpn_builder_identity="${LINEVPN_MACOS_APP_IDENTITY#Developer ID Application: }"
    vpn_builder_args=("-c.mac.identity=$vpn_builder_identity" -c.mac.type=distribution -c.forceCodeSigning=true -c.mac.entitlements=../../packaging/macos/entitlements.release.plist -c.mac.entitlementsInherit=../../packaging/macos/entitlements.release.plist)
    ;;
  *) echo 'LINEVPN_MACOS_SIGNING must be preview or release' >&2; exit 1;;
esac
# Eliminate stale architecture/signature artifacts before preparing this payload.
rm -rf build/macos-root build/macos-scripts build/macos-image apps/desktop/assets apps/desktop/dist
mkdir -p build/macos-root/Library/LaunchDaemons 'build/macos-root/Library/Application Support/LineVPN' build/macos-scripts apps/desktop/assets
python3 scripts/collect-licenses.py apps/desktop/assets/THIRD_PARTY_NOTICES.txt
GOOS=darwin GOARCH="$vpn_arch" CGO_ENABLED=0 go build -tags with_gvisor -trimpath -ldflags='-s -w' -o 'build/macos-root/Library/Application Support/LineVPN/linevpn-agent' ./cmd/linevpn-agent
cp packaging/macos/dev.linevpn.agent.plist build/macos-root/Library/LaunchDaemons/
cp packaging/macos/preinstall packaging/macos/postinstall packaging/macos/stop-service.sh build/macos-scripts/
printf '%s\n' "$vpn_version" > build/macos-scripts/version
cp packaging/macos/service-wrapper.sh packaging/macos/uninstall.sh packaging/macos/stop-service.sh 'build/macos-root/Library/Application Support/LineVPN/'
cp packaging/macos/Uninstall-LineVPN.command apps/desktop/assets/
chmod 755 apps/desktop/assets/Uninstall-LineVPN.command
chmod 755 build/macos-scripts/preinstall build/macos-scripts/postinstall build/macos-scripts/stop-service.sh 'build/macos-root/Library/Application Support/LineVPN/'*
codesign "${vpn_sign_args[@]}" 'build/macos-root/Library/Application Support/LineVPN/linevpn-agent'
codesign --verify --strict 'build/macos-root/Library/Application Support/LineVPN/linevpn-agent'
# Sign/notarize the app first. The full PKG is kept outside its payload so that
# installing the service cannot leave an older UI (or recursively embed itself).
(
  cd apps/desktop
  npm ci
  npx electron-builder --mac --dir --"$vpn_electron_arch" --publish never "${vpn_builder_args[@]}"
)
vpn_app_dir=apps/desktop/dist/mac
[[ "$vpn_electron_arch" != arm64 ]] || vpn_app_dir=apps/desktop/dist/mac-arm64
mkdir -p build/macos-root/Applications build/macos-image
# executableName preserves the executable and builder output name for upgrades;
# install the bundle under the user-facing product name.
ditto "$vpn_app_dir/LineVPN.app" build/macos-root/Applications/Сеть.app
pkgbuild --analyze --root build/macos-root build/macos-components.plist
python3 - <<'PY'
import pathlib, plistlib
path = pathlib.Path('build/macos-components.plist')
components = plistlib.loads(path.read_bytes())
for component in components:
    component['BundleIsRelocatable'] = False
    component['BundleIsVersionChecked'] = True
    component['BundleHasStrictIdentifier'] = True
    component['BundleOverwriteAction'] = 'upgrade'
path.write_bytes(plistlib.dumps(components))
PY
mkdir -p build/macos-payloads
vpn_pkg="build/macos-payloads/payload-$vpn_electron_arch.pkg"
# Keep the array nonempty: macOS /bin/bash 3.2 treats an empty array as unset
# under nounset, even when it was explicitly initialized.
"${vpn_pkg_command[@]}" --root build/macos-root --scripts build/macos-scripts --component-plist build/macos-components.plist --identifier dev.linevpn.service --version "$vpn_version" --install-location / "$vpn_pkg"
if [[ "$LINEVPN_MACOS_SIGNING" == release ]]; then
  pkgutil --check-signature "$vpn_pkg"
  xcrun notarytool submit "$vpn_pkg" --keychain-profile "$LINEVPN_MACOS_NOTARY_PROFILE" --wait
  xcrun stapler staple "$vpn_pkg"
  xcrun stapler validate "$vpn_pkg"
fi
cp 'build/macos-root/Library/Application Support/LineVPN/linevpn-agent' "build/macos-payloads/recovery-$vpn_electron_arch"
