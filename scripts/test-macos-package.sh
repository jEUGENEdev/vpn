#!/usr/bin/env bash
# Validate the final download, including the service actually shipped in it.
set -euo pipefail
cd "$(dirname "$0")/.."
vpn_dmg="${1:?DMG path required}"
vpn_arch="${2:?arm64 or x64 required}"
vpn_signing="${3:-preview}"
case "$vpn_arch" in arm64) vpn_macho_arch=arm64;; x64) vpn_macho_arch=x86_64;; *) exit 1;; esac
mkdir -p build
vpn_mount="$(mktemp -d "${TMPDIR:-/tmp}/linevpn-image.XXXXXX")"
cleanup() { hdiutil detach "$vpn_mount" -quiet || true; rmdir "$vpn_mount" || true; }
trap cleanup EXIT
# A Git LFS pointer with a .dmg extension fails here too.
hdiutil verify "$vpn_dmg"
hdiutil attach "$vpn_dmg" -readonly -nobrowse -mountpoint "$vpn_mount"
rm -rf build/macos-expanded build/macos-smoke
pkgutil --expand-full "$vpn_mount/Установить-Сеть.pkg" build/macos-expanded
vpn_app=build/macos-expanded/Payload/Applications/Сеть.app
codesign --verify --deep --strict --verbose=2 "$vpn_app"
lipo "$vpn_app/Contents/MacOS/LineVPN" -verify_arch "$vpn_macho_arch"
python3 - <<'CHECK'
import pathlib, plistlib, sys, xml.etree.ElementTree as ET
sys.path.insert(0, 'scripts')
from package_version import product_version
package = ET.parse('build/macos-expanded/PackageInfo').getroot()
assert package.get('identifier') == 'dev.linevpn.service' and package.get('version') == product_version()
app = plistlib.loads(pathlib.Path('build/macos-expanded/Payload/Applications/Сеть.app/Contents/Info.plist').read_bytes())
assert app['CFBundleIdentifier'] == 'dev.linevpn.desktop'
CHECK
vpn_agent="build/macos-expanded/Payload/Library/Application Support/LineVPN/linevpn-agent"
codesign --verify --strict "$vpn_agent"
lipo "$vpn_agent" -verify_arch "$vpn_macho_arch"
if [[ "$vpn_signing" == release ]]; then
  pkgutil --check-signature "$vpn_mount/Установить-Сеть.pkg"
  xcrun stapler validate "$vpn_mount/Установить-Сеть.pkg"
  xcrun stapler validate "$vpn_app"
  spctl --assess --type execute --verbose=2 "$vpn_app"
  spctl --assess --type install --verbose=2 "$vpn_mount/Установить-Сеть.pkg"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$vpn_dmg"
fi
# Assert the downloaded PKG contains the actual upgrade hooks and one version.
cmp packaging/macos/preinstall build/macos-expanded/Scripts/preinstall
cmp packaging/macos/postinstall build/macos-expanded/Scripts/postinstall
vpn_version="$(python3 scripts/package_version.py)"
[[ "$(cat build/macos-expanded/Scripts/version)" == "$vpn_version" ]]
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$vpn_app/Contents/Info.plist")" == "$vpn_version" ]]
cp "$vpn_mount/Установить-Сеть.pkg" build/macos-tested.pkg
printf 'PASS: final DMG integrity, unified app/helper PKG, versions, upgrade hooks, signatures, architecture; mode=%s\n' "$vpn_signing" > build/macos-signing.txt
