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
codesign --verify --deep --strict --verbose=2 "$vpn_mount/LineVPN.app"
lipo "$vpn_mount/LineVPN.app/Contents/MacOS/LineVPN" -verify_arch "$vpn_macho_arch"
rm -rf build/macos-expanded build/macos-smoke
pkgutil --expand-full "$vpn_mount/Install-LineVPN-Service.pkg" build/macos-expanded
cmp packaging/macos/preinstall build/macos-expanded/Scripts/preinstall
cmp packaging/macos/postinstall build/macos-expanded/Scripts/postinstall
python3 - "$vpn_mount" <<'PY'
import json, pathlib, plistlib, sys, xml.etree.ElementTree as ET
version = json.loads(pathlib.Path('apps/desktop/package.json').read_text())['version']
package = ET.parse('build/macos-expanded/PackageInfo').getroot()
assert package.get('identifier') == 'dev.linevpn.service' and package.get('version') == version
app = plistlib.loads((pathlib.Path(sys.argv[1]) / 'LineVPN.app/Contents/Info.plist').read_bytes())
assert app['CFBundleIdentifier'] == 'dev.linevpn.desktop' and app['CFBundleShortVersionString'] == version
PY
vpn_agent="build/macos-expanded/Payload/Library/Application Support/LineVPN/linevpn-agent"
codesign --verify --strict "$vpn_agent"
lipo "$vpn_agent" -verify_arch "$vpn_macho_arch"
if [[ "$vpn_signing" == release ]]; then
  pkgutil --check-signature "$vpn_mount/Install-LineVPN-Service.pkg"
  xcrun stapler validate "$vpn_mount/Install-LineVPN-Service.pkg"
  xcrun stapler validate "$vpn_mount/LineVPN.app"
  spctl --assess --type execute --verbose=2 "$vpn_mount/LineVPN.app"
  spctl --assess --type install --verbose=2 "$vpn_mount/Install-LineVPN-Service.pkg"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$vpn_dmg"
fi
mkdir -p build/macos-smoke
ditto "$vpn_mount/LineVPN.app" build/macos-smoke/LineVPN.app
cp "$vpn_mount/Install-LineVPN-Service.pkg" build/macos-tested-service.pkg
printf 'PASS: final DMG integrity, app/helper signatures, architecture, PKG payload; mode=%s\n' "$vpn_signing" > build/macos-signing.txt
