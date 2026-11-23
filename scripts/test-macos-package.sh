#!/usr/bin/env bash
# Validate the download on macOS, including both internal app/service packages.
set -euo pipefail
cd "$(dirname "$0")/.."
vpn_dmg="${1:?DMG path required}"
vpn_signing="${2:-preview}"
vpn_mount="$(mktemp -d "${TMPDIR:-/tmp}/linevpn-image.XXXXXX")"
cleanup() { hdiutil detach "$vpn_mount" -quiet || true; rmdir "$vpn_mount" || true; }
trap cleanup EXIT
hdiutil verify "$vpn_dmg"
hdiutil attach "$vpn_dmg" -readonly -nobrowse -mountpoint "$vpn_mount"
vpn_setup="$vpn_mount/Установщик Сеть.app"
vpn_resources="$vpn_setup/Contents/Resources"
[[ "$(find "$vpn_mount" -maxdepth 1 -name '*.app' | wc -l | tr -d ' ')" == 1 ]]
codesign --verify --deep --strict "$vpn_setup"
lipo "$vpn_setup/Contents/MacOS/SetSetup" -verify_arch arm64 x86_64
osacompile -o build/macos-installer-check.scpt "$vpn_resources/installer.applescript"
for vpn_file in installer.applescript manage.sh uninstall.sh stop-service.sh; do
  cmp "packaging/macos/$vpn_file" "$vpn_resources/$vpn_file"
done
vpn_version="$(python3 scripts/package_version.py)"
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$vpn_setup/Contents/Info.plist")" == "$vpn_version" ]]
for vpn_arch in arm64 x64; do
  vpn_macho_arch="$vpn_arch"
  [[ "$vpn_arch" != x64 ]] || vpn_macho_arch=x86_64
  vpn_expanded="build/macos-expanded-$vpn_arch"
  rm -rf "$vpn_expanded"
  vpn_pkg="$vpn_resources/payload-$vpn_arch.pkg"
  pkgutil --expand-full "$vpn_pkg" "$vpn_expanded"
  vpn_app="$vpn_expanded/Payload/Applications/Сеть.app"
  codesign --verify --deep --strict "$vpn_app"
  lipo "$vpn_app/Contents/MacOS/LineVPN" -verify_arch "$vpn_macho_arch"
  vpn_agent="$vpn_expanded/Payload/Library/Application Support/LineVPN/linevpn-agent"
  codesign --verify --strict "$vpn_agent"
  lipo "$vpn_agent" -verify_arch "$vpn_macho_arch"
  cmp "$vpn_agent" "$vpn_resources/recovery-$vpn_arch"
  python3 - "$vpn_expanded" "$vpn_version" <<'PY'
import pathlib, sys, xml.etree.ElementTree as ET
root = pathlib.Path(sys.argv[1])
package = ET.parse(root / 'PackageInfo').getroot()
assert package.get('identifier') == 'dev.linevpn.service' and package.get('version') == sys.argv[2]
PY
  for vpn_file in preinstall postinstall stop-service.sh; do
    cmp "packaging/macos/$vpn_file" "$vpn_expanded/Scripts/$vpn_file"
  done
  for vpn_file in stop-service.sh uninstall.sh recover-network.sh service-wrapper.sh; do
    cmp "packaging/macos/$vpn_file" "$vpn_expanded/Payload/Library/Application Support/LineVPN/$vpn_file"
  done
  [[ "$(cat "$vpn_expanded/Scripts/version")" == "$vpn_version" ]]
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$vpn_app/Contents/Info.plist")" == dev.linevpn.desktop ]]
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$vpn_app/Contents/Info.plist")" == "$vpn_version" ]]
  if [[ "$vpn_signing" == release ]]; then
    pkgutil --check-signature "$vpn_pkg"
    xcrun stapler validate "$vpn_pkg"
    spctl --assess --type execute "$vpn_app"
    spctl --assess --type install "$vpn_pkg"
  fi
done
if [[ "$vpn_signing" == release ]]; then
  xcrun stapler validate "$vpn_setup"
  spctl --assess --type execute "$vpn_setup"
  spctl --assess --type open --context context:primary-signature "$vpn_dmg"
fi
rm -rf build/macos-tested-setup.app
ditto "$vpn_setup" build/macos-tested-setup.app
vpn_host_arch=x64
[[ "$(uname -m)" != arm64 ]] || vpn_host_arch=arm64
cp "$vpn_resources/payload-$vpn_host_arch.pkg" build/macos-tested.pkg
printf 'PASS: universal installer, both payloads, upgrade/recovery scripts, AppleScript compilation, versions, signatures; mode=%s\n' "$vpn_signing" > build/macos-signing.txt
