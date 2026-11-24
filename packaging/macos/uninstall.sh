#!/bin/bash
# Explicit removal clears local credentials after successful network teardown.
set -euo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
vpn_base='/Library/Application Support/LineVPN'
vpn_tools="$(cd "$(dirname "$0")" && pwd)"
# The unified installer supplies its own recovery binary. Standalone removal
# uses the installed one. Neither path executes an older installed uninstaller.
vpn_recovery="${1:-$vpn_base/linevpn-agent}"
[[ -x "$vpn_recovery" ]] || { echo 'Откройте свежий установщик «Сеть» и выберите «Удалить».' >&2; exit 1; }
# Never report successful removal while a foreign/unknown bundle remains at
# the installation path. Validate before stopping anything or deleting state.
for vpn_bundle in /Applications/LineVPN.app /Applications/Сеть.app; do
  if [[ -e "$vpn_bundle" || -L "$vpn_bundle" ]]; then
    [[ ! -L "$vpn_bundle" && "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$vpn_bundle/Contents/Info.plist" 2>/dev/null || true)" == dev.linevpn.desktop ]] || { echo "Не удалось подтвердить принадлежность приложения: $vpn_bundle. Файлы не удалены." >&2; exit 1; }
  fi
done
/bin/bash "$vpn_tools/stop-service.sh"
# Cleanup MUST succeed before deleting the executable or recovery data.
"$vpn_recovery" -data /var/lib/linevpn -recover-network
/bin/launchctl disable system/dev.linevpn.agent 2>/dev/null || true
if [[ -f /etc/pf.conf ]]; then
  vpn_pf="$(/usr/bin/mktemp /etc/pf.conf.linevpn.XXXXXX)"
  trap '/bin/rm -f "$vpn_pf"' EXIT
  /usr/bin/awk '!/^[[:space:]]*anchor "linevpn"([[:space:]]+out[[:space:]]+quick)?[[:space:]]*$/' /etc/pf.conf > "$vpn_pf"
  /sbin/pfctl -nf "$vpn_pf"
  /bin/cat "$vpn_pf" > /etc/pf.conf
fi
# Delete only the dedicated account created by this installer. Unexpected
# ownership is an error, never permission to remove another system identity.
if /usr/bin/id _linevpn >/dev/null 2>&1; then
  vpn_uid="$(/usr/bin/dscl . -read /Users/_linevpn UniqueID | /usr/bin/awk '{print $2}')"
  vpn_gid="$(/usr/bin/dscl . -read /Users/_linevpn PrimaryGroupID | /usr/bin/awk '{print $2}')"
  vpn_home="$(/usr/bin/dscl . -read /Users/_linevpn NFSHomeDirectory | /usr/bin/awk '{print $2}')"
  vpn_shell="$(/usr/bin/dscl . -read /Users/_linevpn UserShell | /usr/bin/awk '{print $2}')"
  [[ "$vpn_uid" =~ ^[23][0-9][0-9]$ && "$vpn_uid" == "$vpn_gid" && "$vpn_home" == /var/empty && "$vpn_shell" == /usr/bin/false ]] || { echo 'Неожиданная системная учётная запись _linevpn; удаление остановлено.' >&2; exit 1; }
  vpn_group="$(/usr/bin/dscl . -read /Groups/_linevpn PrimaryGroupID | /usr/bin/awk '{print $2}')"
  [[ "$vpn_group" == "$vpn_gid" ]] || { echo 'Неожиданная группа _linevpn.' >&2; exit 1; }
  /usr/bin/dscl . -delete /Users/_linevpn
  /usr/bin/dscl . -delete /Groups/_linevpn
fi
/bin/rm -f /Library/LaunchDaemons/dev.linevpn.agent.plist
/bin/rm -rf "$vpn_base"
for vpn_bundle in /Applications/LineVPN.app /Applications/Сеть.app; do
  if [[ -d "$vpn_bundle" ]] && [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$vpn_bundle/Contents/Info.plist" 2>/dev/null || true)" == dev.linevpn.desktop ]]; then
    /bin/rm -rf "$vpn_bundle"
  fi
done
/bin/rm -rf /var/lib/linevpn
/bin/rm -f /var/log/linevpn-error.log
# Only the app's private Electron directory; never the generic Electron folder.
for vpn_home in /Users/* /var/root; do
  [[ -d "$vpn_home" && ! -L "$vpn_home" && ! -L "$vpn_home/Library" ]] || continue
  for vpn_parent in 'Application Support' Caches Preferences 'Saved Application State'; do
    [[ ! -L "$vpn_home/Library/$vpn_parent" ]] || { echo "Нельзя очистить каталог-ссылку: $vpn_home/Library/$vpn_parent" >&2; exit 1; }
  done
  /bin/rm -rf "$vpn_home/Library/Application Support/LineVPN" \
    "$vpn_home/Library/Caches/dev.linevpn.desktop" \
    "$vpn_home/Library/Saved Application State/dev.linevpn.desktop.savedState"
  /bin/rm -f "$vpn_home/Library/Preferences/dev.linevpn.desktop.plist"
done
if /usr/sbin/pkgutil --pkg-info dev.linevpn.service >/dev/null 2>&1; then
  /usr/sbin/pkgutil --forget dev.linevpn.service >/dev/null
fi
echo 'Приложение «Сеть», служба и локальные данные удалены. Можно установить приложение заново.'
