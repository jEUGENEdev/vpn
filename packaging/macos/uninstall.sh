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
# Validate identities before stopping the service or touching network/state.
source "$vpn_tools/service-account.sh"
vpn_check_service_account
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
# macOS can deny directory deletion even to root. The validated, non-login
# identity is not the app or its credentials: a known permission denial must
# not strand those files. Other directory failures remain fatal and visible.
vpn_account_warning=''
vpn_delete_service_record() {
  local vpn_output vpn_status vpn_records
  if vpn_output="$(/usr/bin/dscl . -delete "$1" 2>&1)"; then
    vpn_records="$(/usr/bin/dscl . -list "${1%/*}")"
    if printf '%s\n' "$vpn_records" | /usr/bin/grep -Eq '^_linevpn([[:space:]]|$)'; then
      echo "Служебная запись $1 осталась после удаления; операция остановлена." >&2
      return 1
    fi
    return 0
  else
    vpn_status=$?
  fi
  printf '%s\n' "$vpn_output" >&2
  if [[ "$vpn_status" -eq 40 && "$vpn_output" == *'-14120 (eDSPermissionError)'* ]]; then
    vpn_account_warning="Предупреждение: macOS запретила удалить $2 _linevpn (DS Error -14120). Приложение, служба и локальные данные удалены; служебная запись с запрещённым входом осталась. Она не мешает новой установке."
    return 0
  fi
  echo "Не удалось удалить служебную запись $1; файлы сохранены для повторной попытки." >&2
  return "$vpn_status"
}
if [[ -n "$vpn_uid" ]]; then
  vpn_delete_service_record /Users/_linevpn 'учётную запись и группу'
fi
# Keep the primary group with a retained user, but remove an orphaned group on
# retries even when the user was already deleted in a previous attempt.
if [[ -n "$vpn_group" && -z "$vpn_account_warning" ]]; then
  vpn_delete_service_record /Groups/_linevpn 'группу'
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
if [[ -n "$vpn_account_warning" ]]; then printf '%s\n' "$vpn_account_warning"; fi
