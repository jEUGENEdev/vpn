#!/bin/bash
# Removes this client's service and UI. Account/profile data is preserved.
set -euo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
vpn_base='/Library/Application Support/LineVPN'
vpn_tools="$(cd "$(dirname "$0")" && pwd)"
# The unified installer supplies its own recovery binary. Standalone removal
# uses the installed one. Neither path executes an older installed uninstaller.
vpn_recovery="${1:-$vpn_base/linevpn-agent}"
[[ -x "$vpn_recovery" ]] || { echo 'Откройте свежий установщик «Сеть» и выберите «Удалить».' >&2; exit 1; }
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
/bin/rm -f /Library/LaunchDaemons/dev.linevpn.agent.plist
/bin/rm -rf "$vpn_base"
for vpn_bundle in /Applications/LineVPN.app /Applications/Сеть.app; do
  if [[ -d "$vpn_bundle" ]] && [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$vpn_bundle/Contents/Info.plist" 2>/dev/null || true)" == dev.linevpn.desktop ]]; then
    /bin/rm -rf "$vpn_bundle"
  fi
done
/usr/sbin/pkgutil --forget dev.linevpn.service >/dev/null 2>&1 || true
echo 'Приложение «Сеть» удалено. Прямое подключение восстановлено. Профиль сохранён в /var/lib/linevpn.'
