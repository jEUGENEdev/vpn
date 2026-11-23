#!/bin/bash
# Removes this client's service and UI. Account/profile data is preserved.
set -euo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
vpn_base='/Library/Application Support/LineVPN'
/bin/launchctl disable system/dev.linevpn.agent 2>/dev/null || true
/bin/launchctl bootout system/dev.linevpn.agent 2>/dev/null || true
if /bin/launchctl print system/dev.linevpn.agent >/dev/null 2>&1; then
  echo 'Cannot stop Сеть; keeping recovery files. Retry after stopping the service.' >&2
  exit 1
fi
# Cleanup MUST succeed before deleting the executable or recovery data.
"$vpn_base/linevpn-agent" -data /var/lib/linevpn -recover-network
if [[ -f /etc/pf.conf ]]; then
  /usr/bin/awk '$0 != "anchor \"linevpn\" out quick"' /etc/pf.conf > /etc/pf.conf.linevpn-uninstall
  /bin/cat /etc/pf.conf.linevpn-uninstall > /etc/pf.conf
  /bin/rm -f /etc/pf.conf.linevpn-uninstall
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
