#!/bin/bash
set -euo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Нужны права администратора.' >&2; exit 1; }
vpn_action="${1:-}"
case "$vpn_action" in install|uninstall) ;; *) echo 'Use install or uninstall.' >&2; exit 2;; esac
vpn_resources="$(cd "$(dirname "$0")" && pwd)"
vpn_arch="$(/usr/bin/uname -m)"
if [[ "$(/usr/sbin/sysctl -in hw.optional.arm64 2>/dev/null || true)" == 1 ]]; then vpn_arch=arm64; fi
case "$vpn_arch" in arm64) ;; x86_64) vpn_arch=x64;; *) echo 'Этот Mac не поддерживается.' >&2; exit 1;; esac
vpn_package="$vpn_resources/payload-$vpn_arch.pkg"
vpn_agent="$vpn_resources/recovery-$vpn_arch"
[[ -f "$vpn_package" && -x "$vpn_agent" ]] || { echo 'Установщик повреждён. Скачайте полный DMG заново.' >&2; exit 1; }

vpn_lock=/var/run/dev.linevpn.installer.lock
if ! /bin/mkdir -m 700 "$vpn_lock" 2>/dev/null; then
  echo 'Другая операция установки уже выполняется. Дождитесь её завершения; после аварийного завершения перезагрузите Mac.' >&2
  exit 1
fi
trap '/bin/rm -f "$vpn_lock/operator.uid"; /bin/rmdir "$vpn_lock"' EXIT
vpn_log="$(/usr/bin/mktemp /var/log/linevpn-installer.XXXXXX)"
if [[ "$vpn_action" == install ]]; then
  # Capture the account that opened the DMG before OS elevation. The package
  # reads the handoff only from this installer-owned directory.
  vpn_operator="${2:-}"
  if [[ "$vpn_operator" =~ ^[1-9][0-9]{2,9}$ ]] && (( vpn_operator >= 500 && vpn_operator < 4294967295 )); then
    (umask 077; printf '%s\n' "$vpn_operator" > "$vpn_lock/operator.uid")
  fi
  if ! /usr/sbin/installer -pkg "$vpn_package" -target / > "$vpn_log" 2>&1; then
    /usr/bin/tail -n 20 "$vpn_log" >&2
    echo "Журнал установки: $vpn_log (подробности также в /var/log/install.log)." >&2
    exit 1
  fi
else
  if ! /bin/bash "$vpn_resources/uninstall.sh" "$vpn_agent" > "$vpn_log" 2>&1; then
    /usr/bin/tail -n 20 "$vpn_log" >&2
    echo "Журнал удаления: $vpn_log" >&2
    exit 1
  fi
  # Keep raw command diagnostics in the log; show retained identities in the UI.
  /usr/bin/awk '/^Предупреждение:/' "$vpn_log"
fi
