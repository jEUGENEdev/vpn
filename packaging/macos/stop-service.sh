#!/bin/bash
# Shared by upgrade, removal and explicit recovery. Never changes PF/DNS/data.
set -euo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Run with administrator privileges.' >&2; exit 1; }
vpn_service=system/dev.linevpn.agent
vpn_plist=/Library/LaunchDaemons/dev.linevpn.agent.plist
vpn_gui='^/Applications/(LineVPN|Сеть)\.app/Contents/MacOS/LineVPN( |$)'
vpn_worker='^(/bin/(bash|sh) )?/Library/Application Support/LineVPN/(linevpn-agent|service-wrapper\.sh)( |$)'

wait_for_gui() {
  local vpn_wait
  for ((vpn_wait=0; vpn_wait<10; vpn_wait++)); do
    /usr/bin/pgrep -f "$vpn_gui" >/dev/null || return 0
    sleep 1
  done
  return 1
}
/usr/bin/pkill -TERM -f "$vpn_gui" 2>/dev/null || true
if ! wait_for_gui; then
  /usr/bin/pkill -KILL -f "$vpn_gui" 2>/dev/null || true
  wait_for_gui || { echo 'Не удалось закрыть «Сеть». Закройте приложение и повторите операцию.' >&2; exit 1; }
fi

service_stopped() {
  ! /bin/launchctl print "$vpn_service" >/dev/null 2>&1 &&
    ! /usr/bin/pgrep -f "$vpn_worker" >/dev/null
}
wait_for_service() {
  local vpn_wait
  for ((vpn_wait=0; vpn_wait<15; vpn_wait++)); do
    service_stopped && return 0
    sleep 1
  done
  return 1
}

/bin/launchctl bootout "$vpn_service" 2>/dev/null || true
if wait_for_service; then exit 0; fi
# A stale registration or orphan from an older supervisor must not make the
# installer permanently unusable. Scope signals to our exact installed paths.
/bin/launchctl kill SIGTERM "$vpn_service" 2>/dev/null || true
/usr/bin/pkill -TERM -f "$vpn_worker" 2>/dev/null || true
/bin/launchctl bootout system "$vpn_plist" 2>/dev/null || true
if wait_for_service; then exit 0; fi
/bin/launchctl kill SIGKILL "$vpn_service" 2>/dev/null || true
/usr/bin/pkill -KILL -f "$vpn_worker" 2>/dev/null || true
/bin/launchctl bootout "$vpn_service" 2>/dev/null || true
if wait_for_service; then exit 0; fi
echo 'Не удалось остановить службу «Сеть». Файлы, профиль и защита сети сохранены. Перезагрузите Mac и повторите операцию.' >&2
exit 1
