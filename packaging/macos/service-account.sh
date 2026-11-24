#!/bin/bash
# Sourced by install/removal. Read the local directory, not the id/NSS cache.
vpn_check_service_account() {
  vpn_users="$(/usr/bin/dscl . -list /Users UniqueID)"
  vpn_groups="$(/usr/bin/dscl . -list /Groups PrimaryGroupID)"
  vpn_uid=''
  vpn_group=''
  if printf '%s\n' "$vpn_users" | /usr/bin/awk '$1 == "_linevpn" {found=1} END {exit !found}'; then
    vpn_uid="$(/usr/bin/dscl . -read /Users/_linevpn UniqueID | /usr/bin/awk '{print $2}')"
    vpn_gid="$(/usr/bin/dscl . -read /Users/_linevpn PrimaryGroupID | /usr/bin/awk '{print $2}')"
    vpn_home="$(/usr/bin/dscl . -read /Users/_linevpn NFSHomeDirectory | /usr/bin/awk '{print $2}')"
    vpn_shell="$(/usr/bin/dscl . -read /Users/_linevpn UserShell | /usr/bin/awk '{print $2}')"
    [[ "$vpn_uid" =~ ^[23][0-9][0-9]$ && "$vpn_uid" == "$vpn_gid" && "$vpn_home" == /var/empty && "$vpn_shell" == /usr/bin/false ]] || {
      echo 'Неожиданная системная учётная запись _linevpn; операция остановлена.' >&2; return 1;
    }
  fi
  if printf '%s\n' "$vpn_groups" | /usr/bin/awk '$1 == "_linevpn" {found=1} END {exit !found}'; then
    vpn_group="$(/usr/bin/dscl . -read /Groups/_linevpn PrimaryGroupID | /usr/bin/awk '{print $2}')"
    [[ "$vpn_group" =~ ^[23][0-9][0-9]$ && ( -z "$vpn_uid" || "$vpn_group" == "$vpn_uid" ) ]] || {
      echo 'Неожиданная группа _linevpn; операция остановлена.' >&2; return 1;
    }
  fi
  # An orphaned group is possible after interrupted removal. Only reuse/remove
  # it if its ID is not assigned to another user or group.
  vpn_service_id="${vpn_uid:-$vpn_group}"
  vpn_primary_groups="$(/usr/bin/dscl . -list /Users PrimaryGroupID)"
  if [[ -n "$vpn_service_id" ]]; then
    if printf '%s\n' "$vpn_users" "$vpn_groups" "$vpn_primary_groups" |
        /usr/bin/awk -v id="$vpn_service_id" '$1 != "_linevpn" && $2 == id {found=1} END {exit !found}'; then
      echo 'UID/GID _linevpn используется другой учётной записью; операция остановлена.' >&2
      return 1
    fi
  fi
}
