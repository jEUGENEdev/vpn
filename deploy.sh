#!/usr/bin/env bash
# Four inputs; compilation and Ansible run on the VPS.
set +x
set -euo pipefail
linevpn_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fail() { printf 'ERROR: %s\n' "$*" >&2; return 1; }

validate_inputs() {
  [[ "$linevpn_host" =~ ^[0-9a-fA-F:.]+$ && "$linevpn_host" == *[.:]* ]] || { fail 'host must be a public IPv4 or IPv6 address.'; return 1; }
  [[ "$linevpn_user" =~ ^[a-z_][a-z0-9_-]{0,31}\$?$ ]] || { fail 'Invalid SSH username.'; return 1; }
  [[ "$linevpn_port" =~ ^[0-9]{1,5}$ ]] && ((10#$linevpn_port >= 1 && 10#$linevpn_port <= 65535)) || { fail 'Invalid VPS_PORT.'; return 1; }
  [[ -n "$linevpn_password" && "$linevpn_password" != *$'\n'* && "$linevpn_password" != *$'\r'* ]] || { fail 'SSH password must be nonempty and on one line.'; return 1; }
  local count
  count=$(LC_ALL=C printf '%s' "$linevpn_admin" | wc -c | tr -d ' ')
  ((count >= 16 && count <= 72)) && [[ "$linevpn_admin" != *$'\n'* && "$linevpn_admin" != *$'\r'* && "$linevpn_admin" != [[:space:]]* && "$linevpn_admin" != *[[:space:]] ]] || { fail 'VPN admin password must be 16-72 UTF-8 bytes, without surrounding whitespace.'; return 1; }
}

ssh_run() {
  LINEVPN_SSH_PASSWORD="$linevpn_password" SSH_ASKPASS="$linevpn_tmp/askpass" \
    SSH_ASKPASS_REQUIRE=force DISPLAY=linevpn:0 \
    ssh -F /dev/null -T -p "$linevpn_port" -o StrictHostKeyChecking=accept-new \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 -o ConnectTimeout=20 \
      -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
      "$linevpn_user@$linevpn_host" "$@"
}

check_port() {
  local port=$1 pid timer result
  (exec 3<>"/dev/tcp/$linevpn_host/$port") 2>/dev/null & pid=$!
  (sleep 10; kill "$pid" 2>/dev/null || true) & timer=$!
  if wait "$pid"; then result=0; else result=1; fi
  kill "$timer" 2>/dev/null || true
  wait "$timer" 2>/dev/null || true
  return "$result"
}

decode64() {
  if printf '%s' "$1" | base64 --decode 2>/dev/null; then return; fi
  printf '%s' "$1" | base64 -D
}

cleanup() {
  local result=$?
  trap - EXIT
  if [[ -n ${linevpn_remote:-} ]]; then
    ssh_run "rm -rf -- '$linevpn_remote'" </dev/null >/dev/null 2>&1 || true
  fi
  [[ -z ${linevpn_tmp:-} ]] || rm -rf -- "$linevpn_tmp"
  unset linevpn_password linevpn_admin
  exit "$result"
}

main() {
  if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    printf '%s\n' 'Usage: bash deploy.sh' \
      'Enter host, username, password and vpn admin password when prompted.' \
      'Alternatively set VPS_HOST, VPS_USERNAME, VPS_PASSWORD, VPN_ADMIN_PASSWORD.' \
      'SSH port defaults to 22; optional VPS_PORT overrides it.' \
      'Run from the full repository. Go, Python and Ansible are installed on the VPS.'
    return
  fi
  [[ $# == 0 ]] || { fail 'Use interactive prompts or environment variables, not password arguments.'; return 1; }
  linevpn_host=${VPS_HOST:-}; linevpn_user=${VPS_USERNAME:-}
  linevpn_password=${VPS_PASSWORD:-}; linevpn_admin=${VPN_ADMIN_PASSWORD:-}
  linevpn_port=${VPS_PORT:-22}
  unset VPS_PASSWORD VPN_ADMIN_PASSWORD
  [[ -n "$linevpn_host" ]] || read -r -p 'host: ' linevpn_host
  [[ -n "$linevpn_user" ]] || read -r -p 'username: ' linevpn_user
  if [[ -z "$linevpn_password" ]]; then read -r -s -p 'password: ' linevpn_password; printf '\n'; fi
  if [[ -z "$linevpn_admin" ]]; then read -r -s -p 'vpn admin password: ' linevpn_admin; printf '\n'; fi
  validate_inputs
  local tool
  for tool in ssh tar base64; do command -v "$tool" >/dev/null || { fail "Missing standard system tool: $tool"; return 1; }; done
  local version major minor
  version=$(ssh -V 2>&1)
  [[ "$version" =~ OpenSSH_([0-9]+)\.([0-9]+) ]] || { fail 'OpenSSH 8.4+ is required.'; return 1; }
  major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}
  ((major > 8 || (major == 8 && minor >= 4))) || { fail 'OpenSSH 8.4+ is required for hidden password input.'; return 1; }
  umask 077
  linevpn_tmp=$(mktemp -d)
  linevpn_remote=''
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  printf '#!/bin/sh\nprintf "%%s\\n" "$LINEVPN_SSH_PASSWORD"\n' > "$linevpn_tmp/askpass"
  chmod 700 "$linevpn_tmp/askpass"
  printf '%s\n' 'Packaging server source. New SSH keys are saved on first use; changed keys are rejected.'
  tar -czf "$linevpn_tmp/source.tar.gz" -C "$linevpn_root" \
    --exclude='__pycache__' --exclude='*.pyc' -T "$linevpn_root/deploy/source-files.txt"
  linevpn_remote=$(ssh_run 'umask 077; mktemp -d /tmp/linevpn-deploy.XXXXXXXX' </dev/null)
  [[ "$linevpn_remote" =~ ^/tmp/linevpn-deploy\.[a-zA-Z0-9]{8}$ ]] || { linevpn_remote=''; fail 'Invalid SSH response.'; return 1; }
  ssh_run "cat > '$linevpn_remote/source.tar.gz'" < "$linevpn_tmp/source.tar.gz"
  ssh_run "cat > '$linevpn_remote/bootstrap.sh'" < "$linevpn_root/scripts/deploy-bootstrap.sh"
  printf '%s\n%s\n%s\n%s\n' "$linevpn_host" "$linevpn_port" "$linevpn_password" "$linevpn_admin" |
    ssh_run "umask 077; cat > '$linevpn_remote/input'"
  printf '%s\n' 'Installing tools and deploying on VPS. The first build may take several minutes.'
  local command
  command="if [ \"\$(id -u)\" = 0 ]; then bash '$linevpn_remote/bootstrap.sh' '$linevpn_remote'; else sed -n '3p' '$linevpn_remote/input' | sudo -S -p '' bash '$linevpn_remote/bootstrap.sh' '$linevpn_remote'; fi"
  ssh_run "$command" </dev/null | tee "$linevpn_tmp/result" | sed '/^LINEVPN_PROFILE_B64=/d; /^LINEVPN_CERT_B64=/d; /^LINEVPN_REMOTE_OK=/d'
  grep -qx 'LINEVPN_REMOTE_OK=1' "$linevpn_tmp/result" || { fail 'The server did not confirm successful deployment.'; return 1; }
  local profile64 cert64 output
  profile64=$(sed -n 's/^LINEVPN_PROFILE_B64=//p' "$linevpn_tmp/result")
  cert64=$(sed -n 's/^LINEVPN_CERT_B64=//p' "$linevpn_tmp/result")
  [[ -n "$profile64" && -n "$cert64" ]] || { fail 'Missing profile or certificate.'; return 1; }
  output="$linevpn_root/deploy/ansible/generated"
  mkdir -p "$output"
  decode64 "$profile64" > "$output/vpn1-bootstrap.txt"
  decode64 "$cert64" > "$output/vpn1-api-cert.pem"
  check_port 443 && check_port 8443 || { fail 'Remote health passed, but public TCP 443/8443 is blocked. Check the provider firewall.'; return 1; }
  local address=$linevpn_host
  [[ "$address" != *:* ]] || address="[$address]"
  printf '\nDeployment verified: remote HTTPS health and public TCP 443/8443.\nAdmin: https://%s:8443/\n' "$address"
  cat "$output/vpn1-bootstrap.txt"
  printf 'API certificate: %s/vpn1-api-cert.pem\n' "$output"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
