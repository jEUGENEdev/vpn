#!/usr/bin/env bash
# Secrets use protected RAM staging on the VPS; never enable shell tracing.
set +x
set -euo pipefail
linevpn_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fail() { printf 'ERROR: %s\n' "$*" >&2; return 1; }

validate_inputs() {
  python3 - "$linevpn_host" <<'IP' || { fail 'host must be a public IPv4 or IPv6 address.'; return 1; }
import ipaddress, sys
try:
    ip = ipaddress.ip_address(sys.argv[1])
    valid = ip.is_global and not ip.is_multicast and not ip.is_reserved and '%' not in sys.argv[1]
except ValueError:
    valid = False
sys.exit(0 if valid else 1)
IP
  [[ "$linevpn_user" =~ ^[a-z_][a-z0-9_-]{0,31}\$?$ ]] || { fail 'Invalid SSH username.'; return 1; }
  [[ "$linevpn_port" =~ ^[0-9]{1,5}$ ]] && ((10#$linevpn_port >= 1 && 10#$linevpn_port <= 65535)) || { fail 'Invalid VPS_PORT.'; return 1; }
  [[ "$linevpn_password" != *$'\n'* && "$linevpn_password" != *$'\r'* ]] || { fail 'SSH/sudo password must be on one line.'; return 1; }
  local count
  count=$(LC_ALL=C printf '%s' "$linevpn_admin" | wc -c | tr -d ' ')
  ((count >= 16 && count <= 72)) && [[ "$linevpn_admin" != *$'\n'* && "$linevpn_admin" != *$'\r'* && "$linevpn_admin" != [[:space:]]* && "$linevpn_admin" != *[[:space:]] ]] || { fail 'VPN admin password must be 16-72 UTF-8 bytes, without surrounding whitespace.'; return 1; }
}

ssh_run() {
  # Bash 3.2 treats empty arrays as unset under set -u. Keep the command nonempty.
  local -a ssh_command=(ssh -F /dev/null -T -p "$linevpn_port" "${linevpn_ssh_opts[@]}"
    -o PreferredAuthentications=publickey,password -o PubkeyAuthentication=yes
    -o NumberOfPasswordPrompts=1 -o ConnectTimeout=20
    -o ServerAliveInterval=10 -o ServerAliveCountMax=2
    "$linevpn_user@$linevpn_host" "$@")
  if [[ -n ${linevpn_deadline:-} ]]; then
    ssh_command=(python3 -c 'import subprocess,sys
try:
    sys.exit(subprocess.run(sys.argv[2:], timeout=int(sys.argv[1])).returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)' "$linevpn_deadline" "${ssh_command[@]}")
  fi
  SSH_ASKPASS="$linevpn_tmp/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=linevpn:0 \
    "${ssh_command[@]}"
}

configure_ssh() {
  linevpn_ssh_opts=(-o StrictHostKeyChecking=accept-new)
  if [[ -n ${VPS_IDENTITY_FILE:-} ]]; then
    [[ -r "$VPS_IDENTITY_FILE" ]] || { fail 'Cannot read VPS_IDENTITY_FILE.'; return 1; }
    linevpn_ssh_opts+=(-i "$VPS_IDENTITY_FILE" -o IdentitiesOnly=yes)
  fi
  if [[ -n ${VPS_HOST_FINGERPRINT:-} ]]; then
    [[ "$VPS_HOST_FINGERPRINT" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || { fail 'VPS_HOST_FINGERPRINT must be a full SHA256 fingerprint.'; return 1; }
    ssh-keyscan -T 10 -p "$linevpn_port" "$linevpn_host" > "$linevpn_tmp/scanned" 2>/dev/null || { fail 'Host key scan failed.'; return 1; }
    : > "$linevpn_tmp/known_hosts"
    local key actual
    while IFS= read -r key; do
      [[ -z "$key" || "$key" == '#'* ]] && continue
      printf '%s\n' "$key" > "$linevpn_tmp/key"
      actual=$(ssh-keygen -E sha256 -lf "$linevpn_tmp/key" 2>/dev/null | awk '{print $2}') || continue
      # Only matching keys enter the trust store; ssh-keyscan is unauthenticated.
      if [[ "$actual" == "$VPS_HOST_FINGERPRINT" ]]; then printf '%s\n' "$key" >> "$linevpn_tmp/known_hosts"; fi
    done < "$linevpn_tmp/scanned"
    [[ -s "$linevpn_tmp/known_hosts" ]] || { fail 'Host key fingerprint mismatch.'; return 1; }
    linevpn_ssh_opts+=(-o "UserKnownHostsFile=$linevpn_tmp/known_hosts" -o GlobalKnownHostsFile=/dev/null)
    linevpn_ssh_opts[1]=StrictHostKeyChecking=yes
  else
    printf '%s\n' 'SSH first-use trust: set VPS_HOST_FINGERPRINT from the provider console to verify a new host.'
  fi
}

prepare_source() {
  if [[ -n ${LINEVPN_SERVER_BUNDLE:-} ]]; then
    [[ -f "$LINEVPN_SERVER_BUNDLE" ]] || { fail 'Cannot read LINEVPN_SERVER_BUNDLE.'; return 1; }
    cp -- "$LINEVPN_SERVER_BUNDLE" "$linevpn_tmp/source.tar.gz"
  else
    printf '%s\n' 'Building server binaries locally (Go 1.27.4), before contacting the VPS.'
    bash "$linevpn_root/scripts/package-server.sh"
    cp -- "$linevpn_root/build/linevpn-server-bundle.tar.gz" "$linevpn_tmp/source.tar.gz"
  fi
}

decode64() {
  local out
  out=$(printf '%s' "$1" | base64 -d 2>/dev/null) ||
    out=$(printf '%s' "$1" | base64 -D 2>/dev/null) || return 1
  printf '%s\n' "$out"
}

verify_public() {
  python3 "$linevpn_root/scripts/deploy-actions.py" --host "$linevpn_host" --certificate "$1" --reality-sni "$2"
}

cleanup() {
  local result=$?
  trap - EXIT
  if [[ -n ${linevpn_remote:-} ]]; then
    # Python is already a launcher prerequisite; this bounds the full SSH
    # process without orphaned watchdogs or requiring GNU timeout on macOS.
    trap '' INT TERM
    linevpn_deadline=30 ssh_run "rm -rf -- '$linevpn_remote'" </dev/null >/dev/null 2>&1 || true
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
      'Optional: VPS_PORT (22), VPS_IDENTITY_FILE, VPS_HOST_FINGERPRINT=SHA256:...' \
      'Set VPS_PASSWORD to an empty string for SSH keys with passwordless sudo.' \
      'Requires Python 3.11+ and Go 1.27.4 locally, or LINEVPN_SERVER_BUNDLE from CI.'
    return
  fi
  [[ $# == 0 ]] || { fail 'Use prompts or environment variables, not password arguments.'; return 1; }
  linevpn_host=${VPS_HOST:-}; linevpn_user=${VPS_USERNAME:-}
  linevpn_password=${VPS_PASSWORD:-}; linevpn_admin=${VPN_ADMIN_PASSWORD:-}
  linevpn_port=${VPS_PORT:-22}
  local password_set=${VPS_PASSWORD+x}
  unset VPS_PASSWORD VPN_ADMIN_PASSWORD LINEVPN_SSH_PASSWORD
  [[ -n "$linevpn_host" ]] || read -r -p 'host: ' linevpn_host
  [[ -n "$linevpn_user" ]] || read -r -p 'username: ' linevpn_user
  if [[ -z "$password_set" && -z ${VPS_IDENTITY_FILE:-} ]]; then read -r -s -p 'password (empty for SSH key): ' linevpn_password; printf '\n'; fi
  if [[ -z "$linevpn_admin" ]]; then read -r -s -p 'vpn admin password: ' linevpn_admin; printf '\n'; fi
  local tool
  for tool in ssh ssh-keyscan ssh-keygen tar base64 python3; do command -v "$tool" >/dev/null || { fail "Missing system tool: $tool"; return 1; }; done
  validate_inputs
  local version major minor
  version=$(ssh -V 2>&1)
  [[ "$version" =~ OpenSSH_([0-9]+)\.([0-9]+) ]] || { fail 'OpenSSH 8.4+ is required.'; return 1; }
  major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}
  ((major > 8 || (major == 8 && minor >= 4))) || { fail 'OpenSSH 8.4+ is required for hidden password input.'; return 1; }
  umask 077
  local temp_base=${TMPDIR:-/tmp}
  linevpn_tmp=$(mktemp -d "$temp_base/linevpn-local.XXXXXXXX")
  linevpn_remote=''
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  printf '%s\n' "$linevpn_password" > "$linevpn_tmp/pw"
  chmod 600 "$linevpn_tmp/pw"
  printf '#!/bin/sh\ncat "$(dirname "$0")/pw"\n' > "$linevpn_tmp/askpass"
  chmod 700 "$linevpn_tmp/askpass"
  configure_ssh
  printf '%s\n' 'Preparing verified server bundle.'
  prepare_source
  python3 - "$linevpn_tmp/source.tar.gz" > "$linevpn_tmp/source.sha256" <<'SHA'
import hashlib, sys
with open(sys.argv[1], 'rb') as f:
    print(hashlib.file_digest(f, 'sha256').hexdigest() + '  source.tar.gz')
SHA
  linevpn_remote=$(ssh_run 'umask 077; [ -d /dev/shm ] && [ -w /dev/shm ] || { echo "RAM staging /dev/shm is required" >&2; exit 1; }; mktemp -d /dev/shm/linevpn-deploy.XXXXXXXX' </dev/null)
  [[ "$linevpn_remote" =~ ^/dev/shm/linevpn-deploy\.[a-zA-Z0-9]{8}$ ]] || { linevpn_remote=''; fail 'Invalid SSH response.'; return 1; }
  ssh_run "cat > '$linevpn_remote/source.tar.gz'" < "$linevpn_tmp/source.tar.gz"
  ssh_run "cat > '$linevpn_remote/source.sha256'" < "$linevpn_tmp/source.sha256"
  ssh_run "cat > '$linevpn_remote/bootstrap.sh'" < "$linevpn_root/scripts/deploy-bootstrap.sh"
  printf '%s\n%s\n%s\n%s\n' "$linevpn_host" "$linevpn_port" "$linevpn_password" "$linevpn_admin" |
    ssh_run "umask 077; cat > '$linevpn_remote/input'"
  printf '%s\n' 'Deploying prebuilt binaries on VPS. Installing packages may take several minutes.'
  ssh_run "bash '$linevpn_remote/bootstrap.sh' '$linevpn_remote'" </dev/null | tee "$linevpn_tmp/result" | sed '/^LINEVPN_PROFILE_B64=/d; /^LINEVPN_CERT_B64=/d; /^LINEVPN_REALITY_SNI_B64=/d; /^LINEVPN_REMOTE_OK=/d'
  grep -qx 'LINEVPN_REMOTE_OK=1' "$linevpn_tmp/result" || { fail 'The server did not confirm successful deployment.'; return 1; }
  local profile64 cert64 sni64 reality_sni output
  profile64=$(sed -n 's/^LINEVPN_PROFILE_B64=//p' "$linevpn_tmp/result")
  cert64=$(sed -n 's/^LINEVPN_CERT_B64=//p' "$linevpn_tmp/result")
  sni64=$(sed -n 's/^LINEVPN_REALITY_SNI_B64=//p' "$linevpn_tmp/result")
  [[ -n "$profile64" && -n "$cert64" && -n "$sni64" ]] || { fail 'Missing profile, certificate or REALITY identity.'; return 1; }
  output="$linevpn_root/deploy/ansible/generated"
  mkdir -p "$output"
  decode64 "$profile64" > "$linevpn_tmp/profile"
  decode64 "$cert64" > "$linevpn_tmp/certificate"
  install -m 600 "$linevpn_tmp/profile" "$output/vpn1-bootstrap.txt"
  install -m 600 "$linevpn_tmp/certificate" "$output/vpn1-api-cert.pem"
  reality_sni=$(decode64 "$sni64")
  verify_public "$output/vpn1-api-cert.pem" "$reality_sni"
  local address=$linevpn_host
  [[ "$address" != *:* ]] || address="[$address]"
  printf '\nDeployment verified: authenticated HTTPS API and REALITY TLS listener.\n'
  printf 'Admin: https://%s:8443/\n' "$address"
  printf 'Public API identity (no enrollment key):\n'
  cat "$output/vpn1-bootstrap.txt"
  printf 'Get the current connection profile in Admin > Server profile.\n'
  printf 'API certificate: %s/vpn1-api-cert.pem\n' "$output"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
