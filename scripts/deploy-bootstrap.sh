#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
work=${1:?missing transfer directory}
[[ "$work" =~ ^/dev/shm/linevpn-deploy\.[a-zA-Z0-9]{8}$ && -d "$work" && ! -L "$work" ]] || { echo 'Invalid RAM transfer directory.' >&2; exit 1; }
build_work=''
trap 'rm -rf -- "$work"; [[ -z "$build_work" ]] || rm -rf -- "$build_work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ ${2:-} == --root-input ]]; then
  [[ $(id -u) == 0 ]] || { echo 'Root stage requires sudo.' >&2; exit 1; }
  mapfile -t values
  [[ ${#values[@]} == 3 ]] || { echo 'Invalid bootstrap input.' >&2; exit 1; }
else
  [[ -f "$work/input" && ! -L "$work/input" ]] || { echo 'Missing protected input.' >&2; exit 1; }
  mapfile -t values < "$work/input"
  rm -f -- "$work/input"
  [[ ${#values[@]} == 4 ]] || { echo 'Invalid bootstrap input.' >&2; exit 1; }
  if [[ $(id -u) != 0 ]]; then
    # Authenticate separately. Neither NOPASSWD nor a cached sudo timestamp can
    # send an unread password into bootstrap/apt/Python stdin.
    if ! sudo -n true </dev/null 2>/dev/null; then
      printf '%s\n' "${values[2]}" | sudo -S -p '' -v
    fi
    unset 'values[2]'
    printf '%s\n' "${values[@]}" | sudo -n bash "$work/bootstrap.sh" "$work" --root-input
    exit $?
  fi
  unset 'values[2]'
fi
exec </dev/null
# Root executes/extracts only in directories it owns. The SSH deploy account is
# trusted to supply code and must already have administrative deployment rights.
chown root:root -- "$work"
chmod 700 -- "$work"
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}:$(uname -m)" in
  debian:12:x86_64|debian:13:x86_64|ubuntu:24.04:x86_64|ubuntu:26.04:x86_64) ;;
  *) echo 'Supported VPS: Debian 12/13 or Ubuntu 24.04/26.04, amd64.' >&2; exit 1 ;;
esac
# Verify only the expected archive name, never paths supplied by a checksum file.
read -r expected archive < "$work/source.sha256"
[[ "$expected" =~ ^[0-9a-f]{64}$ && "$archive" =~ ^source\.(tar\.gz|zip)$ && -f "$work/$archive" && ! -L "$work/$archive" ]] || { echo 'Invalid source checksum manifest.' >&2; exit 1; }
actual=$(sha256sum -- "$work/$archive")
[[ "${actual%% *}" == "$expected" ]] || { echo 'Source archive SHA-256 mismatch.' >&2; exit 1; }
# /dev/shm may be noexec and small; only the credential-free build goes to disk.
build_work=$(mktemp -d /tmp/linevpn-build.XXXXXXXX)
export DEBIAN_FRONTEND=noninteractive
apt_opts=(-o DPkg::Lock::Timeout=600 -o Acquire::Retries=3)
apt-get "${apt_opts[@]}" update </dev/null
apt-get "${apt_opts[@]}" install -y --no-install-recommends ca-certificates python3 python3-venv tar unzip </dev/null
mkdir "$build_work/source"
if [[ "$archive" == source.tar.gz ]]; then
  tar -xzf "$work/$archive" -C "$build_work/source" --no-same-owner
else
  unzip -q "$work/$archive" -d "$build_work/source"
fi
# Only host, port and admin password go to Python through a pipe. No SSH secret,
# descriptor referring to a deleted disk file, or inherited credential stdin.
printf '%s\n' "${values[@]}" | python3 "$build_work/source/scripts/deploy-remote.py" --stdin
unset values
