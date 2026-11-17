#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
work=${1:?missing transfer directory}
[[ "$work" =~ ^/tmp/linevpn-deploy\.[a-zA-Z0-9]{8}$ && -d "$work" && ! -L "$work" ]] || exit 1
[[ $(id -u) == 0 ]] || { echo 'root or sudo with the SSH password is required.' >&2; exit 1; }
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
. /etc/os-release
case "$ID:$VERSION_ID:$(uname -m)" in
  debian:12:x86_64|debian:13:x86_64|ubuntu:24.04:x86_64|ubuntu:26.04:x86_64) ;;
  *) echo 'Supported VPS: Debian 12/13 or Ubuntu 24.04/26.04, amd64.' >&2; exit 1 ;;
esac
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates python3 python3-venv tar unzip
mkdir "$work/source"
if [[ -f "$work/source.tar.gz" ]]; then
  tar -xzf "$work/source.tar.gz" -C "$work/source" --no-same-owner
else
  unzip -q "$work/source.zip" -d "$work/source"
fi
python3 "$work/source/scripts/deploy-remote.py" "$work/input"
