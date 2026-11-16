#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
vpn_arch="${1:-arm64}"
mkdir -p build/macos-root/Library/LaunchDaemons 'build/macos-root/Library/Application Support/LineVPN' build/macos-scripts apps/desktop/assets
GOOS=darwin GOARCH="$vpn_arch" CGO_ENABLED=0 go build -tags with_gvisor -trimpath -ldflags='-s -w' -o 'build/macos-root/Library/Application Support/LineVPN/linevpn-agent' ./cmd/linevpn-agent
cp packaging/macos/dev.linevpn.agent.plist build/macos-root/Library/LaunchDaemons/
cp packaging/macos/postinstall build/macos-scripts/postinstall
cp packaging/macos/recover-network.sh 'build/macos-root/Library/Application Support/LineVPN/'
chmod 755 build/macos-scripts/postinstall 'build/macos-root/Library/Application Support/LineVPN/'*
pkgbuild --root build/macos-root --scripts build/macos-scripts --identifier dev.linevpn.service --version 0.1.0 --install-location / apps/desktop/assets/Install-LineVPN-Service.pkg
cat > apps/desktop/assets/Install-Service.command <<'COMMAND'
#!/bin/bash
open "$(dirname "$0")/Install-LineVPN-Service.pkg"
COMMAND
chmod 755 apps/desktop/assets/Install-Service.command
cd apps/desktop
npm ci
vpn_electron_arch="$vpn_arch"
if [[ "$vpn_arch" == amd64 ]]; then vpn_electron_arch=x64; fi
npx electron-builder --mac dmg --"$vpn_electron_arch" --publish never
