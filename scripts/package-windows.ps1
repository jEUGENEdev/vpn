$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
New-Item -ItemType Directory -Force apps/desktop/assets | Out-Null
$env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go build -tags with_gvisor -trimpath -ldflags='-s -w' -o apps/desktop/assets/linevpn-agent.exe ./cmd/linevpn-agent
if ($LASTEXITCODE -ne 0) { throw 'Agent build failed' }
Push-Location apps/desktop
npm ci
npx electron-builder --win --x64 --dir --publish never
if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed' }
Pop-Location
python packaging/windows/package.py apps/desktop/dist/win-unpacked build/LineVPN.wxs
dotnet tool install --global wix --version 5.0.2
wix build build/LineVPN.wxs -arch x64 -o build/LineVPN-0.1.0-windows-x64.msi
if ($LASTEXITCODE -ne 0) { throw 'MSI build failed' }
