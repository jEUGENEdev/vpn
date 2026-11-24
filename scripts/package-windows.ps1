$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$vpnVersion = python scripts/package_version.py --check-consistent
if ($LASTEXITCODE -ne 0) { throw 'Installer version metadata must be consistent' }
New-Item -ItemType Directory -Force apps/desktop/assets | Out-Null
python scripts/collect-licenses.py apps/desktop/assets/THIRD_PARTY_NOTICES.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency notices failed' }
$env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go build -tags with_gvisor -trimpath -ldflags='-s -w' -o apps/desktop/assets/linevpn-agent.exe ./cmd/linevpn-agent
if ($LASTEXITCODE -ne 0) { throw 'Agent build failed' }
Push-Location apps/desktop
npm ci
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
npx electron-builder --win --x64 --dir --publish never
if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed' }
Pop-Location
New-Item -ItemType Directory -Force build | Out-Null
node scripts/verify-windows-payload.cjs apps/desktop/dist/win-unpacked build/windows-file-versions.json
if ($LASTEXITCODE -ne 0) { throw 'Packaged Windows branding or version is invalid' }
python packaging/windows/package.py apps/desktop/dist/win-unpacked build/LineVPN.wxs
if ($LASTEXITCODE -ne 0) { throw 'MSI source generation failed' }
dotnet tool install --global wix --version 5.0.2
if ($LASTEXITCODE -ne 0) { throw 'WiX installation failed' }
wix build build/LineVPN.wxs -arch x64 -o "build/Сеть-$vpnVersion-windows-x64.msi"
if ($LASTEXITCODE -ne 0) { throw 'MSI build failed' }

& scripts/test-windows-package.ps1 -Msi "build/Сеть-$vpnVersion-windows-x64.msi"
