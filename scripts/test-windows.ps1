# Runs only on disposable GitHub-hosted runners. Always restores their network.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Use an isolated CI runner for this network test' }
Set-Location (Join-Path $PSScriptRoot '..')
$msi = (Resolve-Path build/LineVPN-0.2.0-windows-x64.msi).Path
$agent = Join-Path $env:ProgramFiles 'LineVPN/resources/agent/linevpn-agent.exe'
$log = Join-Path (Get-Location) 'build/windows-install.log'
$nativeOK = $false
$env:LINEVPN_NATIVE_RECOVERY_TEST = "1"
go test ./internal/platform -run TestLegacyRecoveryAndStandaloneScript -v
if ($LASTEXITCODE -ne 0) { throw "Legacy WFP migration failed" }
try {
    $install = Start-Process msiexec.exe -ArgumentList @('/i', ('"' + $msi + '"'), '/qn', '/norestart', '/l*v', ('"' + $log + '"')) -Wait -PassThru
    if ($install.ExitCode -notin @(0, 3010)) { throw "MSI installation failed: $($install.ExitCode)" }
    Write-Output 'MSI installed; waiting for local service'
    $state = $null
    for ($i=0; $i -lt 20; $i++) {
        try {
            $token = (Get-Content (Join-Path $env:ProgramData 'LineVPN/ui-token') -Raw).Trim()
            $headers = @{Authorization = 'Bearer ' + $token}
            $state = Invoke-RestMethod -Uri http://127.0.0.1:17891/local/state -Headers $headers -TimeoutSec 2
            break
        } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $state.tunnel -or -not $state.guard) { throw 'TUN or persistent guard unavailable' }
    Write-Output 'Service ready; checking DNS and direct traffic'
    $answer = Resolve-DnsName example.com -Server 172.29.255.2 -Type A -DnsOnly -QuickTimeout
    if (-not ($answer.IPAddress -match '^198\.(18|19)\.')) { throw 'TUN DNS did not return a fake IP' }
    & curl.exe --silent --output NUL --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace
    if ($LASTEXITCODE -ne 0) { throw 'Unapproved direct connection failed' }
    $state = Invoke-RestMethod -Uri http://127.0.0.1:17891/local/state -Headers $headers -TimeoutSec 3
    if (@($state.requests | Where-Object { $_.target -eq '1.1.1.1' }).Count -ne 0) { throw 'Healthy direct traffic produced a proposal' }
    $curlApp = @($state.applications | Where-Object { $_.name -eq 'curl.exe' })[0]
    if (-not $curlApp.id) { throw 'Native connection owner was not identified' }
    $decision = @{id=$curlApp.id;decision='trusted'} | ConvertTo-Json
    Invoke-RestMethod -Uri http://127.0.0.1:17891/local/applications -Headers $headers -Method Post -ContentType 'application/json' -Body $decision -TimeoutSec 3 | Out-Null
    & curl.exe --silent --output NUL --connect-timeout 2 --max-time 3 http://1.1.1.1/cdn-cgi/trace
    if ($LASTEXITCODE -eq 0) { throw 'Offline trusted app bypassed VPN' }
    $decision = @{id=$curlApp.id;decision='addresses'} | ConvertTo-Json
    Invoke-RestMethod -Uri http://127.0.0.1:17891/local/applications -Headers $headers -Method Post -ContentType 'application/json' -Body $decision -TimeoutSec 3 | Out-Null
    try { Invoke-RestMethod -Uri http://127.0.0.1:17891/local/rules -Headers $headers -Method Post -ContentType 'application/json' -Body '{"target":"1.1.1.1","action":"approve","revision":0}' -TimeoutSec 3 | Out-Null } catch { }
    $state = Invoke-RestMethod -Uri http://127.0.0.1:17891/local/state -Headers $headers -TimeoutSec 2
    if ($state.pending_protection -notcontains '1.1.1.1') { throw 'Approval not protected locally' }
    & curl.exe --silent --output NUL --connect-timeout 2 --max-time 3 http://1.1.1.1/cdn-cgi/trace
    if ($LASTEXITCODE -eq 0) { throw 'Offline approved address bypassed VPN' }
    python scripts/test-desktop-power.py
    if ($LASTEXITCODE -ne 0) { throw 'Native power cycle regression failed' }
    Write-Output 'Checking abrupt process termination and retained protection'
    Set-Service LineVPN -StartupType Disabled
    $vpnProcess = (Get-CimInstance Win32_Service -Filter "Name='LineVPN'").ProcessId
    Stop-Process -Id $vpnProcess -Force
    Start-Sleep -Seconds 2
    & curl.exe --silent --output NUL --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace
    if ($LASTEXITCODE -eq 0) { throw 'Protected traffic escaped after process termination' }
    Set-Service LineVPN -StartupType Automatic
    Start-Service LineVPN
    # An enabled service must stop cleanly before MSI removes its executable.
    $remove = Start-Process msiexec.exe -ArgumentList @('/x', ('"' + $msi + '"'), '/qn', '/norestart') -Wait -PassThru
    if ($remove.ExitCode -notin @(0,3010)) { throw "MSI removal failed: $($remove.ExitCode)" }
    if (Get-Service LineVPN -ErrorAction SilentlyContinue) { throw 'Service survived uninstall' }
    if (Test-Path $agent) { throw 'Agent survived uninstall' }
    & curl.exe --silent --output NUL --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace
    if ($LASTEXITCODE -ne 0) { throw 'Network failed after uninstall' }
    Resolve-DnsName example.com -Type A -DnsOnly -QuickTimeout | Out-Null
    $nativeOK = $true
} finally {
    if (Get-Service LineVPN -ErrorAction SilentlyContinue) {
        Set-Service LineVPN -StartupType Disabled
        Stop-Service LineVPN -ErrorAction Continue
    }
    if (Test-Path $agent) { & $agent -recover-network }
    if (-not $nativeOK) { Start-Process msiexec.exe -ArgumentList @('/x', ('"' + $msi + '"'), '/qn', '/norestart') -Wait | Out-Null }
}
if ($nativeOK) { 'PASS: MSI install, DNS, protected failures, off/on, process termination and automatic uninstall recovery' | Set-Content build/windows-native.txt }
