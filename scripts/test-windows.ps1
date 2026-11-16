# Runs only on disposable GitHub-hosted runners. Always restores their network.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Use an isolated CI runner for this network test' }
Set-Location (Join-Path $PSScriptRoot '..')
$msi = (Resolve-Path build/LineVPN-0.1.0-windows-x64.msi).Path
$agent = Join-Path $env:ProgramFiles 'LineVPN/resources/agent/linevpn-agent.exe'
$log = Join-Path (Get-Location) 'build/windows-install.log'
$nativeOK = $false
# Preserve only the CI control plane. Curl/DNS probes receive no exemption.
$controllers = @(Get-Process -Name 'Runner.Listener','Runner.Worker' -ErrorAction SilentlyContinue | ForEach-Object { $_.Path } | Sort-Object -Unique)
if ($controllers.Count -eq 0) { throw 'Actions controller processes not found' }
$ciGuard = Join-Path (Get-Location) 'build/linevpn-ci-controller.exe'
go build -tags linevpn_ci -o $ciGuard ./internal/citest/windowscontrol
if ($LASTEXITCODE -ne 0) { throw 'CI controller helper failed to build' }
try {
    & $ciGuard @controllers
    if ($LASTEXITCODE -ne 0) { throw 'Could not preserve the CI control channel' }
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
    if (-not $state.tunnel -or -not $state.guard) { throw 'TUN / persistent WFP did not start' }
    Write-Output 'Service ready; checking DNS and direct traffic'
    $answer = Resolve-DnsName example.com -Server 172.29.255.2 -Type A -DnsOnly -QuickTimeout
    if (-not ($answer.IPAddress -match '^198\.(18|19)\.')) { throw 'TUN DNS did not return a fake IP' }
    & curl.exe --silent --output NUL --connect-timeout 4 --max-time 8 http://1.1.1.1/cdn-cgi/trace
    if ($LASTEXITCODE -ne 0) { throw 'Unapproved direct connection failed' }
    try { Invoke-RestMethod -Uri http://127.0.0.1:17891/local/rules -Headers $headers -Method Post -ContentType 'application/json' -Body '{"target":"1.1.1.1","action":"approve","revision":0}' -TimeoutSec 3 | Out-Null } catch { }
    $state = Invoke-RestMethod -Uri http://127.0.0.1:17891/local/state -Headers $headers -TimeoutSec 2
    if ($state.pending_protection -notcontains '1.1.1.1') { throw 'Approval not protected locally' }
    & curl.exe --silent --output NUL --connect-timeout 2 --max-time 3 http://1.1.1.1/cdn-cgi/trace
    if ($LASTEXITCODE -eq 0) { throw 'Approved IP escaped without VPN' }
    # Stop the service explicitly to suppress recovery while checking persistent rules.
    Write-Output 'Checking bounded service stop and persistent WFP'
    $service = Get-Service LineVPN
    $service.Stop()
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15))
    & curl.exe --silent --output NUL --connect-timeout 2 --max-time 3 http://1.1.1.1/cdn-cgi/trace
    if ($LASTEXITCODE -eq 0) { throw 'WFP guard disappeared with the service' }
    Write-Output 'WFP remained active; restoring test machine'
    $nativeOK = $true
} finally {
    try {
        if (Test-Path $agent) {
            & sc.exe config LineVPN start= disabled | Out-Null
            try {
                $service = Get-Service LineVPN
                if ($service.Status -ne 'Stopped') { $service.Stop(); $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15)) }
            } catch {
                $vpnProcess = (Get-CimInstance Win32_Service -Filter "Name='LineVPN'").ProcessId
                if ($vpnProcess -gt 0) { Stop-Process -Id $vpnProcess -Force -ErrorAction SilentlyContinue }
            }
            & $agent -recover-network
        }
        Start-Process msiexec.exe -ArgumentList @('/x', ('"' + $msi + '"'), '/qn', '/norestart') -Wait | Out-Null
    } finally {
        & $ciGuard -remove @controllers
    }
}
if ($nativeOK) { 'PASS: MSI install, TUN DNS, direct connection, approval block and persistent WFP after service stop' | Set-Content build/windows-native.txt }
