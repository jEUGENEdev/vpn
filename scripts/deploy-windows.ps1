# Native Windows PowerShell 5.1+. Posh-SSH is installed automatically for this user.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$LineVpnRoot = Split-Path -Parent $PSScriptRoot

function Read-DeployValue([string]$Name, [string]$Prompt, [switch]$Secret) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ($value) {
        if ($Secret) { [Environment]::SetEnvironmentVariable($Name, $null, 'Process') }
        return $value
    }
    if ($Secret) {
        $secure = Read-Host $Prompt -AsSecureString
        return (New-Object System.Net.NetworkCredential('', $secure)).Password
    }
    return (Read-Host $Prompt)
}

function Test-DeployInput([string]$Server, [string]$UserName, [string]$Password, [string]$AdminPassword, [string]$SshPort) {
    $ip = $null
    if ($Server -notmatch '^[0-9a-fA-F:.]+$' -or -not [Net.IPAddress]::TryParse($Server, [ref]$ip)) { throw 'host must be a public IPv4 or IPv6 address.' }
    if ($UserName -cnotmatch '^[a-z_][a-z0-9_-]{0,31}\$?$') { throw 'Invalid SSH username.' }
    if ($SshPort -notmatch '^[0-9]{1,5}$' -or [int]$SshPort -lt 1 -or [int]$SshPort -gt 65535) { throw 'Invalid VPS_PORT.' }
    if (-not $Password -or $Password -match '[\r\n\x00]') { throw 'SSH password must be nonempty and on one line.' }
    $bytes = [Text.Encoding]::UTF8.GetByteCount($AdminPassword)
    if ($bytes -lt 16 -or $bytes -gt 72 -or $AdminPassword -match '[\r\n\x00]' -or $AdminPassword -cne $AdminPassword.Trim()) { throw 'VPN admin password must be 16-72 UTF-8 bytes without surrounding whitespace.' }
}

function Prepare-ServerBinaries {
    if ($env:LINEVPN_SERVER_BUILD_DIR) {
        $source = $env:LINEVPN_SERVER_BUILD_DIR
        New-Item -ItemType Directory -Path (Join-Path $LineVpnRoot 'build') -Force | Out-Null
        foreach ($name in @('linevpn-server-linux-amd64','linevpn-keygen-linux-amd64','SHA256SUMS')) {
            Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $LineVpnRoot "build/$name") -Force
        }
        return
    }
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw 'Install Go 1.27.4 locally, or set LINEVPN_SERVER_BUILD_DIR to extracted CI build files.' }
    $saved = @($env:CGO_ENABLED,$env:GOOS,$env:GOARCH)
    Push-Location $LineVpnRoot
    try {
        $env:CGO_ENABLED='0';$env:GOOS='linux';$env:GOARCH='amd64'
        New-Item -ItemType Directory -Path 'build' -Force | Out-Null
        foreach ($name in @('server','keygen')) {
            & go build -trimpath '-ldflags=-s -w' -o "build/linevpn-$name-linux-amd64" "./cmd/linevpn-$name"
            if ($LASTEXITCODE -ne 0) { throw 'Local server build failed.' }
        }
        $lines = foreach ($name in @('linevpn-server-linux-amd64','linevpn-keygen-linux-amd64')) {
            (Get-FileHash -Algorithm SHA256 "build/$name").Hash.ToLowerInvariant() + '  ' + $name
        }
        [IO.File]::WriteAllText((Join-Path $LineVpnRoot 'build/SHA256SUMS'), ($lines -join "`n") + "`n", (New-Object Text.UTF8Encoding($false)))
    } finally {
        $env:CGO_ENABLED=$saved[0];$env:GOOS=$saved[1];$env:GOARCH=$saved[2]
        Pop-Location
    }
}

function New-SourceArchive([string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($Destination, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($entry in @((Get-Content -LiteralPath (Join-Path $LineVpnRoot 'deploy/source-files.txt')) + @('build/linevpn-server-linux-amd64','build/linevpn-keygen-linux-amd64','build/SHA256SUMS'))) {
            if (-not $entry) { continue }
            $item = Get-Item -LiteralPath (Join-Path $LineVpnRoot $entry)
            $files = if ($item.PSIsContainer) { Get-ChildItem -LiteralPath $item.FullName -File -Recurse } else { @($item) }
            foreach ($file in $files) {
                if ($file.Extension -eq '.pyc' -or $file.FullName -match '[\\/]__pycache__[\\/]') { continue }
                $relative = $file.FullName.Substring($LineVpnRoot.Length).TrimStart([char[]]'\/').Replace('\', '/')
                [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $relative) | Out-Null
            }
        }
    } finally { $archive.Dispose() }
}

function Test-PublicPort([string]$Server, [int]$Port) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect($Server, $Port, $null, $null)
        try {
            if (-not $pending.AsyncWaitHandle.WaitOne(10000)) { throw "TCP $Port is not reachable; check the provider firewall." }
            $client.EndConnect($pending)
        } finally { $pending.AsyncWaitHandle.Close() }
    } finally { $client.Dispose() }
}

function Invoke-CheckedSsh($Session, [string]$Command) {
    $result = Invoke-SSHCommand -SSHSession $Session -Command $Command -TimeOut 60
    if ($result.ExitStatus -ne 0) { throw ('SSH command failed: ' + $result.Error) }
    return (($result.Output -join "`n").Trim())
}

function Send-File($Session, [string]$LocalPath, [string]$RemotePath) {
    $stream = [IO.File]::OpenRead($LocalPath)
    try { $Session.Session.UploadFile($stream, $RemotePath) }
    finally { $stream.Dispose() }
}

function Invoke-RemoteDeployment($Session, [string]$Command) {
    $commandObject = $Session.Session.CreateCommand($Command)
    $commandObject.CommandTimeout = [TimeSpan]::FromHours(1)
    $reader = $null
    $pendingCommand = $null
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    $data = @{}
    try {
        $pendingCommand = $commandObject.BeginExecute()
        $reader = New-Object IO.StreamReader($commandObject.OutputStream)
        while ($true) {
            $pendingLine = $reader.ReadLineAsync()
            while (-not $pendingLine.Wait(1000)) {
                if ($elapsed.Elapsed.TotalHours -ge 1) { throw 'Remote deployment timed out.' }
            }
            $line = $pendingLine.GetAwaiter().GetResult()
            if ($null -eq $line) { break }
            if ($line -match '^LINEVPN_(PROFILE_B64|CERT_B64|REALITY_SNI_B64|REMOTE_OK)=(.*)$') { $data[$Matches[1]] = $Matches[2] }
            else { Write-Host $line }
        }
        $commandObject.EndExecute($pendingCommand) | Out-Null
        if ($commandObject.ExitStatus -ne 0 -or $data['REMOTE_OK'] -ne '1') {
            if ($commandObject.Error) { Write-Host $commandObject.Error }
            throw 'The server did not confirm successful deployment.'
        }
        return $data
    } finally {
        if ($pendingCommand -and -not $pendingCommand.IsCompleted) { $commandObject.CancelAsync() }
        if ($reader) { $reader.Dispose() }
        $commandObject.Dispose()
    }
}

function Invoke-Deployment {
    $server = Read-DeployValue 'VPS_HOST' 'host'
    $username = Read-DeployValue 'VPS_USERNAME' 'username'
    $password = Read-DeployValue 'VPS_PASSWORD' 'password' -Secret
    $adminPassword = Read-DeployValue 'VPN_ADMIN_PASSWORD' 'vpn admin password' -Secret
    $port = if ($env:VPS_PORT) { $env:VPS_PORT } else { '22' }
    Test-DeployInput $server $username $password $adminPassword $port
    $localWork = Join-Path ([IO.Path]::GetTempPath()) ('linevpn-' + [Guid]::NewGuid().ToString('N'))
    $sshSession = $null
    $sftpSession = $null
    $remoteWork = $null
    New-Item -ItemType Directory -Path $localWork | Out-Null
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if (-not (Get-Module -ListAvailable -Name Posh-SSH | Where-Object { $_.Version -eq [Version]'4.0.0' })) {
            Write-Host 'Installing the SSH module for the current Windows user...'
            if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
            }
            Install-Module -Name Posh-SSH -RequiredVersion 4.0.0 -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -Confirm:$false
        }
        Import-Module Posh-SSH -RequiredVersion 4.0.0
        Prepare-ServerBinaries
        New-SourceArchive (Join-Path $localWork 'source.zip')
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        $credential = New-Object Management.Automation.PSCredential($username, $securePassword)
        Write-Host 'Connecting. New host keys are saved on first use; changed keys are rejected.'
        $sshSession = New-SSHSession -ComputerName $server -Port ([int]$port) -Credential $credential -AcceptKey -ConnectionTimeout 20 -KeepAliveInterval 30
        $remoteWork = Invoke-CheckedSsh $sshSession 'umask 077; test -d /dev/shm || exit 1; mktemp -d /dev/shm/linevpn-deploy.XXXXXXXX'
        if ($remoteWork -cnotmatch '^/dev/shm/linevpn-deploy\.[a-zA-Z0-9]{8}$') { $remoteWork = $null; throw 'Invalid SSH response.' }
        $sftpSession = New-SFTPSession -ComputerName $server -Port ([int]$port) -Credential $credential -AcceptKey -ConnectionTimeout 20
        $checksum = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $localWork 'source.zip')).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText((Join-Path $localWork 'source.sha256'), "$checksum  source.zip`n", (New-Object Text.UTF8Encoding($false)))
        Send-File $sftpSession (Join-Path $localWork 'source.zip') "$remoteWork/source.zip"
        Send-File $sftpSession (Join-Path $localWork 'source.sha256') "$remoteWork/source.sha256"
        Send-File $sftpSession (Join-Path $PSScriptRoot 'deploy-bootstrap.sh') "$remoteWork/bootstrap.sh"
        # Credentials go directly from memory to a protected remote directory over SFTP.
        $inputBytes = [Text.Encoding]::UTF8.GetBytes("$server`n$port`n$password`n$adminPassword`n")
        $stream = $sftpSession.Session.OpenWrite("$remoteWork/input")
        try { $stream.Write($inputBytes, 0, $inputBytes.Length) }
        finally { $stream.Dispose(); [Array]::Clear($inputBytes, 0, $inputBytes.Length) }
        $sftpSession.Session.ChangePermissions("$remoteWork/input", [uint16]384)
        Remove-SFTPSession -SessionId $sftpSession.SessionId | Out-Null
        $sftpSession = $null
        $command = "bash '$remoteWork/bootstrap.sh' '$remoteWork' </dev/null"
        Write-Host 'Installing verified server binaries on VPS.'
        $resultData = Invoke-RemoteDeployment $sshSession $command
        if (-not $resultData['PROFILE_B64'] -or -not $resultData['CERT_B64']) { throw 'Missing profile or certificate.' }
        $output = Join-Path $LineVpnRoot 'deploy/ansible/generated'
        New-Item -ItemType Directory -Path $output -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $output 'vpn1-bootstrap.txt'), [Convert]::FromBase64String($resultData['PROFILE_B64']))
        [IO.File]::WriteAllBytes((Join-Path $output 'vpn1-api-cert.pem'), [Convert]::FromBase64String($resultData['CERT_B64']))
        Test-PublicPort $server 443
        Test-PublicPort $server 8443
        $address = if ($server.Contains(':')) { "[$server]" } else { $server }
        Write-Host "`nDeployment verified: remote HTTPS health and public TCP 443/8443."
        Write-Host "Admin tunnel: ssh -N -p $port -L 8443:127.0.0.1:8444 $username@$address"
        Write-Host 'Admin (after starting the tunnel): https://127.0.0.1:8443/'
        Write-Host 'Public API identity (no enrollment key):'
        Write-Host (Get-Content -LiteralPath (Join-Path $output 'vpn1-bootstrap.txt') -Raw)
        Write-Host 'Get the current connection profile in Admin > Server profile.'
        Write-Host "API certificate: $output\vpn1-api-cert.pem"
    } finally {
        if ($sftpSession) { Remove-SFTPSession -SessionId $sftpSession.SessionId -ErrorAction SilentlyContinue | Out-Null }
        if ($sshSession) {
            if ($remoteWork) { Invoke-SSHCommand -SSHSession $sshSession -Command "rm -rf -- '$remoteWork'" -TimeOut 20 -ErrorAction SilentlyContinue | Out-Null }
            Remove-SSHSession -SessionId $sshSession.SessionId -ErrorAction SilentlyContinue | Out-Null
        }
        Remove-Item -LiteralPath $localWork -Recurse -Force -ErrorAction SilentlyContinue
        $password = $null; $adminPassword = $null
    }
}

# Dot-sourcing loads only the functions for native Windows tests.
if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-Deployment; exit 0 }
    catch { Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }
}
