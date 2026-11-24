$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'deploy-windows.ps1'
$tokens = $null
$errors = $null
[Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count) { throw ($errors | Out-String) }
. $scriptPath

Test-DeployInput '8.8.8.8' 'root' 'ssh $() password' 'admin $() {{literal}} password' '22'
Test-DeployInput '2606:4700:4700::1111' 'ubuntu' 'password' ('a' * 16) '2222'
$invalid = @(
    @('8.8.8.8;id', 'root', 'password', ('a' * 16), '22'),
    @('8.8.8.8', '-oProxyCommand=id', 'password', ('a' * 16), '22'),
    @('8.8.8.8', 'root', 'password', ('a' * 16), '0'),
    @('8.8.8.8', 'root', 'password', ([string][char]0x044f * 40), '22'),
    @('8.8.8.8', 'root', "password`nsecond-line", ('a' * 16), '22')
)
foreach ($values in $invalid) {
    $rejected = $false
    try { Test-DeployInput @values } catch { $rejected = $true }
    if (-not $rejected) { throw 'Invalid input was accepted.' }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('vpn package ' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $zip = Join-Path $work 'source.zip'
    Prepare-ServerBinaries
    New-SourceArchive $zip
    $archive = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        $names = @($archive.Entries | ForEach-Object { $_.FullName })
        foreach ($required in @('go.mod', 'scripts/deploy-remote.py', 'deploy/ansible/deploy.yml')) {
            if ($names -notcontains $required) { throw "Missing package entry: $required" }
        }
        if ($names | Where-Object { $_ -match '(^\.git/|vault\.yml$|inventory\.ini$|generated/|\\)' }) { throw 'Unexpected private file or Windows path separator in archive.' }
    } finally { $archive.Dispose() }
    Write-Host 'PowerShell syntax, input validation and source packaging passed.'
} finally { Remove-Item -LiteralPath $work -Recurse -Force }
