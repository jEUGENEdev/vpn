# Read-only validation of the compiled MSI against its payload's PE resources.
param([Parameter(Mandatory=$true)][string]$Msi,
      [string]$Source = 'build/LineVPN.wxs',
      [string]$Versions = 'build/windows-file-versions.json')
$ErrorActionPreference = 'Stop'
$expected = Get-Content -Raw -Encoding UTF8 $Versions | ConvertFrom-Json
$payload = (Resolve-Path 'apps/desktop/dist/win-unpacked').Path + '\'
[xml]$sourceXml = Get-Content -Raw -Encoding UTF8 $Source
$ns = New-Object System.Xml.XmlNamespaceManager($sourceXml.NameTable)
$ns.AddNamespace('w', 'http://wixtoolset.org/schemas/v4/wxs')
$sources = @{}
foreach ($file in $sourceXml.SelectNodes('//w:File', $ns)) {
    if (-not $file.Source.StartsWith($payload, [StringComparison]::OrdinalIgnoreCase)) { throw 'File outside payload' }
    $sources[$file.Id] = $file.Source.Substring($payload.Length).Replace('\', '/')
}
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase((Resolve-Path $Msi).Path, 0)
$view = $database.OpenView('SELECT `File`, `Version` FROM `File`')
$view.Execute()
$checked = 0
while ($record = $view.Fetch()) {
    $id = $record.StringData(1)
    if (-not $sources.ContainsKey($id)) { throw "Unknown MSI payload file: $id" }
    $relative = $sources[$id]
    $entry = $expected.file_versions.PSObject.Properties[$relative]
    $version = if ($entry) { $entry.Value.version } else { '' }
    if ($record.StringData(2) -ne $version) { throw "MSI File.Version differs from PE resource: $relative" }
    $checked++
}
$view.Close()
if ($checked -ne $sources.Count) { throw 'Incomplete MSI File table' }
$view = $database.OpenView('SELECT `Value` FROM `Property` WHERE `Property` = ''ProductName''')
$view.Execute()
if ($view.Fetch().StringData(1) -ne $expected.product_name) { throw 'Wrong MSI product name' }
$view.Close()
Write-Output "PASS: compiled MSI name and all $checked file-version entries match the payload"

$view = $database.OpenView('SELECT `Target` FROM `Shortcut` WHERE `Shortcut` = ''StartShortcut''')
$view.Execute()
if ($view.Fetch().StringData(1) -ne '[#ClientUI]') { throw 'Shortcut must directly reference the installed UI file' }
$view.Close()
$view = $database.OpenView('SELECT `Value` FROM `Property` WHERE `Property` = ''DISABLEADVTSHORTCUTS''')
$view.Execute()
if ($view.Fetch().StringData(1) -ne '1') { throw 'Installer shortcut repair must be disabled' }
$view.Close()

# Validate the compiled service contract, including compilers that have different defaults.
$view = $database.OpenView('SELECT `Name`, `ErrorControl`, `Arguments` FROM `ServiceInstall`')
$view.Execute()
$service = $view.Fetch()
if (-not $service -or $service.StringData(1) -ne 'LineVPN' -or ($service.IntegerData(2) -band 32768) -eq 0 -or $service.StringData(3) -ne '-service') { throw 'MSI must install a mandatory LineVPN service' }
if ($view.Fetch()) { throw 'Unexpected extra service in MSI' }
$view.Close()
$view = $database.OpenView('SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`')
$view.Execute()
$actions = @{}
while ($record = $view.Fetch()) { $actions[$record.StringData(1)] = @{ Condition=$record.StringData(2); Sequence=$record.IntegerData(3) } }
$view.Close()
if (-not $actions.ContainsKey('CheckServiceReady') -or $actions.CheckServiceReady.Sequence -le $actions.StartServices.Sequence -or $actions.CheckServiceReady.Sequence -ge $actions.InstallFinalize.Sequence) { throw 'Missing transactional service readiness check' }
if ($actions.CheckServiceReady.Condition -ne 'NOT REMOVE AND NOT UPGRADINGPRODUCTCODE') { throw 'Readiness must not run during removal' }
Write-Output 'PASS: compiled MSI requires service registration and readiness before commit'

if ($actions.RemoveClientState.Sequence -le $actions.StopServices.Sequence -or $actions.RemoveClientState.Sequence -ge $actions.RemoveFiles.Sequence) { throw 'Removal must clear state after stop, before deleting payload' }
if ($actions.PrepareCleanInstall.Sequence -ge $actions.RollbackCleanInstall.Sequence -or $actions.RollbackCleanInstall.Sequence -ge $actions.InstallFiles.Sequence) { throw 'Invalid fresh-install/rollback order' }
$view = $database.OpenView('SELECT `Source`, `Type` FROM `CustomAction` WHERE `Action` = ''RemoveClientState''')
$view.Execute()
$cleanup = $view.Fetch()
if ($cleanup.StringData(1) -ne 'InstallerAgent' -or ($cleanup.IntegerData(2) -band 63) -ne 2) { throw 'Uninstall must use the embedded executable' }
$view.Close()
Write-Output 'PASS: cached MSI owns removal helper and orders cleanup safely'
