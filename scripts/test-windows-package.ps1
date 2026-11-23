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
