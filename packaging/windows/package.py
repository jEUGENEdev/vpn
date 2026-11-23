"""Generate WiX v4 package with a real, automatically installed Windows service."""
import argparse, pathlib, uuid, xml.etree.ElementTree as ET, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from package_version import product_version, version_parts
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('payload', type=pathlib.Path)
parser.add_argument('output', type=pathlib.Path)
parser.add_argument('--version', help='Version override for upgrade fixtures only')
args = parser.parse_args()
version = args.version or product_version()
version_parts(version)
root=args.payload.resolve(); out=args.output
for required in ('LineVPN.exe', 'resources/agent/linevpn-agent.exe'):
 if not (root / required).is_file(): parser.error('Missing payload file: ' + required)
out.parent.mkdir(parents=True, exist_ok=True)
ns='http://wixtoolset.org/schemas/v4/wxs'; ET.register_namespace('',ns)
def node(parent,tag,**attrs):return ET.SubElement(parent,'{'+ns+'}'+tag,attrs)
# The same release is maintenance/repair; a new version gets a new ProductCode.
product_code = str(uuid.uuid5(uuid.NAMESPACE_URL, 'dev.linevpn.windows.x64:' + version))
w=ET.Element('{'+ns+'}Wix'); p=node(w,'Package',Name='Сеть',Manufacturer='jEUGENEdev',Version=version,ProductCode=product_code,UpgradeCode='{0ACF9EA2-83F8-4EE0-8877-E3BAE8A42E91}',Scope='perMachine',InstallerVersion='500',Codepage='1251',Language='1049')
node(p,'Icon',Id='SetIcon',SourceFile=str(pathlib.Path(__file__).resolve().parents[2] / 'apps/desktop/branding/set.ico'))
node(p,'Property',Id='ARPPRODUCTICON',Value='SetIcon')
# Remove the previous product inside the transaction so a failed upgrade rolls back.
node(p,'MajorUpgrade',DowngradeErrorMessage='Установлена более новая версия приложения «Сеть».',Schedule='afterInstallInitialize');node(p,'MediaTemplate',EmbedCab='yes',CompressionLevel='high')
# Opening the SAME MSI again repairs the existing product, including unversioned
# Go/JS files. Explicit removal and major-upgrade removal never enter this path.
node(p,'SetProperty',Id='REINSTALL',Value='ALL',Before='CostInitialize',Sequence='both',Condition='Installed AND NOT REMOVE AND NOT UPGRADINGPRODUCTCODE AND NOT REINSTALL')
# A major upgrade has a new ProductCode, so Installed is false. Replace our
# payload even when an old preview retained Electron's higher EXE version or
# an MSI omitted file-version metadata. Also refresh shortcuts and icon cache.
# Do not set REINSTALL=ALL for a new product: it would skip initial installation.
node(p,'SetProperty',Id='REINSTALLMODE',Value='amus',Before='CostInitialize',Sequence='both',Condition='NOT REMOVE AND NOT UPGRADINGPRODUCTCODE AND NOT REINSTALLMODE')
program=node(p,'StandardDirectory',Id='ProgramFiles64Folder');install=node(program,'Directory',Id='INSTALLFOLDER',Name='LineVPN')
feature=node(p,'Feature',Id='Main',Title='Сеть',Level='1');dirs={pathlib.Path('.'):install}
for i,file in enumerate(sorted(root.rglob('*'))):
 if not file.is_file():continue
 rel=file.relative_to(root); parent=rel.parent
 for depth in range(1,len(parent.parts)+1):
  d=pathlib.Path(*parent.parts[:depth])
  if d not in dirs:dirs[d]=node(dirs[d.parent],'Directory',Id='D'+uuid.uuid5(uuid.NAMESPACE_URL,str(d)).hex,Name=d.name)
 cid='C'+uuid.uuid5(uuid.NAMESPACE_URL,rel.as_posix()).hex
 c=node(dirs[parent],'Component',Id=cid,Guid=str(uuid.uuid5(uuid.NAMESPACE_URL,'linevpn:'+rel.as_posix())),Bitness='always64')
 fid='Agent' if rel.as_posix()=='resources/agent/linevpn-agent.exe' else 'F'+str(i)
 node(c,'File',Id=fid,Source=str(file),KeyPath='yes')
 if fid=='Agent':
  node(c,'ServiceInstall',Id='InstallAgent',Name='LineVPN',DisplayName='Сеть',Description='VPN routing with protection until explicit off',Type='ownProcess',Start='auto',ErrorControl='normal',Account='LocalSystem',Arguments='-service')
  node(c,'ServiceControl',Id='ControlAgent',Name='LineVPN',Start='install',Stop='both',Remove='uninstall',Wait='yes')
 node(feature,'ComponentRef',Id=cid)
# A new shortcut location needs its own component and registry key path. The
# old MSI removes its registered menu folder during the transactional upgrade.
# Do not remove generic Electron shortcuts belonging to other applications.
programmenu=node(p,'StandardDirectory',Id='ProgramMenuFolder')
c=node(programmenu,'Component',Id='SetStartMenuShortcut',Guid=str(uuid.uuid5(uuid.NAMESPACE_URL,'dev.linevpn.windows.shortcut:ProgramMenuFolder/Сеть.lnk')),Bitness='always64')
node(c,'Shortcut',Id='StartShortcut',Name='Сеть',Target='[INSTALLFOLDER]LineVPN.exe',Icon='SetIcon',IconIndex='0',WorkingDirectory='INSTALLFOLDER')
node(c,'RegistryValue',Root='HKLM',Key='Software\\LineVPN\\Installer',Name='StartMenuShortcut',Type='integer',Value='1',KeyPath='yes')
node(feature,'ComponentRef',Id='SetStartMenuShortcut')
# Run elevated after the service stops but BEFORE deleting its executable.
# A cleanup failure aborts removal, leaving the recovery tool available.
node(p,'CustomAction',Id='RecoverNetwork',FileRef='Agent',ExeCommand='-recover-network',Execute='deferred',Impersonate='no',Return='check')
sequence=node(p,'InstallExecuteSequence')
# An upgrade is not an explicit request to switch protected traffic to direct.
node(sequence,'Custom',Action='RecoverNetwork',After='StopServices',Condition='REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE')
out.write_bytes(ET.tostring(w,encoding='utf-8',xml_declaration=True))
