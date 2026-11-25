"""Generate WiX v4 package with a real, automatically installed Windows service."""
import argparse, pathlib, uuid, xml.etree.ElementTree as ET, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from package_version import product_version, version_parts
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('payload', type=pathlib.Path)
parser.add_argument('output', type=pathlib.Path)
parser.add_argument('--version', help='Version override for related-package rejection fixtures')
args = parser.parse_args()
version = args.version or product_version()
version_parts(version)
root=args.payload.resolve(); out=args.output
for required in ('Сеть.exe', 'resources/agent/linevpn-agent.exe'):
 if not (root / required).is_file(): parser.error('Missing payload file: ' + required)
out.parent.mkdir(parents=True, exist_ok=True)
ns='http://wixtoolset.org/schemas/v4/wxs'; ET.register_namespace('',ns)
def node(parent,tag,**attrs):return ET.SubElement(parent,'{'+ns+'}'+tag,attrs)
# Stable identity for uninstall; reinstall requires explicit removal first.
product_code = str(uuid.uuid5(uuid.NAMESPACE_URL, 'dev.linevpn.windows.x64:' + version))
w=ET.Element('{'+ns+'}Wix'); p=node(w,'Package',Name='Сеть',Manufacturer='jEUGENEdev',Version=version,ProductCode=product_code,UpgradeCode='{0ACF9EA2-83F8-4EE0-8877-E3BAE8A42E91}',Scope='perMachine',InstallerVersion='500',Codepage='1251',Language='1049')
node(p,'Icon',Id='SetIcon',SourceFile=str(pathlib.Path(__file__).resolve().parents[2] / 'apps/desktop/branding/set.ico'))
node(p,'Property',Id='ARPPRODUCTICON',Value='SetIcon')
node(p,'Property',Id='ARPNOMODIFY',Value='1')
node(p,'Property',Id='ARPNOREPAIR',Value='1')
node(p,'Property',Id='DISABLEADVTSHORTCUTS',Value='1')
node(p,'Property',Id='MsiLogging',Value='voicewarmup')
# Populate related-product detection; Launch below rejects replacement in place.
node(p,'MajorUpgrade',DowngradeErrorMessage='Установлена более новая версия приложения «Сеть».',Schedule='afterInstallInitialize');node(p,'MediaTemplate',EmbedCab='yes',CompressionLevel='high')
# ARPNOREPAIR only hides the button. Reject command-line repair and repeated
# /i before any service or file changes, including upgrades of legacy products.
node(p,'Launch',Condition='REMOVE~="ALL" OR (NOT Installed AND NOT WIX_UPGRADE_DETECTED AND NOT REINSTALL)',Message='Сначала удалите «Сеть» в параметрах Windows / Приложения. Затем запустите установку заново. Локальные настройки и вход будут удалены; понадобятся профиль сервера и ключ доступа.')
program=node(p,'StandardDirectory',Id='ProgramFiles64Folder');install=node(program,'Directory',Id='INSTALLFOLDER',Name='LineVPN')
feature=node(p,'Feature',Id='Main',Title='Сеть',Level='1',AllowAdvertise='no');dirs={pathlib.Path('.'):install}
for i,file in enumerate(sorted(root.rglob('*'))):
 if not file.is_file():continue
 rel=file.relative_to(root); parent=rel.parent
 for depth in range(1,len(parent.parts)+1):
  d=pathlib.Path(*parent.parts[:depth])
  if d not in dirs:dirs[d]=node(dirs[d.parent],'Directory',Id='D'+uuid.uuid5(uuid.NAMESPACE_URL,str(d)).hex,Name=d.name)
 cid='C'+uuid.uuid5(uuid.NAMESPACE_URL,rel.as_posix()).hex
 c=node(dirs[parent],'Component',Id=cid,Guid=str(uuid.uuid5(uuid.NAMESPACE_URL,'linevpn:'+rel.as_posix())),Bitness='always64')
 fid='Agent' if rel.as_posix()=='resources/agent/linevpn-agent.exe' else ('ClientUI' if rel.as_posix()=='Сеть.exe' else 'F'+str(i))
 node(c,'File',Id=fid,Source=str(file),KeyPath='yes')
 if fid=='Agent':
  agent_component=c
  node(c,'ServiceInstall',Id='InstallAgent',Name='LineVPN',DisplayName='Сеть',Description='VPN routing with protection until explicit off',Type='ownProcess',Start='auto',ErrorControl='normal',Vital='yes',Account='LocalSystem',Arguments='-service')
  node(c,'ServiceControl',Id='ControlAgent',Name='LineVPN',Start='install',Stop='both',Remove='uninstall',Wait='yes')
 node(feature,'ComponentRef',Id=cid)
# Explicitly remove every empty payload directory on uninstall. Unrelated
# files prevent removal; no wildcard deletion is scheduled by Windows Installer.
for directory, element in sorted(dirs.items(), key=lambda pair: len(pair[0].parts), reverse=True):
 node(agent_component,'RemoveFolder',Id='R'+uuid.uuid5(uuid.NAMESPACE_URL,directory.as_posix()).hex,Directory=element.get('Id'),On='uninstall')
# The shortcut has its own component and registry key path for clean removal.
# Do not remove generic Electron shortcuts belonging to other applications.
programmenu=node(p,'StandardDirectory',Id='ProgramMenuFolder')
c=node(programmenu,'Component',Id='SetStartMenuShortcut',Guid=str(uuid.uuid5(uuid.NAMESPACE_URL,'dev.linevpn.windows.shortcut:ProgramMenuFolder/Сеть.lnk')),Bitness='always64')
node(c,'Shortcut',Id='StartShortcut',Name='Сеть',Target='[#ClientUI]',Advertise='no',Icon='SetIcon',IconIndex='0',WorkingDirectory='INSTALLFOLDER')
node(c,'RegistryValue',Root='HKLM',Key='Software\\LineVPN\\Installer',Name='StartMenuShortcut',Type='integer',Value='1',KeyPath='yes')
node(c,'RegistryValue',Root='HKLM',Key='Software\\LineVPN\\Installer',Name='DesktopOperatorSID',Type='string',Value='[UserSID]')
node(feature,'ComponentRef',Id='SetStartMenuShortcut')
# The cached MSI owns an independent copy. A missing installed executable must
# not make explicit uninstall impossible or strand the persistent WFP filters.
node(p,'Binary',Id='InstallerAgent',SourceFile=str(root / 'resources/agent/linevpn-agent.exe'))
node(p,'CustomAction',Id='RemoveClientState',BinaryRef='InstallerAgent',ExeCommand='-uninstall-state',Execute='deferred',Impersonate='no',Return='check')
node(p,'CustomAction',Id='RollbackCleanInstall',BinaryRef='InstallerAgent',ExeCommand='-uninstall-state',Execute='rollback',Impersonate='no',Return='check')
node(p,'CustomAction',Id='PrepareCleanInstall',BinaryRef='InstallerAgent',ExeCommand='-prepare-install',Execute='deferred',Impersonate='no',Return='check')
node(p,'CustomAction',Id='CheckServiceReady',FileRef='Agent',ExeCommand='-check-service',Execute='deferred',Impersonate='no',Return='check')
sequence=node(p,'InstallExecuteSequence')
node(sequence,'Custom',Action='RollbackCleanInstall',Before='InstallFiles',Condition='NOT Installed AND NOT REMOVE')
node(sequence,'Custom',Action='PrepareCleanInstall',Before='RollbackCleanInstall',Condition='NOT Installed AND NOT REMOVE')
node(sequence,'Custom',Action='CheckServiceReady',After='StartServices',Condition='NOT REMOVE AND NOT UPGRADINGPRODUCTCODE')
node(sequence,'Custom',Action='RemoveClientState',After='StopServices',Condition='REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE')
out.write_bytes(ET.tostring(w,encoding='utf-8',xml_declaration=True))
