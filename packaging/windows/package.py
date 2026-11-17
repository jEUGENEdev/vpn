"""Generate WiX v4 package with a real, automatically installed Windows service."""
import pathlib, uuid, xml.etree.ElementTree as ET, sys
root=pathlib.Path(sys.argv[1]).resolve(); out=pathlib.Path(sys.argv[2])
out.parent.mkdir(parents=True, exist_ok=True)
ns='http://wixtoolset.org/schemas/v4/wxs'; ET.register_namespace('',ns)
def node(parent,tag,**attrs):return ET.SubElement(parent,'{'+ns+'}'+tag,attrs)
w=ET.Element('{'+ns+'}Wix'); p=node(w,'Package',Name='LineVPN',Manufacturer='jEUGENEdev',Version='0.2.0',UpgradeCode='{0ACF9EA2-83F8-4EE0-8877-E3BAE8A42E91}',Scope='perMachine',InstallerVersion='500',Codepage='1251',Language='1049')
node(p,'MajorUpgrade',DowngradeErrorMessage='A newer LineVPN version is installed.',AllowSameVersionUpgrades='yes');node(p,'MediaTemplate',EmbedCab='yes',CompressionLevel='high')
program=node(p,'StandardDirectory',Id='ProgramFiles64Folder');install=node(program,'Directory',Id='INSTALLFOLDER',Name='LineVPN')
feature=node(p,'Feature',Id='Main',Title='LineVPN',Level='1');dirs={pathlib.Path('.'):install}
for i,file in enumerate(sorted(root.rglob('*'))):
 if not file.is_file():continue
 rel=file.relative_to(root); parent=rel.parent
 for depth in range(1,len(parent.parts)+1):
  d=pathlib.Path(*parent.parts[:depth])
  if d not in dirs:dirs[d]=node(dirs[d.parent],'Directory',Id='D'+uuid.uuid5(uuid.NAMESPACE_URL,str(d)).hex,Name=d.name)
 cid='C'+uuid.uuid5(uuid.NAMESPACE_URL,rel.as_posix()).hex
 c=node(dirs[parent],'Component',Id=cid,Guid=str(uuid.uuid5(uuid.NAMESPACE_URL,'linevpn:'+rel.as_posix())),Bitness='always64')
 fid='Agent' if file.name=='linevpn-agent.exe' else 'F'+str(i)
 node(c,'File',Id=fid,Source=str(file),KeyPath='yes')
 if fid=='Agent':
  node(c,'ServiceInstall',Id='InstallAgent',Name='LineVPN',DisplayName='Линия VPN',Description='VPN routing with automatic direct network fallback',Type='ownProcess',Start='auto',ErrorControl='normal',Account='LocalSystem',Arguments='-service')
  node(c,'ServiceControl',Id='ControlAgent',Name='LineVPN',Start='install',Stop='both',Remove='uninstall',Wait='yes')
 node(feature,'ComponentRef',Id=cid)
programmenu=node(p,'StandardDirectory',Id='ProgramMenuFolder');folder=node(programmenu,'Directory',Id='LineMenu',Name='LineVPN');c=node(folder,'Component',Id='Shortcut',Guid='{9A5D6DC0-5C93-4DC6-82BC-9857E58B9B20}')
node(c,'Shortcut',Id='StartShortcut',Name='Линия VPN',Target='[INSTALLFOLDER]LineVPN.exe',WorkingDirectory='INSTALLFOLDER');node(c,'RemoveFolder',Id='RemoveShortcutFolder',On='uninstall');node(c,'RegistryValue',Root='HKLM',Key='Software\\LineVPN',Name='installed',Type='integer',Value='1',KeyPath='yes');node(feature,'ComponentRef',Id='Shortcut')
# Run elevated after the service stops but BEFORE deleting its executable.
# A cleanup failure aborts removal, leaving the recovery tool available.
node(p,'CustomAction',Id='RecoverNetwork',FileRef='Agent',ExeCommand='-recover-network',Execute='deferred',Impersonate='no',Return='check')
sequence=node(p,'InstallExecuteSequence')
node(sequence,'Custom',Action='RecoverNetwork',After='StopServices',Condition='REMOVE~="ALL"')
out.write_bytes(ET.tostring(w,encoding='utf-8',xml_declaration=True))
