"""Check shipped branding and stable upgrade identity in generated packages."""
import json, pathlib, subprocess, tempfile, xml.etree.ElementTree as ET
root=pathlib.Path(__file__).resolve().parents[1]
pkg=json.loads((root/'apps/desktop/package.json').read_text())
assert pkg['build']['productName']=='Сеть'
assert pkg['build']['appId']=='dev.linevpn.desktop'
assert pkg['build']['executableName']=='LineVPN'
assert 'control.cjs' in pkg['build']['files'] and 'branding/*.png' in pkg['build']['files']
for key,magic in [('mac',b'icns'),('win',b'\x00\x00\x01\x00')]:
 asset=root/'apps/desktop'/pkg['build'][key]['icon']
 assert asset.read_bytes().startswith(magic), asset
assert (root/'apps/desktop/branding/set.png').read_bytes().startswith(b'\x89PNG')
manifest=ET.parse(root/'apps/android/app/src/main/AndroidManifest.xml').getroot().find('application')
ns='{http://schemas.android.com/apk/res/android}'
assert manifest.get(ns+'label')=='Сеть' and manifest.get(ns+'icon')=='@mipmap/ic_set'
for p in (root/'internal/ui/client/index.html',root/'internal/ui/admin/index.html'):
 s=p.read_text();assert 'Сеть' in s and 'Линия' not in s and 'icon.png' in s
with tempfile.TemporaryDirectory() as d:
 payload=pathlib.Path(d)/'payload';(payload/'resources/agent').mkdir(parents=True)
 (payload/'LineVPN.exe').write_bytes(b'fixture');(payload/'resources/agent/linevpn-agent.exe').write_bytes(b'fixture')
 out=pathlib.Path(d)/'package.wxs'
 subprocess.run(['python3',str(root/'packaging/windows/package.py'),str(payload),str(out)],check=True)
 tree=ET.parse(out);ns={'w':'http://wixtoolset.org/schemas/v4/wxs'}
 p=tree.find('w:Package',ns);assert p.get('Name')=='Сеть' and p.get('UpgradeCode')=='{0ACF9EA2-83F8-4EE0-8877-E3BAE8A42E91}'
 assert tree.find('.//w:ServiceInstall',ns).get('Name')=='LineVPN'
 assert tree.find('.//w:ServiceInstall',ns).get('DisplayName')=='Сеть'
 assert tree.find('.//w:Shortcut',ns).get('Icon')=='SetIcon'
print('PASS: Сеть branding, native icon containers and stable installer identity')
