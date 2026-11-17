"""Publish only a complete four-installer set; never create placeholder binaries."""
import hashlib,json,os,pathlib,shutil,sys,datetime
source,dest=map(pathlib.Path,sys.argv[1:]);files=sorted(p for p in source.iterdir() if p.suffix in {'.apk','.dmg','.msi'})
if len([p for p in files if p.suffix=='.apk'])!=1 or len([p for p in files if p.suffix=='.msi'])!=1 or len([p for p in files if p.suffix=='.dmg'])!=2:raise SystemExit('A complete APK + MSI + two DMG set is required')
# Recheck the APK at the publication boundary, including for manual callers.
import subprocess
root = pathlib.Path(__file__).resolve().parents[1]
metadata = json.loads((root / 'apps/desktop/package.json').read_text())
apk = next(p for p in files if p.suffix == '.apk')
subprocess.run([sys.executable, str(root / 'scripts/verify-android-update.py'), str(apk)], check=True)
manifest={'version':metadata['version']+'-preview','android_version_code':metadata['linevpn']['androidVersionCode'],'android_certificate_sha256':metadata['linevpn']['androidCertificateSha256'],'source_commit':os.environ['SOURCE_COMMIT'],'built_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'preview-native-acceptance-required','signing':{'android':'pinned preview certificate verified; not a production release key','macos':'ad-hoc signed app and agent; not Apple notarized; PKG unsigned','windows':'not Authenticode signed'},'files':[]}
dest.mkdir(parents=True,exist_ok=True)
for old in dest.iterdir():
 if old.suffix in {'.apk','.msi','.dmg'}:old.unlink()
checks=[]
for p in files:
 if p.stat().st_size<100000:raise SystemExit(f'Not a plausible installer: {p}')
 digest=hashlib.sha256(p.read_bytes()).hexdigest();shutil.copy2(p,dest/p.name);checks.append(f'{digest}  {p.name}')
 manifest['files'].append({'name':p.name,'size':p.stat().st_size,'sha256':digest})
(dest/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(dest/'SHA256SUMS').write_text('\n'.join(checks)+'\n')
