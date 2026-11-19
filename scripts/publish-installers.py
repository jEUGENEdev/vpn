"""Publish only a complete four-installer set; never create placeholder binaries."""
import hashlib,json,os,pathlib,shutil,sys,datetime
from package_version import product_version, android_code, check_newer
from verify_android_update import expected_certificate
check_newer()
version = product_version()
certificate = expected_certificate()
source,dest=map(pathlib.Path,sys.argv[1:]);files=sorted(p for p in source.iterdir() if p.suffix in {'.apk','.dmg','.msi'})
if len([p for p in files if p.suffix=='.apk'])!=1 or len([p for p in files if p.suffix=='.msi'])!=1 or len([p for p in files if p.suffix=='.dmg'])!=2:raise SystemExit('A complete APK + MSI + two DMG set is required')
# Verify the actual APK again before replacing published files.
from verify_android_update import check_apk
check_apk(next(p for p in files if p.suffix == '.apk'))
manifest={'version':version+'-preview','android_version_code':android_code(version),'android_certificate_sha256':certificate,'source_commit':os.environ['SOURCE_COMMIT'],'built_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'preview-native-acceptance-required','signing':{'android':'persistent certificate verified against the pinned identity; see docs/android-signing.md for legacy migration','macos':'ad-hoc signed app and agent; not Apple notarized; PKG unsigned','windows':'not Authenticode signed'},'files':[]}
# Reject invalid artifacts before touching the existing published set.
for p in files:
 if p.stat().st_size<100000:raise SystemExit(f'Not a plausible installer: {p}')
dest.mkdir(parents=True,exist_ok=True)
for old in dest.iterdir():
 if old.suffix in {'.apk','.msi','.dmg'}:old.unlink()
checks=[]
for p in files:
 digest=hashlib.sha256(p.read_bytes()).hexdigest();shutil.copy2(p,dest/p.name);checks.append(f'{digest}  {p.name}')
 manifest['files'].append({'name':p.name,'size':p.stat().st_size,'sha256':digest})
(dest/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(dest/'SHA256SUMS').write_text('\n'.join(checks)+'\n')
