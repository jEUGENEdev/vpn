#!/usr/bin/env python3
"""Stage the single macOS installer app; native recipe supplies its launcher."""
import pathlib
import plistlib
import shutil
import sys

from package_version import ROOT, product_version

payloads, app = map(pathlib.Path, sys.argv[1:])
resources = app / 'Contents/Resources'
resources.mkdir(parents=True)
(app / 'Contents/MacOS').mkdir()
for arch in ('arm64', 'x64'):
    for name in (f'payload-{arch}.pkg', f'recovery-{arch}'):
        shutil.copy2(payloads / name, resources / name)
    (resources / f'recovery-{arch}').chmod(0o755)
for name in ('installer.applescript', 'manage.sh', 'uninstall.sh', 'stop-service.sh'):
    shutil.copy2(ROOT / 'packaging/macos' / name, resources / name)
shutil.copy2(ROOT / 'apps/desktop/branding/set.icns', resources / 'set.icns')
(app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
    'CFBundleIdentifier': 'dev.linevpn.installer',
    'CFBundleName': 'Установщик Сеть',
    'CFBundleDisplayName': 'Установщик Сеть',
    'CFBundleExecutable': 'SetSetup',
    'CFBundlePackageType': 'APPL',
    'CFBundleShortVersionString': product_version(),
    'CFBundleVersion': product_version(),
    'CFBundleIconFile': 'set.icns',
    'LSMinimumSystemVersion': '12.0',
    'LSUIElement': True,
    'NSHighResolutionCapable': True,
}))
