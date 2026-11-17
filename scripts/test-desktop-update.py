#!/usr/bin/env python3
"""Native reinstall/major-upgrade acceptance on disposable CI hosts only."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('installer', type=pathlib.Path)
args = parser.parse_args()
assert os.environ.get('GITHUB_ACTIONS') == 'true', 'Use a disposable CI host'
system = platform.system()
assert system in ('Darwin', 'Windows'), 'Native Windows/macOS required'
ROOT = pathlib.Path(__file__).resolve().parents[1]
os.chdir(ROOT)
installer = args.installer.resolve()
data = pathlib.Path('/var/lib/linevpn') if system == 'Darwin' else pathlib.Path(os.environ['PROGRAMDATA']) / 'LineVPN'
token = (data / 'ui-token').read_text().strip()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(body=None):
    request = urllib.request.Request('http://127.0.0.1:17891/local/' + ('vpn' if body is not None else 'state'),
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    with opener.open(request, timeout=5) as response:
        return json.load(response)


def ready(enabled):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            state = api()
            if not state.get('power_transition') and state['vpn_enabled'] == enabled:
                assert not state.get('power_error')
                return state
        except (OSError, ValueError):
            pass
        time.sleep(.25)
    raise AssertionError('Service did not resume with the preserved VPN setting')


def install(path, repair=False):
    if system == 'Darwin':
        command = ['/usr/sbin/installer', '-pkg', str(path), '-target', '/']
    else:
        command = ['msiexec.exe', '/fa' if repair else '/i', str(path), '/qn', '/norestart', '/l*v', str(ROOT / 'build/windows-update.log')]
    result = subprocess.run(command, timeout=240, stdout=subprocess.DEVNULL)
    assert result.returncode in (0, 3010), f'Installer failed: {result.returncode}'
    ready(False)
    for name, digest in before.items():
        assert hashlib.sha256((data / name).read_bytes()).hexdigest() == digest, f'Update changed {name}'
    state = api()
    for field in ('device_id', 'account_id', 'login', 'rules', 'pending_protection'):
        assert state.get(field) == saved_state.get(field), f'Update reset {field}'


was_enabled = api()['vpn_enabled']
api({'enabled': False, 'confirm': True})
saved_state = ready(False)
before = {name: hashlib.sha256((data / name).read_bytes()).hexdigest()
          for name in ('profile.json', 'applications.json', 'ui-token')}
if system == 'Darwin':
    # Run Installer twice; preinstall must stop the service started by each run.
    install(installer)
    install(installer)
else:
    install(installer, repair=True)
    # A higher version changes ProductCode and exercises MajorUpgrade,
    # file replacement and removal of files owned by the previous MSI.
    with tempfile.TemporaryDirectory(prefix='linevpn-upgrade-') as temp:
        work = pathlib.Path(temp)
        payload = work / 'payload'
        shutil.copytree(ROOT / 'apps/desktop/dist/win-unpacked', payload)
        (payload / 'upgrade-fixture.txt').write_text('new package payload')
        fixture = work / 'upgrade.msi'
        from package_version import product_version, version_parts
        major, minor, patch = version_parts(product_version())
        fixture_version = f'{major}.{minor}.{patch + 1}' if patch < 999 else f'{major}.{minor + 1}.0'
        subprocess.run([sys.executable, 'packaging/windows/package.py', str(payload), str(work / 'upgrade.wxs'), '--version', fixture_version], check=True)
        subprocess.run(['wix', 'build', str(work / 'upgrade.wxs'), '-arch', 'x64', '-o', str(fixture)], check=True)
        installed = pathlib.Path(os.environ['ProgramFiles']) / 'LineVPN'
        try:
            install(fixture)
            assert (installed / 'upgrade-fixture.txt').read_text() == 'new package payload'
            # Return to the released version only after explicit fixture removal.
            removed = subprocess.run(['msiexec.exe', '/x', str(fixture), '/qn', '/norestart'], timeout=240)
            assert removed.returncode in (0, 3010)
            install(installer)
            assert not (installed / 'upgrade-fixture.txt').exists(), 'Previous MSI files survived upgrade'
            for path in ('resources/app.asar', 'resources/agent/linevpn-agent.exe'):
                assert hashlib.sha256((installed / path).read_bytes()).digest() == hashlib.sha256((payload / path).read_bytes()).digest()
        except BaseException:
            subprocess.run(['msiexec.exe', '/x', str(fixture), '/qn', '/norestart'], timeout=240)
            raise
if was_enabled:
    api({'enabled': True})
    ready(True)
print('PASS: native repeated installation, data/identity preservation and service restart')
