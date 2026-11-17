#!/usr/bin/env python3
"""Installer contract tests and isolated execution of macOS lifecycle hooks.

The macOS command doubles exercise failure/order handling, not native launchd.
Native MSI/PKG/APK reinstall checks also live in test-{windows,macos,android}.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
META = json.loads((ROOT / 'apps/desktop/package.json').read_text())
NS = {'w': 'http://wixtoolset.org/schemas/v4/wxs'}
spec = importlib.util.spec_from_file_location('android_update', ROOT / 'scripts/verify-android-update.py')
android = importlib.util.module_from_spec(spec)
spec.loader.exec_module(android)


class WindowsUpdate(unittest.TestCase):
    def test_old_and_new_package_share_identity_but_upgrade_transactionally(self):
        with tempfile.TemporaryDirectory() as temp:
            work = pathlib.Path(temp)
            payload = work / 'payload'
            (payload / 'resources/agent').mkdir(parents=True)
            for path in ('LineVPN.exe', 'resources/app.asar', 'resources/agent/linevpn-agent.exe'):
                (payload / path).write_text('old payload')
            def generate(name, *args):
                output = work / name
                subprocess.run([sys.executable, str(ROOT / 'packaging/windows/package.py'), str(payload), str(output), *args], check=True)
                return ET.parse(output)
            old = generate('old.wxs', '--version', '0.2.0')
            (payload / 'resources/app.asar').write_text('updated payload')
            new = generate('new.wxs')
            a, b = [tree.find('w:Package', NS) for tree in (old, new)]
            self.assertEqual(a.attrib['UpgradeCode'], b.attrib['UpgradeCode'])
            self.assertEqual(b.attrib['UpgradeCode'], '{0ACF9EA2-83F8-4EE0-8877-E3BAE8A42E91}')
            self.assertEqual(b.attrib['Version'], META['version'])
            self.assertNotEqual(a.attrib['Version'], b.attrib['Version'])
            self.assertEqual({c.attrib['Id']: c.attrib['Guid'] for c in old.findall('.//w:Component', NS)},
                             {c.attrib['Id']: c.attrib['Guid'] for c in new.findall('.//w:Component', NS)})
            upgrade = new.find('.//w:MajorUpgrade', NS)
            self.assertEqual(upgrade.attrib['Schedule'], 'afterInstallInitialize')
            self.assertNotEqual(upgrade.get('AllowDowngrades'), 'yes')
            self.assertEqual(upgrade.get('AllowSameVersionUpgrades'), 'yes')
            self.assertEqual(len(new.findall('.//w:ServiceInstall', NS)), 1)
            self.assertFalse(new.findall('.//w:RemoveFile', NS), 'profile cleanup must not be packaged')
            self.assertNotIn('CommonAppDataFolder', ET.tostring(b).decode())
            for version in ('0.2.1.4', '0.2.preview', '256.0.0', '0.2.65536'):
                result = subprocess.run([sys.executable, str(ROOT / 'packaging/windows/package.py'), str(payload), str(work / 'bad.wxs'), '--version', version], capture_output=True)
                self.assertNotEqual(result.returncode, 0)

    def test_release_metadata_matches_npm_lock(self):
        lock = json.loads((ROOT / 'apps/desktop/package-lock.json').read_text())
        self.assertEqual(META['version'], lock['version'])
        self.assertEqual(META['version'], lock['packages']['']['version'])


class AndroidUpdate(unittest.TestCase):
    def info(self):
        return dict(application_id='dev.linevpn.app', version_code=META['linevpn']['androidVersionCode'],
                    version_name=META['version'] + '-preview', certificate_sha256=META['linevpn']['androidCertificateSha256'])

    def test_same_identity_updates_and_reinstalls(self):
        old = dict(self.info(), version_code=2, version_name='0.2.0-preview')
        android.validate(self.info(), META, old)
        android.validate(self.info(), META, self.info())

    def test_wrong_key_package_or_version_is_rejected(self):
        for field, value in [('certificate_sha256', 'a' * 64), ('application_id', 'dev.linevpn.other'),
                             ('version_code', 2), ('version_name', '0.2.0-preview')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                android.validate(dict(self.info(), **{field: value}), META)
        with self.assertRaises(ValueError):
            android.validate(self.info(), META, dict(self.info(), version_code=999))

    def test_signature_verification_failure_cannot_be_ignored(self):
        with patch.object(android, 'sdk_tool', return_value='apksigner'), patch.object(android.subprocess, 'check_output', side_effect=subprocess.CalledProcessError(1, 'apksigner')):
            with self.assertRaises(subprocess.CalledProcessError):
                android.inspect_apk('broken.apk')


class MacLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = pathlib.Path(self.temp.name)
        self.state = self.work / 'state.json'
        self.log = self.work / 'calls.json'
        self.data = self.work / 'data'
        self.data.mkdir()
        self.saved = {'profile.json': b'{"disabled":true,"pinned":["example.com"],"device_id":"existing"}',
                      'applications.json': b'{"trusted":"test-app"}', 'ui-token': b'existing-token'}
        for name, value in self.saved.items():
            (self.data / name).write_bytes(value)
        self.set_state(job=True, worker=True)
        self.log.write_text('[]')
        # Replace only native system commands in a test copy, never the real host.
        source = '''import json, pathlib, sys
base = pathlib.Path(__file__).parent
state = json.loads((base / 'state.json').read_text())
calls = json.loads((base / 'calls.json').read_text())
cmd = pathlib.Path(sys.argv[0]).name
calls.append([cmd, *sys.argv[1:]])
(base / 'calls.json').write_text(json.dumps(calls))
result = 0
if cmd == 'launchctl':
    action = sys.argv[1]
    if action == 'print': result = 0 if state['job'] else 1
    elif action == 'bootout': state['stopping'] = True
    elif action == 'bootstrap':
        result = 1 if state.get('bootstrap_fail') or state['job'] else 0
        if result == 0: state.update(job=True, worker=True, stopping=False)
elif cmd == 'pgrep': result = 0 if state['worker'] else 1
elif cmd == 'sleep' and state.get('stopping') and not state.get('stuck'):
    state['remaining'] -= 1
    if state['remaining'] <= 0: state.update(job=False, worker=False)
(base / 'state.json').write_text(json.dumps(state))
sys.exit(result)
'''
        for name in ('launchctl', 'pgrep', 'sleep', 'id'):
            path = self.work / name
            path.write_text('#!' + sys.executable + '\n' + source)
            path.chmod(0o755)

    def set_state(self, **values):
        self.state.write_text(json.dumps(dict(remaining=2, **values)))

    def run_hook(self, name, target='/'):
        source = (ROOT / 'packaging/macos' / name).read_text()
        for original in ('/bin/launchctl', '/usr/bin/pgrep', '/bin/sleep', '/usr/bin/id'):
            source = source.replace(original, str(self.work / pathlib.Path(original).name))
        source = source.replace('"$EUID"', '"0"').replace('/var/lib/linevpn', str(self.data))
        path = self.work / name
        path.write_text(source)
        return subprocess.run(['bash', str(path), 'package.pkg', '/', target], capture_output=True, text=True, timeout=10)

    def assert_data_preserved(self):
        self.assertEqual({p.name: p.read_bytes() for p in self.data.iterdir()}, self.saved)

    def test_update_and_repeat_stop_before_start_and_keep_data(self):
        for _ in range(2):
            self.assertEqual(self.run_hook('preinstall').returncode, 0)
            self.assertFalse(json.loads(self.state.read_text())['worker'])
            result = self.run_hook('postinstall')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(self.state.read_text())['job'])
            self.assert_data_preserved()
        calls = json.loads(self.log.read_text())
        actions = [c[1] for c in calls if c[0] == 'launchctl' and c[1] != 'print']
        self.assertEqual(actions, ['bootout', 'enable', 'bootstrap'] * 2)

    def test_fresh_install_without_service(self):
        self.set_state(job=False, worker=False)
        self.assertEqual(self.run_hook('preinstall').returncode, 0)
        self.assertEqual(self.run_hook('postinstall').returncode, 0)
        self.assert_data_preserved()

    def test_stuck_job_or_orphan_worker_aborts_before_payload(self):
        for job in (True, False):
            self.set_state(job=job, worker=True, stuck=True)
            self.assertNotEqual(self.run_hook('preinstall').returncode, 0)
            self.assert_data_preserved()

    def test_postinstall_refuses_duplicate_and_preserves_data_on_start_failure(self):
        self.assertNotEqual(self.run_hook('postinstall').returncode, 0)
        self.set_state(job=False, worker=False, bootstrap_fail=True)
        self.assertNotEqual(self.run_hook('postinstall').returncode, 0)
        self.assert_data_preserved()

    def test_other_volume_never_touches_running_service(self):
        for hook in ('preinstall', 'postinstall'):
            self.assertNotEqual(self.run_hook(hook, '/Volumes/Other').returncode, 0)
        self.assertEqual(json.loads(self.log.read_text()), [])
        self.assert_data_preserved()


if __name__ == '__main__':
    unittest.main(verbosity=2)
