"""Installer contract tests. OS commands are replaced only in temporary copies.

This exercises macOS script control flow on Linux; it does not claim to run
Apple Installer, Windows Installer or Android's PackageManager.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from package_version import ROOT, android_code, check_newer, product_version, version_parts
import verify_android_update as android


class VersionTests(unittest.TestCase):
    def test_new_release_and_platform_order(self):
        check_newer()
        versions = ['0.2.0', '0.2.1', '0.2.999', '0.3.0', '1.0.0']
        self.assertEqual(sorted(versions, key=version_parts), versions)
        self.assertEqual(sorted(versions, key=android_code), versions)
        self.assertGreater(android_code(product_version()), 2)  # old preview
        for value in ['0.2.1.1', '0.2.1-preview', '0.2.1000', '256.0.0', '0.01.1']:
            with self.assertRaises(ValueError):
                version_parts(value)

    def test_windows_product_identity_and_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / 'payload'
            (payload / 'resources/agent').mkdir(parents=True)
            (payload / 'resources/agent/linevpn-agent.exe').write_bytes(b'agent')
            (payload / 'LineVPN.exe').write_bytes(b'gui')
            output = root / 'package.wxs'
            def generate():
                subprocess.run([sys.executable, str(ROOT / 'packaging/windows/package.py'), str(payload), str(output)], check=True)
                return ET.parse(output)
            ns = {'w': 'http://wixtoolset.org/schemas/v4/wxs'}
            first, second = generate(), generate()
            p = first.find('w:Package', ns)
            self.assertEqual(p.attrib['Version'], product_version())
            self.assertEqual(p.attrib['ProductCode'], second.find('w:Package', ns).attrib['ProductCode'])
            subprocess.run([sys.executable, str(ROOT / 'packaging/windows/package.py'), str(payload), str(output), '--version', '0.2.0'], check=True)
            previous = ET.parse(output).find('w:Package', ns)
            self.assertNotEqual(p.attrib['ProductCode'], previous.attrib['ProductCode'])
            self.assertEqual(p.attrib['UpgradeCode'], previous.attrib['UpgradeCode'])
            self.assertEqual(p.attrib['UpgradeCode'], '{0ACF9EA2-83F8-4EE0-8877-E3BAE8A42E91}')
            self.assertEqual(p.find('w:MajorUpgrade', ns).attrib['Schedule'], 'afterInstallInitialize')
            self.assertNotIn('AllowSameVersionUpgrades', p.find('w:MajorUpgrade', ns).attrib)
            repair = p.find('w:SetProperty[@Id="REINSTALL"]', ns)
            self.assertEqual(repair.attrib['Value'], 'ALL')
            self.assertEqual(repair.attrib['Before'], 'CostInitialize')
            self.assertIn('Installed AND NOT REMOVE AND NOT UPGRADINGPRODUCTCODE', repair.attrib['Condition'])
            self.assertEqual(p.find('w:SetProperty[@Id="REINSTALLMODE"]', ns).attrib['Value'], 'amus')
            self.assertIsNone(first.find('.//w:StandardDirectory[@Id="CommonAppDataFolder"]', ns), 'user state must remain outside MSI ownership')
            self.assertEqual(len(first.findall('.//w:ServiceInstall', ns)), 1)


class AndroidTests(unittest.TestCase):
    def test_missing_key_does_not_generate_one(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(android.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'ANDROID_KEYSTORE'):
                android.check_keystore()
            run.assert_not_called()

    def test_key_fingerprint_and_password_handling(self):
        certificate = b'fixture DER certificate'
        env = dict(ANDROID_KEYSTORE='/private/signing.keystore', ANDROID_STORE_PASSWORD='fixture-secret',
                   ANDROID_KEY_ALIAS='fixture', ANDROID_KEY_PASSWORD='fixture-secret')
        result = subprocess.CompletedProcess([], 0, stdout=certificate)
        with patch.dict(os.environ, env), patch.object(android, 'expected_certificate', return_value=hashlib.sha256(certificate).hexdigest()), patch.object(android.subprocess, 'run', return_value=result) as run:
            android.check_keystore()
            self.assertNotIn('fixture-secret', repr(run.call_args))
            with patch.object(android, 'expected_certificate', return_value='a' * 64):
                with self.assertRaisesRegex(ValueError, 'differs'):
                    android.check_keystore()

    def test_apk_identity_version_and_signer(self):
        good = ("Signer #1 certificate SHA-256 digest: " + 'a' * 64,
                f"package: name='dev.linevpn.app' versionCode='{android_code(product_version())}' versionName='{product_version()}'")
        cases = [good, (good[0].replace('a' * 64, 'b' * 64), good[1]),
                 (good[0], good[1].replace('dev.linevpn.app', 'dev.linevpn.other')),
                 (good[0], good[1].replace(str(android_code(product_version())), '2'))]
        for index, output in enumerate(cases):
            with self.subTest(index=index), patch.dict(os.environ, ANDROID_HOME='/sdk'), patch.object(android, 'expected_certificate', return_value='a' * 64), patch.object(android.subprocess, 'check_output', side_effect=output):
                if index == 0:
                    android.check_apk(Path('test.apk'))
                else:
                    with self.assertRaises(ValueError):
                        android.check_apk(Path('test.apk'))


    def test_previous_apk_cannot_be_downgraded_or_replaced_by_another_key(self):
        current = ("dev.linevpn.app", str(android_code(product_version())), product_version(), 'a' * 64)
        good = (current[0], '2', '0.2.0-preview', current[3])
        for previous in [good, current, (current[0], str(int(current[1]) + 1), 'next', current[3]),
                         (current[0], '2', 'old', 'b' * 64)]:
            with patch.object(android, 'inspect_apk', side_effect=[current, previous]), patch.object(android, 'expected_certificate', return_value='a' * 64):
                if previous in (good, current):
                    android.check_apk(Path('new.apk'), Path('old.apk'))
                else:
                    with self.assertRaises(ValueError):
                        android.check_apk(Path('new.apk'), Path('old.apk'))

    def test_invalid_publication_preserves_existing_installers(self):
        import runpy
        with tempfile.TemporaryDirectory() as directory:
            source, dest = Path(directory) / 'incoming', Path(directory) / 'current'
            source.mkdir(); dest.mkdir()
            for name in ('client.apk', 'client.msi', 'arm64.dmg', 'x64.dmg'):
                (source / name).write_bytes(b'incomplete')
            (dest / 'existing.msi').write_bytes(b'previous installer')
            (dest / 'manifest.json').write_bytes(b'previous manifest')
            before = {p.name: p.read_bytes() for p in dest.iterdir()}
            for error in (ValueError('bad signature'), None):
                with patch.object(sys, 'argv', ['publish-installers.py', str(source), str(dest)]), patch.dict(os.environ, SOURCE_COMMIT='fixture'), patch.object(android, 'check_apk', side_effect=error):
                    with self.assertRaises((ValueError, SystemExit)):
                        runpy.run_path(str(ROOT / 'scripts/publish-installers.py'), run_name='__main__')
                self.assertEqual({p.name: p.read_bytes() for p in dest.iterdir()}, before)


# These commands never operate on the real host. Their calls form an execution
# trace so tests can check both successful and failed installer paths.
FAKE_COMMAND = r'''
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
with (root/'trace').open('a') as log:
    log.write(json.dumps([name] + sys.argv[1:]) + '\n')
if name == 'pkgutil':
    version = os.environ.get('INSTALLED_VERSION', '')
    if not version: sys.exit(1)
    print('version: ' + version)
elif name == 'PlistBuddy':
    version = os.environ.get('APP_VERSION', '')
    if not version: sys.exit(1)
    print(version)
elif name == 'pgrep':
    gui = 'Contents/MacOS' in sys.argv[-1]
    stuck = os.environ.get('STUCK_GUI' if gui else 'STUCK_WORKER') == '1'
    sys.exit(0 if stuck else 1)
elif name == 'launchctl':
    if sys.argv[1] == 'print':
        counter = root/'stopping'
        left = int(counter.read_text()) if counter.exists() else 0
        if left:
            counter.write_text(str(left - 1))
        sys.exit(0 if left or os.environ.get('STUCK_SERVICE') == '1' else 1)
    if sys.argv[1] == 'bootstrap' and os.environ.get('FAIL_BOOTSTRAP') == '1':
        sys.exit(1)
    if sys.argv[1] == 'bootout':
        (root/'stopping').write_text(os.environ.get('STOP_POLLS', '0'))
        sys.exit(int(os.environ.get('BOOTOUT_CODE', '0')))
elif name == 'id':
    sys.exit(0)  # Existing service account must be reused.
elif name == 'dscl':
    sys.exit(99)  # Recreating the existing account is a regression.
'''


class MacOSScriptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commands = self.root / 'commands'
        self.commands.mkdir()
        names = ['pkgutil', 'PlistBuddy', 'pgrep', 'pkill', 'launchctl', 'id', 'dscl', 'sleep', 'linevpn-agent', 'pfctl']
        for name in names:
            file = self.commands / name
            file.write_text('#!' + sys.executable + '\n' + FAKE_COMMAND)
            file.chmod(0o755)
        self.data = self.root / 'state'
        self.data.mkdir()
        self.files = {
            'profile.json': b'{"profile":{"device_id":"existing-device","token":"fixture","rules":["example.org"]},"vpn_disabled":true}',
            'applications.json': b'{"fixture":{"decision":"trusted"}}',
            'dns.db': b'fixture database', 'ui-token': b'fixture-ui-token',
        }
        for name, content in self.files.items():
            (self.data / name).write_bytes(content)
        for name in ('preinstall', 'postinstall'):
            source = (ROOT / 'packaging/macos' / name).read_text()
            # Privilege/root paths are substituted in the temporary test copy.
            source = source.replace('"$EUID"', '"0"').replace('/var/lib/linevpn', str(self.data))
            source = source.replace('/etc/pf.conf', str(self.root / 'pf.conf'))
            source = source.replace("'/Library/Application Support/LineVPN/linevpn-agent'", str(self.commands / 'linevpn-agent'))
            for command in names:
                for prefix in ('/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/', '/usr/libexec/'):
                    source = source.replace(prefix + command, str(self.commands / command))
            (self.root / name).write_text(source)
        (self.root / 'pf.conf').write_text('# fixture system PF configuration\n')
        (self.root / 'version').write_text(product_version() + '\n')
        self.env = dict(os.environ, FIXTURE_ROOT=str(self.root), PATH=str(self.commands) + os.pathsep + os.environ['PATH'])

    def run_script(self, script, target='/', **env):
        result = subprocess.run(['bash', str(self.root / script), 'fixture.pkg', '/', target], env=dict(self.env, **env), text=True, capture_output=True, timeout=5)
        for name, content in self.files.items():
            self.assertEqual((self.data / name).read_bytes(), content, f'{name} changed')
        return result

    def trace(self):
        file = self.root / 'trace'
        return [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []

    def test_fresh_upgrade_and_repeat_preserve_state(self):
        for previous in ['', '0.2.0', product_version()]:
            with self.subTest(previous=previous):
                result = self.run_script('preinstall', INSTALLED_VERSION=previous, STOP_POLLS='2')
                self.assertEqual(result.returncode, 0, result.stderr)
                result = self.run_script('postinstall')
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('dscl', [call[0] for call in self.trace()])
        self.assertFalse(any('-recover-network' in call for call in self.trace()), 'upgrade removed protection')
        self.assertEqual((self.root / 'pf.conf').read_text().count('anchor "linevpn"'), 1)
        self.assertTrue(any(call[:2] == ['launchctl', 'bootstrap'] for call in self.trace()))

    def test_downgrade_rejected_before_stopping_anything(self):
        for version_source in ('INSTALLED_VERSION', 'APP_VERSION'):
            self.assertNotEqual(self.run_script('preinstall', **{version_source: '1.0.0'}).returncode, 0)
        self.assertFalse(any(call[0] in ('launchctl', 'pkill') for call in self.trace()))

    def test_wrong_volume_rejected_before_host_changes(self):
        for script in ('preinstall', 'postinstall'):
            self.assertNotEqual(self.run_script(script, target='/Volumes/Other').returncode, 0)
        self.assertEqual(self.trace(), [])

    def test_failed_bootout_is_allowed_only_when_already_stopped(self):
        self.assertEqual(self.run_script('preinstall', BOOTOUT_CODE='3').returncode, 0)
        for flag in ('STUCK_SERVICE', 'STUCK_WORKER', 'STUCK_GUI'):
            with self.subTest(flag=flag):
                self.assertNotEqual(self.run_script('preinstall', BOOTOUT_CODE='3', **{flag: '1'}).returncode, 0)

    def test_postinstall_will_not_start_a_duplicate_service(self):
        self.assertNotEqual(self.run_script('postinstall', STUCK_SERVICE='1').returncode, 0)
        self.assertFalse(any(call[:2] == ['launchctl', 'bootstrap'] for call in self.trace()))
        self.assertNotEqual(self.run_script('postinstall', STUCK_WORKER='1').returncode, 0)
        self.assertNotEqual(self.run_script('postinstall', FAIL_BOOTSTRAP='1').returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
