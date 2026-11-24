"""Installer contract tests. OS commands are replaced only in temporary copies.

This exercises macOS script control flow on Linux; it does not claim to run
Apple Installer, Windows Installer or Android's PackageManager.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from package_version import ROOT, android_code, check_consistent, check_newer, product_version, version_parts
import verify_android_update as android


class VersionTests(unittest.TestCase):
    def test_utf8_metadata_on_a_windows_legacy_locale(self):
        original_read = Path.read_text
        expected = product_version()
        def windows_read(path, encoding=None, errors=None):
            return original_read(path, encoding=encoding or 'cp1252', errors=errors)
        with patch.object(Path, 'read_text', windows_read):
            self.assertEqual(product_version(), expected)
            check_consistent()
            check_newer()

    def test_new_release_and_platform_order(self):
        check_consistent()
        versions = ['0.2.0', '0.2.1', '0.2.999', '0.3.0', '1.0.0']
        self.assertEqual(sorted(versions, key=version_parts), versions)
        self.assertEqual(sorted(versions, key=android_code), versions)
        self.assertGreater(android_code(product_version()), 2)  # old preview
        for value in ['0.2.1.1', '0.2.1-preview', '0.2.1000', '256.0.0', '0.01.1']:
            with self.assertRaises(ValueError):
                version_parts(value)

    def test_catalog_can_match_source_but_republication_requires_a_bump(self):
        import package_version
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'apps/desktop').mkdir(parents=True)
            (root / 'installers/current').mkdir(parents=True)
            (root / 'apps/desktop/package.json').write_text(json.dumps({'version': '0.3.1'}))
            (root / 'apps/desktop/package-lock.json').write_text(json.dumps({'version': '0.3.1', 'packages': {'': {'version': '0.3.1'}}}))
            (root / 'installers/current/manifest.json').write_text(json.dumps({'version': '0.3.1-preview'}))
            with patch.object(package_version, 'ROOT', root):
                check_consistent()
                with self.assertRaises(ValueError):
                    check_newer()

    def test_windows_product_identity_and_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / 'payload'
            (payload / 'resources/agent').mkdir(parents=True)
            (payload / 'resources/agent/linevpn-agent.exe').write_bytes(b'agent')
            (payload / 'Сеть.exe').write_bytes(b'gui')
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
            self.assertIsNone(p.find('w:SetProperty[@Id="REINSTALL"]', ns))
            self.assertIsNone(p.find('w:SetProperty[@Id="REINSTALLMODE"]', ns))
            self.assertEqual(p.find('w:Property[@Id="ARPNOREPAIR"]', ns).get('Value'), '1')
            self.assertEqual(p.find('w:Property[@Id="DISABLEADVTSHORTCUTS"]', ns).get('Value'), '1')
            self.assertEqual(p.find('w:Feature', ns).get('AllowAdvertise'), 'no')
            for launch in p.findall('w:Launch', ns):
                launch.get('Message').encode('cp1251')  # MSI string pool uses the declared code page.
            conditions = [x.get('Condition') for x in p.findall('w:Launch', ns)]
            self.assertIn('REMOVE~=\"ALL\" OR (NOT Installed AND NOT WIX_UPGRADE_DETECTED AND NOT REINSTALL)', conditions)
            cleanup = p.find('w:CustomAction[@Id="RemoveClientState"]', ns)
            self.assertEqual(cleanup.get('BinaryRef'), 'InstallerAgent')
            self.assertEqual(cleanup.get('ExeCommand'), '-uninstall-state')
            prepare = p.find('w:CustomAction[@Id="PrepareCleanInstall"]', ns)
            self.assertEqual(prepare.get('ExeCommand'), '-prepare-install')
            menu = p.find('w:StandardDirectory[@Id="ProgramMenuFolder"]', ns)
            shortcut = menu.find('w:Component/w:Shortcut', ns)
            self.assertIsNotNone(shortcut, 'Сеть must have a current, directly discoverable Start menu shortcut')
            self.assertEqual(shortcut.attrib['Name'], 'Сеть')
            self.assertEqual(shortcut.attrib['Target'], '[#ClientUI]')
            self.assertEqual(shortcut.attrib['Advertise'], 'no')
            self.assertEqual(Path(first.find('.//w:File[@Id="ClientUI"]', ns).get('Source')).name, 'Сеть.exe')
            component = menu.find('w:Component', ns)
            self.assertNotEqual(component.attrib['Guid'], '{9A5D6DC0-5C93-4DC6-82BC-9857E58B9B20}', 'renamed/moved shortcut must not reuse the legacy component')
            marker = component.find('w:RegistryValue', ns)
            self.assertEqual(marker.attrib['Name'], 'StartMenuShortcut')
            self.assertIsNone(first.find('.//w:StandardDirectory[@Id="CommonAppDataFolder"]', ns), 'user state must remain outside MSI ownership')
            self.assertEqual(len(first.findall('.//w:ServiceInstall', ns)), 1)
            self.assertEqual(first.find('.//w:ServiceInstall', ns).get('Vital'), 'yes',
                             'service registration must fail the installation instead of leaving a GUI-only product')
            ready = first.find('.//w:CustomAction[@Id="CheckServiceReady"]', ns)
            self.assertEqual(ready.get('ExeCommand'), '-check-service')
            self.assertEqual(ready.get('Return'), 'check')
            self.assertEqual(ready.get('Impersonate'), 'no')
            scheduled = first.find('.//w:Custom[@Action="CheckServiceReady"]', ns)
            self.assertEqual(scheduled.get('After'), 'StartServices')
            self.assertIn('NOT REMOVE', scheduled.get('Condition'))



class AndroidTests(unittest.TestCase):
    def test_explicit_signing_identity_preserves_historical_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / 'installers/current/manifest.json'
            previous.parent.mkdir(parents=True)
            previous.write_text(json.dumps({'android_certificate_sha256': 'a' * 64}))
            identity = root / 'packaging/android/signing-certificate.json'
            identity.parent.mkdir(parents=True)
            identity.write_text(json.dumps({'android_certificate_sha256': 'b' * 64}))
            with patch.object(android, 'ROOT', root):
                self.assertEqual(android.expected_certificate(), 'b' * 64)
                identity.write_text(json.dumps({'android_certificate_sha256': 'invalid'}))
                with self.assertRaises(ValueError):
                    android.expected_certificate()
                identity.unlink()
                self.assertEqual(android.expected_certificate(), 'a' * 64)
            self.assertEqual(json.loads(previous.read_text())['android_certificate_sha256'], 'a' * 64)

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
            for name in ('client.apk', 'client.msi', 'Set-macos-universal.dmg'):
                (source / name).write_bytes(b'incomplete')
            (dest / 'existing.msi').write_bytes(b'previous installer')
            (dest / 'manifest.json').write_bytes(b'previous manifest')
            before = {p.name: p.read_bytes() for p in dest.iterdir()}
            for error in (ValueError('bad signature'), None):
                with patch.object(sys, 'argv', ['publish-installers.py', str(source), str(dest)]), patch.dict(os.environ, SOURCE_COMMIT='fixture'), patch.object(android, 'check_apk', side_effect=error), patch('package_version.check_newer'):
                    with self.assertRaises((ValueError, SystemExit)):
                        runpy.run_path(str(ROOT / 'scripts/publish-installers.py'), run_name='__main__')
                self.assertEqual({p.name: p.read_bytes() for p in dest.iterdir()}, before)


# These commands never operate on the real host. Their calls form an execution
# trace so tests can check both successful and failed installer paths.
FAKE_COMMAND = r'''
import json, os, pathlib, plistlib, sys
name = pathlib.Path(sys.argv[0]).name
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
with (root/'trace').open('a') as log:
    log.write(json.dumps([name] + sys.argv[1:]) + '\n')
if name == 'pkgutil':
    version = os.environ.get('INSTALLED_VERSION', '')
    if not version: sys.exit(1)
    print('version: ' + version)
elif name == 'PlistBuddy':
    path = pathlib.Path(sys.argv[-1])
    if not path.is_file():
        # Apple PlistBuddy writes this diagnostic to stdout even when stderr
        # is redirected. A failed read must never become an installed version.
        print("File Doesn't Exist, Will Create: " + str(path))
        sys.exit(1)
    key = sys.argv[2].split(':', 1)[1]
    values = plistlib.loads(path.read_bytes())
    if key == 'CFBundleShortVersionString' and os.environ.get('FAIL_VERSION_READ') == '1':
        print('0.1.0')  # Even plausible output is invalid when the read failed.
        sys.exit(1)
    if key not in values:
        print('Print: Entry, "' + key + '", Does Not Exist', file=sys.stderr)
        sys.exit(1)
    print(values[key])
elif name == 'pgrep':
    gui = 'Contents/MacOS' in sys.argv[-1]
    stuck = os.environ.get('STUCK_GUI' if gui else 'STUCK_WORKER') == '1'
    if not gui and os.environ.get('ORPHAN_WORKER') == '1' and not (root/'worker-stopped').exists():
        stuck = True
    sys.exit(0 if stuck else 1)
elif name == 'pkill':
    if 'Contents/MacOS' not in sys.argv[-1]:
        (root/'worker-stopped').touch()
elif name == 'linevpn-agent':
    if '-check-service' in sys.argv:
        sys.exit(int(os.environ.get('READINESS_CODE', '0')))
    sys.exit(int(os.environ.get('RECOVERY_CODE', '0')))
elif name == 'uname':
    print(os.environ.get('MAC_ARCH', 'arm64'))
elif name == 'sysctl':
    print(os.environ.get('APPLE_SILICON', '0'))
elif name == 'installer':
    sys.exit(int(os.environ.get('INSTALL_CODE', '0')))
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
    if sys.argv[2] == '-read':
        key = sys.argv[-1]
        values = {'UniqueID': '399', 'PrimaryGroupID': '399', 'NFSHomeDirectory': '/var/empty', 'UserShell': '/usr/bin/false'}
        if os.environ.get('FOREIGN_ACCOUNT') == '1': values['UniqueID'] = '501'
        print(key + ': ' + values[key])
    elif sys.argv[2] != '-delete':
        sys.exit(99)

'''


class MacOSScriptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commands = self.root / 'commands'
        self.commands.mkdir()
        names = ['pkgutil', 'PlistBuddy', 'pgrep', 'pkill', 'launchctl', 'id', 'dscl', 'sleep', 'linevpn-agent', 'pfctl', 'uname', 'sysctl', 'installer']
        for name in names:
            file = self.commands / name
            file.write_text('#!' + sys.executable + '\n' + FAKE_COMMAND)
            file.chmod(0o755)
        self.data = self.root / 'state'
        self.data.mkdir()
        self.applications = self.root / 'Applications'
        self.applications.mkdir()
        self.support = self.root / 'support'
        self.support.mkdir()
        (self.support / 'linevpn-agent').symlink_to(self.commands / 'linevpn-agent')
        self.files = {
            'profile.json': b'{"profile":{"device_id":"existing-device","token":"fixture","rules":["example.org"]},"vpn_disabled":true}',
            'applications.json': b'{"fixture":{"decision":"trusted"}}',
            'dns.db': b'fixture database', 'ui-token': b'fixture-ui-token',
        }
        for name, content in self.files.items():
            (self.data / name).write_bytes(content)
        for name in ('preinstall', 'postinstall', 'uninstall.sh', 'stop-service.sh', 'manage.sh'):
            path = ROOT / 'packaging/macos' / name
            if not path.exists():
                continue
            source = path.read_text()
            # Privilege/root paths are substituted in the temporary test copy.
            source = source.replace('"$EUID"', '"0"').replace('/var/lib/linevpn', str(self.data))
            source = source.replace('in /Users/*', 'in ' + str(self.root / 'Users') + '/*').replace('/var/root', str(self.root / 'root-home'))
            source = source.replace('/etc/pf.conf', str(self.root / 'pf.conf'))
            source = source.replace('/Applications/', str(self.applications) + '/')
            source = source.replace('$vpn_home/Library/Application Support/LineVPN', '$vpn_home/Library/Application Support/__UI_LINEVPN__')
            source = source.replace('/Library/Application Support/LineVPN', str(self.support))
            source = source.replace('__UI_LINEVPN__', 'LineVPN')
            source = source.replace('/Library/LaunchDaemons/', str(self.root) + '/LaunchDaemons/')
            source = source.replace('/var/run/', str(self.root) + '/').replace('/var/log/', str(self.root) + '/')
            source = source.replace("'/Library/Application Support/LineVPN/linevpn-agent'", str(self.commands / 'linevpn-agent'))
            for command in names:
                for prefix in ('/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/', '/usr/libexec/'):
                    source = source.replace(prefix + command, str(self.commands / command))
            (self.root / name).write_text(source)
            (self.support / name).write_text(source)
        (self.root / 'pf.conf').write_text('# fixture system PF configuration\n')
        (self.root / 'version').write_text(product_version() + '\n')
        self.env = dict(os.environ, FIXTURE_ROOT=str(self.root), PATH=str(self.commands) + os.pathsep + os.environ['PATH'])

    def run_script(self, script, target='/', **env):
        args = ['fixture.pkg', '/', target] if script in ('preinstall', 'postinstall') else []
        before = {name: (self.data / name).read_bytes() for name in self.files if (self.data / name).exists()}
        result = subprocess.run(['bash', str(self.root / script), *args], env=dict(self.env, **env), text=True, capture_output=True, timeout=15)
        for name, content in before.items():
            if script != 'uninstall.sh' or result.returncode != 0:
                self.assertEqual((self.data / name).read_bytes(), content, f'{name} changed')
        return result

    def trace(self):
        file = self.root / 'trace'
        return [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []

    def clear_installation(self):
        import shutil
        shutil.rmtree(self.data, ignore_errors=True)
        shutil.rmtree(self.support, ignore_errors=True)

    def test_existing_state_blocks_install_before_stopping_service(self):
        result = self.run_script('preinstall')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] in ('launchctl', 'pkill') for call in self.trace()))

    def test_receipt_blocks_install_even_without_payload(self):
        self.clear_installation()
        for previous in ['0.2.0', product_version(), '1.0.0']:
            result = self.run_script('preinstall', INSTALLED_VERSION=previous)
            self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] == 'pkill' for call in self.trace()))

    def bundle(self, name, identifier='dev.linevpn.desktop', version=None):
        bundle = self.applications / name
        (bundle / 'Contents').mkdir(parents=True)
        (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': identifier,
            'CFBundleShortVersionString': product_version() if version is None else version,
        }))
        return bundle

    def test_clean_install_does_not_probe_absent_plists(self):
        self.clear_installation()
        result = self.run_script('preinstall')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call[0] in ('PlistBuddy', 'pkill') for call in self.trace()))

    def test_old_and_current_bundle_require_explicit_removal(self):
        self.clear_installation()
        self.bundle('LineVPN.app', version='0.2.0')
        result = self.run_script('preinstall')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.applications / 'LineVPN.app').exists())

    def test_foreign_bundle_is_not_replaced(self):
        for name in ('LineVPN.app', 'Сеть.app'):
            with self.subTest(name=name):
                bundle = self.bundle(name, 'org.example.another-app')
                self.assertNotEqual(self.run_script('preinstall').returncode, 0)
                self.assertTrue(bundle.exists())
        self.assertFalse(any(call[0] in ('launchctl', 'pkill') for call in self.trace()))

    def test_wrong_volume_rejected_before_host_changes(self):
        for script in ('preinstall', 'postinstall'):
            self.assertNotEqual(self.run_script(script, target='/Volumes/Other').returncode, 0)
        self.assertEqual(self.trace(), [])

    def test_stop_helper_requires_all_processes_to_exit(self):
        self.assertEqual(self.run_script('stop-service.sh', BOOTOUT_CODE='3').returncode, 0)
        for flag in ('STUCK_SERVICE', 'STUCK_WORKER', 'STUCK_GUI'):
            with self.subTest(flag=flag):
                self.assertNotEqual(self.run_script('stop-service.sh', BOOTOUT_CODE='3', **{flag: '1'}).returncode, 0)

    def test_stop_helper_stops_an_orphan_without_changing_network(self):
        result = self.run_script('stop-service.sh', ORPHAN_WORKER='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(call[0] == 'pkill' and 'Contents/MacOS' not in call[-1] for call in self.trace()))
        self.assertFalse(any('-recover-network' in call for call in self.trace()))

    def test_stop_helper_matches_nested_electron_processes_only_in_our_bundles(self):
        self.assertEqual(self.run_script('stop-service.sh').returncode, 0)
        pattern = next(call[-1] for call in self.trace() if call[0] == 'pkill' and 'Contents/MacOS' in call[-1])
        for name in ('LineVPN', 'Сеть'):
            bundle = self.applications / (name + '.app')
            for command in (f'{bundle}/Contents/MacOS/LineVPN --background', f'{bundle}/Contents/Frameworks/LineVPN Helper (Renderer).app/Contents/MacOS/LineVPN Helper (Renderer) --type=renderer'):
                self.assertEqual(subprocess.run(['grep', '-Eq', pattern], input=command, text=True).returncode, 0, command)
        for command in ('/Applications/Other.app/Contents/MacOS/LineVPN', '/Volumes/Сеть/Сеть.app/Contents/MacOS/LineVPN', str(self.applications / 'Сеть.app-other/Contents/MacOS/LineVPN')):
            self.assertNotEqual(subprocess.run(['grep', '-Eq', pattern], input=command, text=True).returncode, 0, command)

    def test_uninstall_waits_for_launchd_and_removes_local_state(self):
        result = self.run_script('uninstall.sh', STOP_POLLS='2')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.support.exists())
        self.assertFalse(self.data.exists())
        self.assertTrue(any('-recover-network' in call for call in self.trace()))

    def test_uninstall_refuses_recovery_while_worker_is_alive(self):
        result = self.run_script('uninstall.sh', STUCK_WORKER='1')
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.support.exists())
        self.assertFalse(any('-recover-network' in call for call in self.trace()))

    def test_failed_recovery_keeps_installed_files(self):
        result = self.run_script('uninstall.sh', RECOVERY_CODE='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.support / 'linevpn-agent').exists())

    def test_uninstall_rejects_foreign_bundle_before_touching_state(self):
        foreign = self.bundle('Сеть.app', identifier='org.example.other')
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(foreign.exists())
        self.assertTrue(self.support.exists())
        self.assertFalse(any(call[0] in ('pkill', 'launchctl', 'linevpn-agent') for call in self.trace()))

    def test_uninstall_does_not_delete_an_unexpected_system_account(self):
        result = self.run_script('uninstall.sh', FOREIGN_ACCOUNT='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.data.exists())
        self.assertFalse(any(call[:3] == ['dscl', '.', '-delete'] for call in self.trace()))

    def test_uninstall_clears_own_ui_data_and_preserves_other_apps(self):
        home = self.root / 'Users/fixture/Library/Application Support'
        own, foreign = home / 'LineVPN', home / 'Electron'
        own.mkdir(parents=True)
        foreign.mkdir()
        (own / 'Preferences').write_text('old UI state')
        (foreign / 'Preferences').write_text('other application')
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(own.exists())
        self.assertEqual((foreign / 'Preferences').read_text(), 'other application')

    def test_uninstall_removes_only_owned_pf_hooks(self):
        pf = self.root / 'pf.conf'
        original = '# fixture\nanchor "other"\nanchor "linevpn"\nanchor "linevpn" out quick\n'
        pf.write_text(original)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(pf.read_text(), '# fixture\nanchor "other"\n')

    def test_postinstall_migrates_legacy_pf_hook_without_flushing_rules(self):
        pf = self.root / 'pf.conf'
        pf.write_text('# fixture\nanchor "other"\nanchor "linevpn" out quick\n')
        result = self.run_script('postinstall')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(pf.read_text(), '# fixture\nanchor "other"\nanchor "linevpn"\n')
        self.assertFalse(any(call[0] == 'pfctl' and '-F' in call for call in self.trace()))

    def run_manager(self, action, **env):
        for arch in ('arm64', 'x64'):
            (self.root / f'payload-{arch}.pkg').write_bytes(b'fixture')
            recovery = self.root / f'recovery-{arch}'
            if not recovery.exists():
                recovery.symlink_to(self.commands / 'linevpn-agent')
        return subprocess.run(['bash', str(self.root / 'manage.sh'), action],
                              env=dict(self.env, **env), text=True, capture_output=True, timeout=15)

    def test_manager_selects_native_payload_including_rosetta(self):
        for arch, translated, expected in [('arm64', '0', 'arm64'), ('x86_64', '0', 'x64'), ('x86_64', '1', 'arm64')]:
            result = self.run_manager('install', MAC_ARCH=arch, APPLE_SILICON=translated)
            self.assertEqual(result.returncode, 0, result.stderr)
            call = [c for c in self.trace() if c[0] == 'installer'][-1]
            self.assertIn(str(self.root / f'payload-{expected}.pkg'), call)
        self.assertFalse(any('-recover-network' in call for call in self.trace()))

    def test_manager_can_remove_broken_old_install_without_its_scripts(self):
        (self.support / 'linevpn-agent').unlink()
        (self.support / 'uninstall.sh').write_text('exit 99\n')
        result = self.run_manager('uninstall', STOP_POLLS='2')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.support.exists())
        self.assertFalse(self.data.exists())

    def test_manager_reports_install_failure_and_releases_lock(self):
        result = self.run_manager('install', INSTALL_CODE='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Журнал установки', result.stderr)
        self.assertFalse((self.root / 'dev.linevpn.installer.lock').exists())

    def test_postinstall_rejects_a_service_that_never_becomes_ready(self):
        result = self.run_script('postinstall', READINESS_CODE='1')
        self.assertNotEqual(result.returncode, 0, 'launchctl bootstrap alone is not successful installation')
        self.assertTrue(any('-check-service' in call for call in self.trace()))
        self.assertFalse(any('-recover-network' in call for call in self.trace()))

    def test_postinstall_will_not_start_a_duplicate_service(self):
        self.assertNotEqual(self.run_script('postinstall', STUCK_SERVICE='1').returncode, 0)
        self.assertFalse(any(call[:2] == ['launchctl', 'bootstrap'] for call in self.trace()))
        self.assertNotEqual(self.run_script('postinstall', STUCK_WORKER='1').returncode, 0)
        self.assertNotEqual(self.run_script('postinstall', FAIL_BOOTSTRAP='1').returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
