import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('remote', ROOT / 'scripts/deploy-remote.py')
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


class RemoteDeploymentTest(unittest.TestCase):
    def test_four_values_roundtrip_and_input_removed(self):
        admin = "Admin'$(){{literal}}\u2028password"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input'
            path.write_text('8.8.8.8\n2222\nssh $() password\n' + admin + '\n')
            self.assertEqual(remote.read_input(path), ('8.8.8.8', 2222, admin))
            self.assertFalse(path.exists())

    def test_invalid_remote_input(self):
        for host, port, admin in [('127.0.0.1', '22', 'a' * 20), ('8.8.8.8', '0', 'a' * 20),
                                 ('8.8.8.8', '22', 'я' * 40), ('8.8.8.8', '22', ' ' + 'a' * 20)]:
            with self.subTest(host=host, port=port), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'input'
                path.write_text(f'{host}\n{port}\npassword\n{admin}\n')
                with self.assertRaises(ValueError):
                    remote.read_input(path)
                self.assertFalse(path.exists())

    def test_go_download_checksum_and_safe_extraction(self):
        for kind in ('valid', 'checksum', 'traversal', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode='w:gz') as tar:
                    info = tarfile.TarInfo('../escape' if kind == 'traversal' else 'go/bin/go')
                    info.size = 4
                    if kind == 'symlink':
                        info.type = tarfile.SYMTYPE
                        info.linkname = '/etc/passwd'
                        info.size = 0
                    tar.addfile(info, io.BytesIO(b'test'))
                archive = stream.getvalue()
                metadata = [{'version': 'go' + remote.GO_VERSION, 'files': [{
                    'filename': f'go{remote.GO_VERSION}.linux-amd64.tar.gz', 'os': 'linux', 'arch': 'amd64',
                    'sha256': '0' * 64 if kind == 'checksum' else hashlib.sha256(archive).hexdigest()}]}]
                with mock.patch.object(remote, 'TOOLS', Path(tmp)), \
                     mock.patch.object(remote.urllib.request, 'urlopen', side_effect=[io.BytesIO(json.dumps(metadata).encode()), io.BytesIO(archive)]):
                    if kind == 'valid':
                        self.assertEqual(remote.install_go().read_bytes(), b'test')
                    else:
                        with self.assertRaises(RuntimeError):
                            remote.install_go()
                        self.assertFalse((Path(tmp) / f'go{remote.GO_VERSION}').exists())

    def test_remote_failures_do_not_emit_success_or_secrets(self):
        for failure in ('build', 'ansible', 'health', None):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                output = io.StringIO()
                generated = root / 'deploy/ansible/generated'
                generated.mkdir(parents=True)
                (generated / 'vpn1-bootstrap.txt').write_text('linevpn://8.8.8.8:8443?pin=test')
                (generated / 'vpn1-api-cert.pem').write_text('test certificate')
                password = "admin'$(literal){{value}}"
                calls = []

                def fake_run(command, env=None):
                    command = [str(x) for x in command]
                    calls.append((command, (env or {}).copy()))
                    self.assertNotIn(password, ' '.join(command))
                    if failure == 'build' and command[1] == 'test':
                        raise RuntimeError('build failed')
                    if command[0].endswith('ansible-playbook'):
                        self.assertEqual(env['VPN_ADMIN_PASSWORD'], password)
                        data = Path(command[2]).read_text()
                        self.assertNotIn(password, data)
                        self.assertEqual(json.loads(data)['all']['children']['vpn']['hosts']['vpn1']['ansible_connection'], 'local')
                        if failure == 'ansible':
                            raise RuntimeError('ansible failed')
                    else:
                        self.assertNotIn('VPN_ADMIN_PASSWORD', env or {})

                with mock.patch.object(remote, 'ROOT', root), mock.patch.object(remote, 'TOOLS', root / 'tools'), \
                     mock.patch.object(remote, 'install_go', return_value=Path('/fake/go/bin/go')), \
                     mock.patch.object(remote, 'run', side_effect=fake_run), \
                     mock.patch.object(remote, 'verify_server', side_effect=RuntimeError('health failed') if failure == 'health' else None) as verify, \
                     contextlib.redirect_stdout(output):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            remote.deploy('8.8.8.8', 22, password)
                    else:
                        remote.deploy('8.8.8.8', 22, password)
                self.assertNotIn(password, output.getvalue())
                self.assertEqual('LINEVPN_REMOTE_OK=1' in output.getvalue(), failure is None)
                if failure in ('build', 'ansible'):
                    verify.assert_not_called()


class ShellLauncherTest(unittest.TestCase):
    def run_launcher(self, failure='', overrides=None):
        with tempfile.TemporaryDirectory(prefix='vpn source ') as tmp:
            tmp = Path(tmp)
            root = tmp / 'repo'
            root.mkdir()
            manifest = (ROOT / 'deploy/source-files.txt').read_text().splitlines()
            for entry in manifest + ['deploy/source-files.txt', 'deploy.sh', 'scripts/deploy-bootstrap.sh']:
                src, dest = ROOT / entry, root / entry
                dest.parent.mkdir(parents=True, exist_ok=True)
                if src.is_dir():
                    shutil.copytree(src, dest)
                else:
                    shutil.copy2(src, dest)
            tools = tmp / 'bin'
            tools.mkdir()
            stub = tools / 'ssh'
            stub.write_text('''#!/usr/bin/env python3
import base64,json,os,pathlib,subprocess,sys
state=pathlib.Path(os.environ['TEST_STATE'])
args=sys.argv[1:]
if args==['-V']:
 print('OpenSSH_9.9p1');sys.exit(0)
with (state/'args').open('a') as f:f.write(json.dumps(args)+'\\n')
answer=subprocess.check_output([os.environ['SSH_ASKPASS']],env=os.environ).decode().rstrip('\\n')
if answer!=os.environ['TEST_PASSWORD']:sys.exit(91)
cmd=args[-1]
if 'mktemp -d' in cmd:
 if os.environ['TEST_FAIL']=='ssh':sys.exit(1)
 print('/tmp/linevpn-deploy.1234abcd')
elif 'source.tar.gz' in cmd:(state/'archive.tar.gz').write_bytes(sys.stdin.buffer.read())
elif cmd.startswith('umask'):(state/'input').write_bytes(sys.stdin.buffer.read())
elif 'cat >' in cmd:sys.stdin.buffer.read()
elif cmd.startswith('if '):
 if os.environ['TEST_FAIL']=='deploy':sys.exit(1)
 print('LINEVPN_PROFILE_B64='+base64.b64encode(b'linevpn://8.8.8.8:8443?pin=test\\n').decode())
 print('LINEVPN_CERT_B64='+base64.b64encode(b'certificate').decode())
 print('LINEVPN_REMOTE_OK=1')
''')
            stub.chmod(0o755)
            password = "ssh' $() & {{password}}"
            admin = 'admin\" $() & {{password}}'
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                       VPS_HOST='8.8.8.8', VPS_USERNAME='root', VPS_PASSWORD=password, VPN_ADMIN_PASSWORD=admin,
                       TEST_STATE=str(tmp), TEST_PASSWORD=password, TEST_FAIL=failure)
            env.update(overrides or {})
            code = 'source ./deploy.sh; check_port() { return ' + ('1' if failure == 'port' else '0') + '; }; main'
            result = subprocess.run(['bash', '-c', code], cwd=root, env=env, capture_output=True, text=True)
            combined = result.stdout + result.stderr
            self.assertNotIn(password, combined)
            self.assertNotIn(admin, combined)
            commands = (tmp / 'args').read_text() if (tmp / 'args').exists() else ''
            self.assertNotIn(password, commands)
            self.assertNotIn(admin, commands)
            if (tmp / 'input').exists():
                self.assertEqual((tmp / 'input').read_text(), f'8.8.8.8\n22\n{password}\n{admin}\n')
            if (tmp / 'archive.tar.gz').exists():
                with tarfile.open(tmp / 'archive.tar.gz') as archive:
                    names = archive.getnames()
                    self.assertIn('go.mod', names)
                    self.assertIn('scripts/deploy-remote.py', names)
                    self.assertFalse(any('vault.yml' in n or n.endswith('/input') or '.git/' in n or 'generated/' in n for n in names))
            return result, commands

    def test_four_values_succeed_without_local_build_tools(self):
        result, commands = self.run_launcher()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Deployment verified:', result.stdout)
        self.assertIn('StrictHostKeyChecking=accept-new', commands)
        self.assertIn('sudo -S', commands)

    def test_failed_ssh_remote_deploy_or_public_port_never_report_success(self):
        for stage in ('ssh', 'deploy', 'port'):
            with self.subTest(stage=stage):
                result, commands = self.run_launcher(stage)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Deployment verified:', result.stdout)
                if stage != 'ssh':
                    self.assertIn('rm -rf', commands)

    def test_invalid_inputs_stop_before_ssh(self):
        for overrides in ({'VPS_HOST': '8.8.8.8;whoami'}, {'VPS_USERNAME': '-oProxyCommand=id'},
                          {'VPS_PORT': '0'}, {'VPN_ADMIN_PASSWORD': 'я' * 40}, {'VPS_PASSWORD': 'a\nb'}):
            with self.subTest(overrides=overrides):
                result, commands = self.run_launcher(overrides=overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(commands, '')


if __name__ == '__main__':
    unittest.main()
