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
BASH = os.environ.get('TEST_BASH', 'bash')
spec = importlib.util.spec_from_file_location('remote', ROOT / 'scripts/deploy-remote.py')
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


class RemoteDeploymentTest(unittest.TestCase):
    def test_three_values_roundtrip_from_pipe(self):
        admin = "Admin'$(){{literal}}\u2028password"
        self.assertEqual(remote.read_input(io.BytesIO(('8.8.8.8\n2222\n' + admin + '\n').encode())), ('8.8.8.8',2222,admin))

    def test_invalid_remote_input(self):
        for host,port,admin in [('127.0.0.1','22','a'*20),('8.8.8.8','0','a'*20),('8.8.8.8','22','я'*40),('8.8.8.8','22',' '+'a'*20)]:
            with self.subTest(host=host), self.assertRaises(ValueError):
                remote.read_input(io.BytesIO(f'{host}\n{port}\n{admin}\n'.encode()))

    def test_prebuilt_binary_checksums_reject_corruption_and_links(self):
        for failure in ('checksum','symlink',None):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);build=root/'build';build.mkdir()
                names=['linevpn-server-linux-amd64','linevpn-keygen-linux-amd64']
                for name in names: (build/name).write_bytes(b'synthetic binary')
                manifest=''.join(hashlib.sha256(b'synthetic binary').hexdigest()+'  '+name+'\n' for name in names)
                (build/'SHA256SUMS').write_text(manifest)
                if failure=='checksum': (build/names[0]).write_bytes(b'corrupted')
                if failure=='symlink':
                    (build/names[0]).unlink();(build/names[0]).symlink_to(build/names[1])
                with mock.patch.object(remote,'ROOT',root):
                    if failure:
                        with self.assertRaises(RuntimeError): remote.verify_binaries()
                    else: remote.verify_binaries()

    def test_remote_failures_do_not_emit_success_or_secrets(self):
        for failure in ('binaries', 'ansible', 'health', None):
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
                     mock.patch.object(remote, 'verify_binaries', side_effect=RuntimeError('binary checksum failed') if failure == 'binaries' else None), mock.patch.object(remote,'prepare_tools'), \
                     mock.patch.object(remote, 'run', side_effect=fake_run), \
                     mock.patch.object(remote, 'verify_server', return_value='example.org', side_effect=RuntimeError('health failed') if failure == 'health' else None) as verify, \
                     contextlib.redirect_stdout(output):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            remote.deploy('8.8.8.8', 22, password)
                    else:
                        remote.deploy('8.8.8.8', 22, password)
                self.assertNotIn(password, output.getvalue())
                self.assertEqual('LINEVPN_REMOTE_OK=1' in output.getvalue(), failure is None)
                if failure in ('binaries', 'ansible'):
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
 print('/dev/shm/linevpn-deploy.1234abcd')
elif 'source.tar.gz' in cmd:(state/'archive.tar.gz').write_bytes(sys.stdin.buffer.read())
elif cmd.startswith('umask'):(state/'input').write_bytes(sys.stdin.buffer.read())
elif 'cat >' in cmd:sys.stdin.buffer.read()
elif cmd.startswith('bash '):
 if os.environ['TEST_FAIL']=='deploy':sys.exit(1)
 print('LINEVPN_PROFILE_B64='+base64.b64encode(b'linevpn://8.8.8.8:8443?pin=test\\n').decode())
 print('LINEVPN_CERT_B64='+base64.b64encode(b'certificate').decode())
 print('LINEVPN_REALITY_SNI_B64='+base64.b64encode(b'example.org').decode())
 print('LINEVPN_REMOTE_OK=1')
''')
            stub.chmod(0o755)
            password = "ssh' $() & {{password}}"
            admin = 'admin\" $() & {{password}}'
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                       VPS_HOST='8.8.8.8', VPS_USERNAME='root', VPS_PASSWORD=password, VPN_ADMIN_PASSWORD=admin,
                       TEST_STATE=str(tmp), TEST_PASSWORD=password, TEST_FAIL=failure)
            env.update(overrides or {})
            code = 'source ./deploy.sh; prepare_source() { tar -czf "$linevpn_tmp/source.tar.gz" -C "$linevpn_root" -T "$linevpn_root/deploy/source-files.txt"; }; verify_public() { [[ ${2:-} == example.org ]] || return 99; return ' + ('1' if failure == 'port' else '0') + '; }; main'
            result = subprocess.run([BASH, '-c', code], cwd=root, env=env, capture_output=True, text=True, timeout=45)
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

    def test_four_values_with_prebuilt_payload(self):
        result, commands = self.run_launcher()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Deployment verified:', result.stdout)
        self.assertIn('Admin: https://8.8.8.8:8443/', result.stdout)
        self.assertIn('StrictHostKeyChecking=accept-new', commands)
        self.assertIn('PubkeyAuthentication=yes', commands)
        self.assertNotIn('LINEVPN_SSH_PASSWORD', commands)

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
