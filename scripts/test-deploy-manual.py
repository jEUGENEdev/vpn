import contextlib
import getpass
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest import mock
import warnings

SCRIPT = Path(__file__).with_name('deploy-manual.py')
spec = importlib.util.spec_from_file_location('deploy_manual', SCRIPT)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


def unix_sockets_available():
    try:
        with socket.socket(socket.AF_UNIX):
            return True
    except OSError:
        return False


class ManualDeploymentTest(unittest.TestCase):
    def test_rejects_injection_and_invalid_target_before_running_tools(self):
        for host, user, port in [('8.8.8.8;id', 'root', '22'), ('127.0.0.1', 'root', '22'),
                                 ('8.8.8.8', '-oProxyCommand=id', '22'),
                                 ('8.8.8.8', 'root', '22 -oTest'), ('8.8.8.8', 'root', '65536')]:
            with self.subTest(host=host, user=user, port=port), \
                 mock.patch.object(deploy, 'prepare_tools') as prepare, \
                 contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(deploy.main([f'--host={host}', f'--user={user}', f'--port={port}']), 1)
                prepare.assert_not_called()
        self.assertEqual(deploy.target_settings('2606:4700:4700::1111', 'ubuntu', '2222'),
                         ('2606:4700:4700::1111', 'ubuntu', 2222))

    def test_password_validation_counts_utf8_bytes_and_confirms(self):
        for values in [ ['short'], ['я' * 40], [' long-enough-but-spaced '],
                        ['a' * 20, 'b' * 20] ]:
            with self.subTest(values=values), mock.patch.object(deploy, 'secret', side_effect=values), \
                 self.assertRaises(ValueError):
                deploy.admin_password()
        with mock.patch.object(deploy, 'secret', return_value=''):
            self.assertEqual(deploy.admin_password(), '')

    def test_refuses_echoed_password_fallback(self):
        def fallback(_):
            warnings.warn('No terminal', getpass.GetPassWarning)
            self.fail('must stop before reading an echoed password')
        with mock.patch.object(deploy.getpass, 'getpass', side_effect=fallback), \
             self.assertRaises(getpass.GetPassWarning):
            deploy.secret('Password: ')

    def test_prebuilt_mode_rejects_wrong_architecture(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(deploy, 'ROOT', Path(tmp)):
            build = Path(tmp) / 'build'
            build.mkdir()
            header = bytearray(20)
            header[:6] = b'\x7fELF\x02\x01'
            header[18:20] = b'\x3e\x00'
            for name in ('linevpn-server-linux-amd64', 'linevpn-keygen-linux-amd64'):
                (build / name).write_bytes(header)
            deploy.check_binaries()
            header[18:20] = b'\xb7\x00'  # aarch64
            (build / 'linevpn-keygen-linux-amd64').write_bytes(header)
            with self.assertRaises(ValueError):
                deploy.check_binaries()

    def exercise_deploy(self, *, failure=None, user='root'):
        admin = 'Admin-$() {{not_a_variable}}'
        sudo = 'sudo test password'
        seen = []
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            ansible = Path(tmp) / 'ansible'
            generated = ansible / 'generated'
            generated.mkdir(parents=True)
            (generated / 'vpn1-api-cert.pem').write_text('test certificate')
            (generated / 'vpn1-bootstrap.txt').write_text('linevpn://8.8.8.8:8443?pin=test\n')

            def fake_run(command, **kwargs):
                command = [str(x) for x in command]
                environment = (kwargs.get('env') or {}).copy()
                seen.append((command, environment))
                if command[0] == 'ansible-playbook':
                    data = Path(command[command.index('-i') + 1]).read_text()
                    self.assertNotIn(admin, data)
                    self.assertNotIn(sudo, data)
                    self.assertEqual(environment['LINEVPN_DEPLOY_ADMIN_PASSWORD'], admin)
                    self.assertEqual(environment['ANSIBLE_HOST_KEY_CHECKING'], 'True')
                    self.assertEqual(environment['LINEVPN_DEPLOY_BECOME_PASSWORD'], sudo if user != 'root' else '')
                    self.assertNotIn(admin, ' '.join(command))
                    if failure == 'ansible' and '--syntax-check' not in command:
                        raise RuntimeError('test deployment failure')
                if failure == 'ssh' and command[0] == 'ssh':
                    raise RuntimeError('test SSH failure')

            with mock.patch.object(deploy, 'ANSIBLE', ansible), \
                 mock.patch.object(deploy, 'run', side_effect=fake_run), \
                 mock.patch.object(deploy, 'secret', side_effect=[admin, admin, sudo]), \
                 mock.patch.object(deploy, 'verify', side_effect=OSError('test TLS error') if failure == 'tls' else None) as verify, \
                 mock.patch.object(deploy.subprocess, 'run') as cleanup, \
                 contextlib.redirect_stdout(output):
                if failure:
                    with self.assertRaises(RuntimeError):
                        deploy.deploy('ansible-playbook', {}, '8.8.8.8', user, 2222)
                else:
                    deploy.deploy('ansible-playbook', {}, '8.8.8.8', user, 2222)
                cleanup.assert_called_once()
                self.assertIn('exit', cleanup.call_args.args[0])
                if failure in ('ssh', 'ansible'):
                    verify.assert_not_called()
                else:
                    verify.assert_called_once_with('8.8.8.8', generated / 'vpn1-api-cert.pem')

        self.assertNotIn(admin, output.getvalue())
        self.assertNotIn(sudo, output.getvalue())
        for command, env in seen:
            if command[0] == 'ssh':
                self.assertFalse(any(name in env for name in deploy.SECRET_NAMES))
        socket = Path(seen[0][0][seen[0][0].index('-S') + 1])
        self.assertFalse(socket.parent.exists())
        return output.getvalue()

    def test_success_requires_both_deploy_and_external_verification(self):
        output = self.exercise_deploy(user='ubuntu')
        self.assertIn('Deployment verified.', output)
        self.assertIn('https://8.8.8.8:8443/', output)

    def test_failures_close_ssh_and_never_report_success(self):
        for failure in ('ssh', 'ansible', 'tls'):
            with self.subTest(failure=failure):
                self.assertNotIn('Deployment verified.', self.exercise_deploy(failure=failure))

    def test_entrypoint_help_works_from_another_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(['bash', str(deploy.ROOT / 'deploy.sh'), '--help'], cwd=tmp,
                                    capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--use-build', result.stdout)

    def test_windows_shell_payload_handles_spaces_unicode_and_metacharacters(self):
        # Exercise the actual BAT's Bash payload. cmd.exe/WSL itself still needs
        # a Windows native smoke test; this guards against shell interpolation.
        line = next(line for line in (deploy.ROOT / 'deploy.bat').read_text().splitlines()
                    if line.strip().startswith('wsl.exe --exec'))
        payload = line.split('bash -lc ', 1)[1][1:-1].replace('\\"', '"')
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "Проект & VPN ' $(touch injected)"
            repo.mkdir()
            (repo / 'deploy.sh').write_text('exit 17\n')
            env = dict(os.environ, LINEVPN_DEPLOY_WINDOWS_ROOT=str(repo))
            result = subprocess.run(['bash', '-c', payload], env=env, cwd=tmp)
            self.assertEqual(result.returncode, 17)
            self.assertFalse((Path(tmp) / 'injected').exists())

    @unittest.skipUnless(shutil.which('ansible-playbook'), 'requires deployment tools')
    @unittest.skipUnless(unix_sockets_available(), 'runtime forbids Unix sockets required by Ansible RPC')
    def test_real_ansible_treats_secret_as_literal_without_logging_it(self):
        password = "Literal{{do_not_evaluate}}$()'\"password"
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Path(tmp) / 'inventory.json'
            inventory.write_text(json.dumps(deploy.inventory('8.8.8.8', 'root', 22, '/tmp/ssh')))
            playbook = Path(tmp) / 'check.yml'
            playbook.write_text('''- hosts: vpn
  connection: local
  gather_facts: false
  tasks:
    - name: Check literal password
      ansible.builtin.assert:
        that: vpn_admin_password == lookup('ansible.builtin.env', 'LINEVPN_DEPLOY_ADMIN_PASSWORD')
      no_log: true
''')
            env = dict(os.environ, LINEVPN_DEPLOY_ADMIN_PASSWORD=password)
            result = subprocess.run(['ansible-playbook', '-i', str(inventory), str(playbook)],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn(password, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
