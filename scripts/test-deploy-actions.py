import importlib.util
import copy
import grp
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name('deploy-actions.py')
spec = importlib.util.spec_from_file_location('deploy_actions', SCRIPT)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class DeploymentSettingsTest(unittest.TestCase):
    def setUp(self):
        self.env = {'VPS_HOST': '8.8.8.8', 'VPS_USERNAME': 'root',
                    'VPS_PASSWORD': 'opaque \' " $() {{example}}\npassword'}

    def test_missing_secrets_fail_without_disclosing_values(self):
        env = dict(os.environ, **self.env)
        env.pop('VPS_USERNAME')
        result = subprocess.run([sys.executable, str(SCRIPT)], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('VPS_USERNAME', result.stderr)
        self.assertNotIn(self.env['VPS_PASSWORD'], result.stdout + result.stderr)
        self.assertNotIn(self.env['VPS_HOST'], result.stdout + result.stderr)

    def test_password_is_not_modified_or_interpreted(self):
        original = self.env.copy()
        self.assertEqual(deploy.settings(self.env), ('8.8.8.8', 22))
        self.assertEqual(self.env, original)

    def test_rejects_address_and_username_injection(self):
        for key, value in [('VPS_HOST', 'root@8.8.8.8'), ('VPS_HOST', '8.8.8.8;whoami'),
                           ('VPS_HOST', '127.0.0.1'), ('VPS_USERNAME', '-oProxyCommand=x')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                deploy.settings(dict(self.env, **{key: value}))

    def test_ipv6_and_custom_port(self):
        self.assertEqual(deploy.settings(dict(self.env, VPS_HOST='2606:4700:4700::1111',
                                             VPS_PORT='2222')), ('2606:4700:4700::1111', 2222))

    def test_rejects_bad_port_and_multibyte_admin_password(self):
        for port in ['0', '65536', '22 -oTest', 'invalid']:
            with self.subTest(port=port), self.assertRaises(ValueError):
                deploy.settings(dict(self.env, VPS_PORT=port))
        with self.assertRaises(ValueError):
            deploy.settings(dict(self.env, VPN_ADMIN_PASSWORD='я' * 40))

    def test_verification_uses_trusted_certificate_and_requires_both_ports(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b'{"status":"ok"}'
        with mock.patch.object(deploy.ssl, 'create_default_context') as ssl_context, \
             mock.patch.object(deploy.urllib.request, 'build_opener') as build_opener, \
             mock.patch.object(deploy.socket, 'create_connection') as tcp:
            build_opener.return_value.open.return_value = response
            deploy.verify('2606:4700:4700::1111', 'trusted.pem')
            ssl_context.assert_called_once_with(cafile='trusted.pem')
            build_opener.return_value.open.assert_called_once_with(
                'https://[2606:4700:4700::1111]:8443/healthz', timeout=20)
            tcp.assert_called_once_with(('2606:4700:4700::1111', 443), timeout=20)
            response.read.return_value = b'{"status":"broken"}'
            with self.assertRaises(RuntimeError):
                deploy.verify('8.8.8.8', 'trusted.pem')

    @unittest.skipUnless(shutil.which('ansible-playbook'), 'requires deployment tools')
    def test_generated_admin_password_survives_redeploy(self):
        import yaml
        root = SCRIPT.parent.parent
        play = yaml.safe_load((root / 'deploy/ansible/deploy.yml').read_text())[0]
        task = copy.deepcopy(next(t for t in play['tasks'] if t['name'] ==
                                 'Install configured admin password or generate it once'))
        task.pop('notify')
        with tempfile.TemporaryDirectory() as tmp:
            password_file = Path(tmp) / 'admin-password'
            task['ansible.builtin.copy'].update(dest=str(password_file),
                owner=pwd.getpwuid(os.getuid()).pw_name,
                group=grp.getgrgid(os.getgid()).gr_name)
            local_play = [{'hosts': 'localhost', 'gather_facts': False, 'connection': 'local',
                           'vars': {'vpn_admin_password': '',
                                    'ansible_python_interpreter': sys.executable}, 'tasks': [task]}]
            playbook = Path(tmp) / 'test.yml'
            playbook.write_text(yaml.safe_dump(local_play))
            command = ['ansible-playbook', '-i', 'localhost,', str(playbook)]
            def run_playbook():
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            run_playbook()
            generated = password_file.read_text()
            self.assertEqual(len(generated), 48)
            self.assertEqual(stat.S_IMODE(password_file.stat().st_mode), 0o600)
            run_playbook()
            self.assertEqual(password_file.read_text(), generated)
            local_play[0]['vars']['vpn_admin_password'] = 'Explicit admin test password'
            playbook.write_text(yaml.safe_dump(local_play))
            run_playbook()
            self.assertEqual(password_file.read_text(), 'Explicit admin test password')


if __name__ == '__main__':
    unittest.main()
