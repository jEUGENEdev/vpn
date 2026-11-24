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

    def test_verification_authenticates_tls_and_checks_public_admin_authorization(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b'{"status":"ok"}'
        page = mock.MagicMock()
        page.__enter__.return_value = page
        page.status = 200
        page.headers = {'Content-Type': 'text/html; charset=utf-8'}
        page.read.return_value = b'<form id="login-form"></form>'
        denied = deploy.urllib.error.HTTPError('https://fixture',401,'unauthorized',{},None)
        with mock.patch.object(deploy.ssl,'create_default_context') as context, \
             mock.patch.object(deploy.urllib.request,'build_opener') as opener, \
             mock.patch.object(deploy.socket,'create_connection') as tcp:
            opener.return_value.open.side_effect = [response, page] + [denied] * 7
            deploy.verify('2606:4700:4700::1111','trusted.pem')
            self.assertEqual(context.call_args_list[0],mock.call(cafile='trusted.pem'))
            tcp.assert_called_once_with(('2606:4700:4700::1111',443),timeout=20)
            context.return_value.wrap_socket.assert_called_once()
            self.assertEqual(context.return_value.minimum_version, deploy.ssl.TLSVersion.TLSv1_3)
            for call in opener.return_value.open.call_args_list[2:]:
                request = call.args[0]
                self.assertTrue(request.full_url.startswith('https://[2606:4700:4700::1111]:8443/api/admin/'))
                self.assertIsNone(request.get_header('Authorization'))
            for status in (200, 403, 404, 500):
                for endpoint in range(7):
                    with self.subTest(status=status, endpoint=endpoint):
                        unexpected = response if status == 200 else deploy.urllib.error.HTTPError('https://fixture',status,'failed',{},None)
                        opener.return_value.open.side_effect = [response, page] + [denied] * endpoint + [unexpected]
                        with self.assertRaises(RuntimeError):
                            deploy.verify('8.8.8.8','trusted.pem')
            for content in (b'wrong application', b'{"status":"ok"}'):
                page.read.return_value = content
                opener.return_value.open.side_effect = [response, page]
                with self.assertRaises(RuntimeError):
                    deploy.verify('8.8.8.8','trusted.pem')

    @unittest.skipUnless(shutil.which('ansible-playbook'), 'requires deployment tools')
    def test_admin_hash_survives_redeploy(self):
        import yaml
        root = SCRIPT.parent.parent
        play = yaml.safe_load((root / 'deploy/ansible/deploy.yml').read_text())[0]
        task = copy.deepcopy(next(t for t in play['tasks'] if t['name'] ==
                                 'Install configured admin password hash'))
        task.pop('notify')
        with tempfile.TemporaryDirectory() as tmp:
            password_file = Path(tmp) / 'admin-password'
            task['ansible.builtin.copy'].update(dest=str(password_file),
                owner=pwd.getpwuid(os.getuid()).pw_name,
                group=grp.getgrgid(os.getgid()).gr_name)
            local_play = [{'hosts': 'localhost', 'gather_facts': False, 'connection': 'local',
                           'vars': {'vpn_admin_password': 'synthetic test password', 'vpn_admin_hash':{'stdout':'bcrypt-hash-from-keygen'},
                                    'ansible_python_interpreter': sys.executable}, 'tasks': [task]}]
            playbook = Path(tmp) / 'test.yml'
            playbook.write_text(yaml.safe_dump(local_play))
            command = ['ansible-playbook', '-i', 'localhost,', str(playbook)]
            def run_playbook():
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            run_playbook()
            generated = password_file.read_text()
            self.assertEqual(generated, 'bcrypt-hash-from-keygen')
            self.assertEqual(stat.S_IMODE(password_file.stat().st_mode), 0o640)
            local_play[0]['vars']['vpn_admin_password']=''
            playbook.write_text(yaml.safe_dump(local_play))
            run_playbook()
            self.assertEqual(password_file.read_text(), generated)
            local_play[0]['vars']['vpn_admin_password'] = 'Explicit admin test password'
            local_play[0]['vars']['vpn_admin_hash']['stdout'] = 'new-bcrypt-hash'
            playbook.write_text(yaml.safe_dump(local_play))
            run_playbook()
            self.assertEqual(password_file.read_text(), 'new-bcrypt-hash')


if __name__ == '__main__':
    unittest.main()
