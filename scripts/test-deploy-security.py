"""Security regressions use synthetic credentials and never contact a VPS."""
import os
import hashlib
import io
import json
import shutil
import tarfile
import textwrap
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
BASH = os.environ.get('TEST_BASH', 'bash')

class DeploymentSecurityTest(unittest.TestCase):
    def shell(self, code, **kwargs):
        return subprocess.run([BASH, '-c', 'source ./deploy.sh; ' + code], cwd=ROOT,
                              capture_output=True, text=True, **kwargs)

    def test_invalid_base64_never_emits_partial_output(self):
        result = self.shell("decode64 'YWJj!'")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_invalid_or_nonpublic_addresses_rejected_before_connection(self):
        for host in ['dead.beef', '...', '1.2', '999.999.999.999', '127.0.0.1', '10.0.0.1', '::1', 'fe80::1']:
            with self.subTest(host=host):
                env = dict(os.environ, TEST_HOST=host)
                result = self.shell('linevpn_host=$TEST_HOST; linevpn_port=22; linevpn_user=root; linevpn_password=test; linevpn_admin=synthetic-admin-password; validate_inputs', env=env)
                self.assertNotEqual(result.returncode, 0)

    def test_askpass_does_not_export_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'ssh').write_text('#!/bin/sh\n[ -z "${LINEVPN_SSH_PASSWORD+x}" ] || exit 99\n"$SSH_ASKPASS"\n')
            (p/'ssh').chmod(0o700)
            (p/'askpass').write_text('#!/bin/sh\nprintf synthetic-password\n')
            (p/'askpass').chmod(0o700)
            env = dict(os.environ, PATH=tmp+os.pathsep+os.environ['PATH'], TEST_TMP=tmp)
            result = self.shell('linevpn_tmp=$TEST_TMP; linevpn_host=8.8.8.8; linevpn_user=root; linevpn_port=22; linevpn_password=synthetic-password; linevpn_ssh_opts=(-o StrictHostKeyChecking=yes); ssh_run true', env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'synthetic-password')

    def test_ssh_arguments_stdin_environment_and_exit_status(self):
        with tempfile.TemporaryDirectory(prefix='vpn ssh ') as tmp:
            stub = Path(tmp) / 'ssh'
            stub.write_text(textwrap.dedent('''\
                #!/usr/bin/env python3
                import json, os, sys
                print(json.dumps({
                    'args': sys.argv[1:],
                    'stdin': sys.stdin.read(),
                    'askpass': os.environ['SSH_ASKPASS'],
                    'require': os.environ['SSH_ASKPASS_REQUIRE'],
                    'display': os.environ['DISPLAY'],
                }))
                sys.exit(int(os.environ['TEST_EXIT']))
            '''))
            stub.chmod(0o700)
            code = ('linevpn_tmp=$TEST_TMP; linevpn_host=8.8.8.8; linevpn_user=root; '
                    'linevpn_port=2222; linevpn_ssh_opts=(-i "$TEST_TMP/key file" '
                    '-o StrictHostKeyChecking=yes); ssh_run "$TEST_COMMAND" ""')
            command = "printf '%s' 'literal $() * words'"
            for deadline in (None, '', '5'):
                for status in (0, 42):
                    with self.subTest(deadline=deadline, status=status):
                        env = dict(os.environ, PATH=tmp+os.pathsep+os.environ['PATH'],
                                   TEST_TMP=tmp, TEST_COMMAND=command, TEST_EXIT=str(status))
                        env.pop('linevpn_deadline', None)
                        if deadline is not None:
                            env['linevpn_deadline'] = deadline
                        result = self.shell(code, env=env, input='synthetic input\n', timeout=10)
                        self.assertEqual(result.returncode, status, result.stderr)
                        self.assertEqual(json.loads(result.stdout), {
                            'args': ['-F', '/dev/null', '-T', '-p', '2222', '-i', tmp+'/key file',
                                     '-o', 'StrictHostKeyChecking=yes',
                                     '-o', 'PreferredAuthentications=publickey,password',
                                     '-o', 'PubkeyAuthentication=yes',
                                     '-o', 'NumberOfPasswordPrompts=1', '-o', 'ConnectTimeout=20',
                                     '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
                                     'root@8.8.8.8', command, ''],
                            'stdin': 'synthetic input\n', 'askpass': tmp+'/askpass',
                            'require': 'force', 'display': 'linevpn:0',
                        })

    def test_ssh_deadline_terminates_stalled_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / 'ssh'
            stub.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n')
            stub.chmod(0o700)
            env = dict(os.environ, PATH=tmp+os.pathsep+os.environ['PATH'], TEST_TMP=tmp)
            result = self.shell('linevpn_tmp=$TEST_TMP; linevpn_host=8.8.8.8; '
                                'linevpn_user=root; linevpn_port=22; '
                                'linevpn_ssh_opts=(-o StrictHostKeyChecking=yes); '
                                'linevpn_deadline=1 ssh_run true', env=env, timeout=10)
            self.assertEqual(result.returncode, 124, result.stderr)

    def test_fingerprint_trusts_only_matching_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            keys=[]
            for i in range(2):
                key=root/f'key{i}'
                subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
                keys.append(key)
            scan=root/'scan'
            scan.write_text(''.join('8.8.8.8 '+key.with_suffix('.pub').read_text() for key in keys))
            bin=root/'bin';bin.mkdir()
            (bin/'ssh-keyscan').write_text('#!/bin/sh\ncat "$TEST_SCAN"\n')
            (bin/'ssh-keyscan').chmod(0o700)
            fingerprint=subprocess.check_output(['ssh-keygen','-E','sha256','-lf',str(keys[0])],text=True).split()[1]
            env=dict(os.environ,PATH=str(bin)+os.pathsep+os.environ['PATH'],TEST_SCAN=str(scan),TEST_TMP=tmp,VPS_HOST_FINGERPRINT=fingerprint)
            code='linevpn_tmp=$TEST_TMP; linevpn_host=8.8.8.8; linevpn_port=22; configure_ssh'
            result=self.shell(code,env=env)
            self.assertEqual(result.returncode,0,result.stderr)
            trusted=(root/'known_hosts').read_text().splitlines()
            self.assertEqual(len(trusted),1)
            self.assertIn(keys[0].with_suffix('.pub').read_text().split()[1],trusted[0])
            env['VPS_HOST_FINGERPRINT']='SHA256:'+'A'*43
            result=self.shell(code,env=env)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual((root/'known_hosts').read_text(),'')

    @unittest.skipUnless(Path('/dev/shm').is_dir(), 'Linux RAM staging fixture')
    def test_bootstrap_unlinks_before_apt_and_isolates_sudo_stdin(self):
        for mode in ('root','nopasswd','password'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);bin=root/'bin';bin.mkdir()
                work=Path(subprocess.check_output(['mktemp','-d','/dev/shm/linevpn-deploy.XXXXXXXX'],text=True).strip())
                try:
                    shutil.copy2(ROOT/'scripts/deploy-bootstrap.sh',work/'bootstrap.sh')
                    (work/'input').write_text('8.8.8.8\n22\nsynthetic-ssh-password\nsynthetic-admin-password\n')
                    script=b"import sys,os; data=sys.stdin.read(); assert data=='8.8.8.8\\n22\\nsynthetic-admin-password\\n',repr(data); print('BOOTSTRAP_OK')"
                    with tarfile.open(work/'source.tar.gz','w:gz') as tar:
                        info=tarfile.TarInfo('scripts/deploy-remote.py');info.size=len(script);tar.addfile(info,io.BytesIO(script))
                    (work/'source.sha256').write_text(hashlib.sha256((work/'source.tar.gz').read_bytes()).hexdigest()+'  source.tar.gz\n')
                    (bin/'id').write_text('#!/bin/sh\necho "${TEST_UID:-0}"\n')
                    (bin/'chown').write_text('#!/bin/sh\nexit 0\n')
                    (bin/'apt-get').write_text('#!/bin/sh\n[ ! -e "$TEST_WORK/input" ] || exit 91\n[ -z "$(cat)" ] || exit 92\n')
                    (bin/'sudo').write_text(textwrap.dedent('''\
                        #!/bin/bash
                        set -e
                        if [[ "$*" == '-n true' ]]; then [[ "$TEST_MODE" == nopasswd ]]; exit; fi
                        if [[ "$1" == -S ]]; then
                          read -r pw
                          [[ "$pw" == synthetic-ssh-password ]] || exit 93
                          exit 0
                        fi
                        [[ "$1" == -n ]] || exit 94
                        shift
                        TEST_UID=0 exec "$@"
                    '''))
                    for tool in bin.iterdir(): tool.chmod(0o700)
                    env=dict(os.environ,PATH=str(bin)+os.pathsep+os.environ['PATH'],TEST_UID='0' if mode=='root' else '1000',TEST_MODE=mode,TEST_WORK=str(work))
                    result=subprocess.run(['bash',str(work/'bootstrap.sh'),str(work)],env=env,capture_output=True,text=True,timeout=15)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    self.assertIn('BOOTSTRAP_OK',result.stdout)
                    self.assertFalse(work.exists())
                    self.assertNotIn('synthetic-',result.stdout+result.stderr)
                finally:
                    shutil.rmtree(work,ignore_errors=True)

if __name__ == '__main__':
    unittest.main()
