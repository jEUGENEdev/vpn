"""Real password authentication against an in-process SSH fixture; never installs on a VPS."""
import base64
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest

import paramiko

ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "test SSH' $() & {{password}}"
ADMIN = 'test admin $() & {{password}}'


class SSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.command = None
        self.ready = threading.Event()

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if username == 'tester' and password == PASSWORD else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode()
        self.ready.set()
        return True


class PasswordSSHTest(unittest.TestCase):
    def test_real_openssh_askpass_and_streamed_credentials(self):
        key = paramiko.RSAKey.generate(2048)
        received = []
        with tempfile.TemporaryDirectory() as tmp, socket.socket() as listener:
            tmp = Path(tmp)
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(0.2)
            port = listener.getsockname()[1]
            stopping = threading.Event()
            errors = []

            def handle(connection):
                try:
                    with paramiko.Transport(connection) as transport:
                        transport.add_server_key(key)
                        server = SSHServer()
                        transport.start_server(server=server)
                        channel = transport.accept(20)
                        if channel is None or not server.ready.wait(20):
                            raise RuntimeError('No SSH exec request')
                        command = server.command
                        self.assertNotIn(PASSWORD, command)
                        self.assertNotIn(ADMIN, command)
                        if 'mktemp -d' in command:
                            channel.sendall(b'/dev/shm/linevpn-deploy.1234abcd\n')
                        elif command.startswith('umask'):
                            received.append(channel.makefile('rb').read())
                        elif 'cat >' in command:
                            channel.makefile('rb').read()
                        elif command.startswith(('bash ', 'if ')):
                            profile = base64.b64encode(b'linevpn://127.0.0.1:8443?pin=test\n').decode()
                            cert = base64.b64encode(b'test certificate').decode()
                            sni = base64.b64encode(b'example.org').decode()
                            channel.sendall(f'LINEVPN_PROFILE_B64={profile}\nLINEVPN_CERT_B64={cert}\nLINEVPN_REALITY_SNI_B64={sni}\nLINEVPN_REMOTE_OK=1\n'.encode())
                        channel.send_exit_status(1 if command == 'if fail-fixture' else 0)
                        channel.close()
                        # Let OpenSSH consume CHANNEL_CLOSE and disconnect before
                        # closing TCP; immediate close can reset unread SSH data.
                        transport.join(2)
                except Exception as error:
                    errors.append(error)

            def serve():
                while not stopping.is_set():
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    threading.Thread(target=handle, args=(connection,), daemon=True).start()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            try:
                # Use the real source but keep generated test profiles outside the checkout.
                root = tmp / 'source'
                root.mkdir()
                for entry in (ROOT / 'deploy/source-files.txt').read_text().splitlines() + ['deploy/source-files.txt', 'scripts/deploy-bootstrap.sh']:
                    source, target = ROOT / entry, root / entry
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if source.is_dir():
                        shutil.copytree(source, target)
                    else:
                        shutil.copy2(source, target)
                known_hosts = tmp / 'known_hosts'
                known_hosts.write_text(f'[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n')
                tools = tmp / 'bin'
                tools.mkdir()
                ssh = tools / 'ssh'
                ssh.write_text('#!/bin/sh\nexec /usr/bin/ssh -o "UserKnownHostsFile=$TEST_KNOWN_HOSTS" -o GlobalKnownHostsFile=/dev/null "$@"\n')
                ssh.chmod(0o755)
                env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                           VPS_HOST='127.0.0.1', VPS_PORT=str(port), VPS_USERNAME='tester',
                           VPS_PASSWORD=PASSWORD, VPN_ADMIN_PASSWORD=ADMIN,
                           TEST_KNOWN_HOSTS=str(known_hosts), TEST_ROOT=str(root), TEST_LAUNCHER=str(ROOT / 'deploy.sh'))
                result = subprocess.run(['bash', '-c', 'source "$TEST_LAUNCHER"; linevpn_root=$TEST_ROOT; prepare_source() { tar -czf "$linevpn_tmp/source.tar.gz" -C "$linevpn_root" -T "$linevpn_root/deploy/source-files.txt"; }; verify_public() { return 0; }; original_validate=$(declare -f validate_inputs); validate_inputs() { local linevpn_host=8.8.8.8; eval "${original_validate/validate_inputs/original_validate}"; original_validate; }; main'],
                                        env=env, capture_output=True, text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Deployment verified:', result.stdout)
                self.assertEqual(received, [f'127.0.0.1\n{port}\n{PASSWORD}\n{ADMIN}\n'.encode()])
                self.assertNotIn(PASSWORD, result.stdout + result.stderr)
                self.assertFalse(errors, errors)
                # Optional native PowerShell/SSH.NET smoke check against the same
                # fixture. No public VPS, sudo or package installation is involved.
                if os.environ.get('TEST_PWSH') and os.environ.get('TEST_POSH_MODULE'):
                    script = tmp / 'ssh.ps1'
                    script.write_text('''$ErrorActionPreference = 'Stop'
Import-Module $env:TEST_POSH_MODULE
. $env:TEST_PS_LAUNCHER
$credential = New-Object Management.Automation.PSCredential('tester', (ConvertTo-SecureString $env:TEST_PASSWORD -AsPlainText -Force))
$store = New-SSHMemoryTrustedHostStore
$session = New-SSHSession -ComputerName 127.0.0.1 -Port ([int]$env:TEST_PORT) -Credential $credential -AcceptKey -TrustedHostStore $store
try {
    $data = Invoke-RemoteDeployment $session 'if fixture'
    if ($data['REMOTE_OK'] -ne '1') { throw 'Missing SSH.NET result.' }
    $methods = [Renci.SshNet.SftpClient].GetMethods().Name
    foreach ($name in @('UploadFile', 'OpenWrite', 'ChangePermissions')) {
        if ($methods -notcontains $name) { throw "Missing SFTP API: $name" }
    }
} finally { Remove-SSHSession -SessionId $session.SessionId | Out-Null }
$session = New-SSHSession -ComputerName 127.0.0.1 -Port ([int]$env:TEST_PORT) -Credential $credential -AcceptKey -TrustedHostStore $store
try {
    $rejected = $false
    try { Invoke-RemoteDeployment $session 'if fail-fixture' | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Failed remote exit status was accepted.' }
} finally { Remove-SSHSession -SessionId $session.SessionId | Out-Null }
''')
                    ps_env = dict(os.environ, TEST_PASSWORD=PASSWORD, TEST_PORT=str(port),
                                  TEST_PS_LAUNCHER=str(ROOT / 'scripts/deploy-windows.ps1'))
                    ps = subprocess.run([os.environ['TEST_PWSH'], '-NoProfile', '-File', str(script)], env=ps_env,
                                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(ps.returncode, 0, ps.stdout + ps.stderr)
                    self.assertNotIn(PASSWORD, ps.stdout + ps.stderr)
            finally:
                stopping.set()
                thread.join(2)


if __name__ == '__main__':
    unittest.main()
