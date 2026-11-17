#!/usr/bin/env python3
"""Interactive SSH deployment using the same Ansible playbook as Actions."""
import argparse
import getpass
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import warnings

ROOT = Path(__file__).resolve().parent.parent
ANSIBLE = ROOT / 'deploy' / 'ansible'
SECRET_NAMES = ('LINEVPN_DEPLOY_ADMIN_PASSWORD', 'LINEVPN_DEPLOY_BECOME_PASSWORD')
SERVER_PACKAGES = ('./internal/policy', './internal/secure', './internal/server', './internal/transport')


def run(command, *, cwd=ROOT, env=None, quiet=False):
    # Never invoke a shell or print a command/env containing credentials.
    result = subprocess.run([str(item) for item in command], cwd=cwd, env=env,
                            stdout=subprocess.DEVNULL if quiet else None,
                            stderr=subprocess.DEVNULL if quiet else None)
    if result.returncode:
        raise RuntimeError(f'{Path(command[0]).name} failed (exit {result.returncode}).')


def secret(prompt):
    # getpass must never fall back to an echoed stdin password.
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        return getpass.getpass(prompt)


def target_settings(host, user, port):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError('Use a public IP address, without a URL, SSH username or port.') from None
    if not address.is_global:
        raise ValueError('The server address must be a public IPv4 or IPv6 address.')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}\$?', user):
        raise ValueError('Invalid Linux SSH username.')
    if not str(port).isascii() or not str(port).isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('SSH port must be between 1 and 65535.')
    return str(address), user, int(port)


def admin_password():
    password = secret('Admin password (empty = generate once / keep existing): ')
    if password:
        if not 16 <= len(password.encode('utf-8')) <= 72 or password != password.strip():
            raise ValueError('Admin password must be 16-72 UTF-8 bytes, without surrounding whitespace.')
        if secret('Repeat admin password: ') != password:
            raise ValueError('Admin passwords do not match.')
    return password


def check_binaries():
    for name in ('linevpn-server-linux-amd64', 'linevpn-keygen-linux-amd64'):
        path = ROOT / 'build' / name
        if not path.is_file():
            raise ValueError(f'Missing {path}. Build first or run without --use-build.')
        with path.open('rb') as binary:
            header = binary.read(20)
        if len(header) < 20 or header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\x3e\x00':
            raise ValueError(f'{name} must be a Linux amd64 ELF binary.')


def prepare_tools(use_build):
    if sys.version_info < (3, 12):
        raise ValueError('Python 3.12+ is required on this computer (or inside WSL).')
    missing = [name for name in ('ssh', 'bash') if not shutil.which(name)]
    if not use_build and not shutil.which('go'):
        missing.append('go (1.27.4+)')
    if missing:
        raise ValueError('Missing tools: ' + ', '.join(missing) +
                         '. See docs/deployment.md; install Go inside WSL when using deploy.bat.')
    if use_build:
        check_binaries()
    else:
        result = subprocess.run(['go', 'version'], capture_output=True, text=True, check=True)
        match = re.search(r'go(\d+)\.(\d+)(?:\.(\d+))?', result.stdout)
        if not match or tuple(int(part or 0) for part in match.groups()) < (1, 27, 4):
            raise ValueError('Install Go 1.27.4+ before building the server.')

    cache = Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'linevpn'
    venv = cache / f'deploy-python{sys.version_info.major}.{sys.version_info.minor}'
    python = venv / 'bin' / 'python'
    if not python.is_file():
        print('Preparing isolated Ansible environment...', flush=True)
        try:
            run([sys.executable, '-m', 'venv', venv])
        except RuntimeError:
            raise RuntimeError('Cannot create the Python environment. On Ubuntu/WSL install python3-venv.') from None
    run([python, '-m', 'pip', 'install', '--disable-pip-version-check', '-r', ROOT / 'deploy/requirements.txt'])
    # Explicit config matters on Windows-mounted WSL directories, where Ansible
    # deliberately ignores automatic discovery from world-writable working dirs.
    env = os.environ.copy()
    env['ANSIBLE_CONFIG'] = str(ANSIBLE / 'ansible.cfg')
    run([venv / 'bin/ansible-galaxy', 'collection', 'install', '-r', ANSIBLE / 'requirements.yml'], env=env)
    if not use_build:
        print('Testing and building the Linux amd64 server...', flush=True)
        run(['go', 'test', *SERVER_PACKAGES])
        run(['bash', ROOT / 'scripts/build-server.sh'])
        check_binaries()
    return venv / 'bin/ansible-playbook', env


def ssh_command(host, user, port, socket, key=None):
    command = ['ssh', '-p', str(port), '-S', str(socket), '-o', 'ConnectTimeout=20',
               '-o', 'ConnectionAttempts=2']
    if key:
        command.extend(['-i', str(key), '-o', 'IdentitiesOnly=yes'])
    return command, f'{user}@{host}'


def inventory(host, user, port, socket):
    # The password is resolved from the child process environment, never written
    # to disk or embedded as Jinja source. SSH authentication stays with OpenSSH.
    ssh_args = shlex.join(['-C', '-o', 'ControlMaster=auto', '-o', 'ControlPersist=300',
                          '-o', f'ControlPath={socket}', '-o', 'StrictHostKeyChecking=yes',
                          '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=20'])
    values = {'ansible_host': host, 'ansible_user': user, 'ansible_port': port,
              'vpn_public_ip': host, 'vpn_ssh_port': port, 'ansible_ssh_args': ssh_args,
              'ansible_become_password': "{{ lookup('ansible.builtin.env', 'LINEVPN_DEPLOY_BECOME_PASSWORD') }}",
              'vpn_admin_password': "{{ lookup('ansible.builtin.env', 'LINEVPN_DEPLOY_ADMIN_PASSWORD') }}"}
    return {'all': {'children': {'vpn': {'hosts': {'vpn1': values}}}}}


def verify(host, certificate):
    spec = importlib.util.spec_from_file_location('deploy_actions', ROOT / 'scripts/deploy-actions.py')
    actions = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(actions)
    actions.verify(host, str(certificate))


def deploy(playbook, env, host, user, port, key=None):
    # Keep socket names short enough for macOS/Unix domain sockets even when the
    # checkout or user's cache directory has a long path or contains spaces.
    with tempfile.TemporaryDirectory(prefix='linevpn-', dir='/tmp') as tmp:
        socket = Path(tmp) / 'ssh'
        command, destination = ssh_command(host, user, port, socket, key)
        try:
            print('\nConnecting over SSH. Verify a new host fingerprint against your VPS console.', flush=True)
            print('SSH will ask for its password/key passphrase if needed; it is not saved by this script.', flush=True)
            run([*command, '-o', 'StrictHostKeyChecking=ask', '-o', 'ControlMaster=yes',
                 '-o', 'ControlPersist=300', '-fN', destination])
            # Fail early with a clear diagnostic before Ansible tries to gather facts.
            print('Checking Python on the VPS...', flush=True)
            run([*command, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', destination,
                 'python3 --version'])

            child_env = env.copy()
            child_env['ANSIBLE_HOST_KEY_CHECKING'] = 'True'
            child_env['LINEVPN_DEPLOY_ADMIN_PASSWORD'] = admin_password()
            child_env['LINEVPN_DEPLOY_BECOME_PASSWORD'] = (
                secret('sudo password on VPS (empty for passwordless sudo): ') if user != 'root' else '')
            inventory_path = Path(tmp) / 'inventory.json'
            inventory_path.write_text(json.dumps(inventory(host, user, port, socket)), encoding='utf-8')
            inventory_path.chmod(0o600)
            try:
                run([playbook, '-i', inventory_path, ANSIBLE / 'deploy.yml', '--syntax-check'], cwd=ANSIBLE, env=child_env)
                print('Deploying: installs/updates LineVPN, enables UFW for SSH/443/8443, and restarts the service.', flush=True)
                run([playbook, '-i', inventory_path, ANSIBLE / 'deploy.yml'], cwd=ANSIBLE, env=child_env)
            finally:
                for name in SECRET_NAMES:
                    child_env.pop(name, None)

            certificate = ANSIBLE / 'generated/vpn1-api-cert.pem'
            print('Verifying HTTPS with the SSH-fetched certificate and TCP 443...', flush=True)
            try:
                verify(host, certificate)
            except Exception as error:
                raise RuntimeError('External verification failed (' + type(error).__name__ +
                                   '). Check TCP 443/8443 in the VPS firewall and journalctl -u linevpn.') from None
            profile = (ANSIBLE / 'generated/vpn1-bootstrap.txt').read_text(encoding='utf-8').strip()
        finally:
            # Best effort even after interruption or a failed deployment. No secret output.
            try:
                subprocess.run([*command, '-O', 'exit', destination], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=10, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass  # ControlPersist will expire; preserve the original deployment error.
    address = f'[{host}]' if ':' in host else host
    password_command = ['ssh', '-t', '-p', str(port)]
    if key:
        password_command.extend(['-i', str(key)])
    password_command.extend([destination, 'sudo cat /etc/linevpn/admin-password' if user != 'root'
                              else 'cat /etc/linevpn/admin-password'])
    print('\nDeployment verified.')
    print(f'Admin: https://{address}:8443/')
    print(f'Server profile: {profile}')
    print(f'API certificate for browser trust: {certificate}')
    print('Read the admin password over SSH: ' + shlex.join(password_command))
    print('Import the profile into the client, register, approve the account in the admin panel, then test the tunnel.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', help='Public VPS IP; otherwise prompted')
    parser.add_argument('--user', help='SSH user; otherwise prompted (default root)')
    parser.add_argument('--port', help='SSH port; otherwise prompted (default 22)')
    parser.add_argument('--key', type=Path, help='Optional SSH private key (never copied to the server)')
    parser.add_argument('--use-build', action='store_true', help='Deploy existing Linux amd64 binaries in build/ without Go/tests')
    args = parser.parse_args(argv)
    try:
        if os.name != 'posix':
            raise ValueError('On Windows use deploy.bat with a Linux WSL distribution.')
        host, user, port = target_settings(args.host or input('VPS public IP: ').strip(),
                                          args.user or input('SSH user [root]: ').strip() or 'root',
                                          args.port or input('SSH port [22]: ').strip() or '22')
        key = args.key.expanduser().resolve() if args.key else None
        if key and not key.is_file():
            raise ValueError('The selected SSH private key does not exist.')
        print(f'Preparing deployment to {user}@{host}, SSH port {port}.', flush=True)
        playbook, env = prepare_tools(args.use_build)
        deploy(playbook, env, host, user, port, key)
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError,
            EOFError, getpass.GetPassWarning) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nDeployment interrupted. A completed server change is not rolled back; rerun to continue.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
