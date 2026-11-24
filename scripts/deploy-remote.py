#!/usr/bin/env python3
"""Runs as root on the VPS after the SSH bootstrap installs Python."""
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
TOOLS = Path('/opt/linevpn-tools')


def read_input(stream):
    try:
        lines = stream.read().decode('utf-8').split('\n')
    except UnicodeDecodeError:
        raise ValueError('Bootstrap input must be UTF-8.') from None
    if lines and lines[-1] == '':
        lines.pop()
    if len(lines) != 3:
        raise ValueError('Expected host, port and VPN admin password.')
    host = ipaddress.ip_address(lines[0])
    if not host.is_global or host.is_multicast or host.is_reserved:
        raise ValueError('host must be a public IP address.')
    if not lines[1].isascii() or not lines[1].isdigit() or not 1 <= int(lines[1]) <= 65535:
        raise ValueError('Invalid SSH port.')
    admin = lines[2]
    if not 16 <= len(admin.encode('utf-8')) <= 72 or admin != admin.strip() or '\r' in admin or '\0' in admin:
        raise ValueError('VPN admin password must be 16-72 UTF-8 bytes without surrounding whitespace.')
    return str(host), int(lines[1]), admin


def run(command, *, env=None):
    result = subprocess.run([str(item) for item in command], cwd=ROOT, env=env, stdin=subprocess.DEVNULL)
    if result.returncode:
        raise RuntimeError(f'{Path(command[0]).name} failed (exit {result.returncode}).')


def verify_binaries():
    build = ROOT / 'build'
    manifest = build / 'SHA256SUMS'
    expected = {}
    for line in manifest.read_text(encoding='ascii').splitlines():
        digest, name = line.split()
        if name in expected or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise RuntimeError('Invalid server binary checksum manifest.')
        expected[name] = digest
    names = {'linevpn-server-linux-amd64', 'linevpn-keygen-linux-amd64'}
    if set(expected) != names:
        raise RuntimeError('Expected both prebuilt Linux amd64 server binaries.')
    for name in sorted(names):
        path = build / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('Server binary must be a regular file.')
        with path.open('rb') as binary:
            if hashlib.file_digest(binary, 'sha256').hexdigest() != expected[name]:
                raise RuntimeError('Server binary SHA-256 mismatch.')


def local_inventory(host, port):
    return {'all': {'children': {'vpn': {'hosts': {'vpn1': {
        'ansible_connection': 'local', 'ansible_host': host, 'ansible_port': port,
        'ansible_python_interpreter': sys.executable,
        'vpn_public_ip': host, 'vpn_ssh_port': port,
        'vpn_admin_password': "{{ lookup('ansible.builtin.env', 'VPN_ADMIN_PASSWORD') }}"
    }}}}}}


def verify_server(host, certificate):
    spec = importlib.util.spec_from_file_location('actions', ROOT / 'scripts/deploy-actions.py')
    actions = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(actions)
    config = json.loads(Path('/etc/linevpn/server.json').read_text())
    actions.verify(host, str(certificate), config['transport']['sni'])
    return config['transport']['sni']


def prepare_tools():
    TOOLS.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = TOOLS.lstat()
    if TOOLS.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError('Deployment tools directory must be root-owned and not writable by others.')
    TOOLS.chmod(0o700)
    # Validate existing descendants too: securing only the parent cannot repair
    # a writable Python module left by an older/manual installation.
    for directory, folders, files in os.walk(TOOLS, followlinks=False):
        for name in folders + files:
            path = Path(directory) / name
            info = path.lstat()
            if info.st_uid != 0 or (not path.is_symlink() and info.st_mode & 0o022):
                raise RuntimeError('Cached deployment tools must be root-owned and not writable by others.')
            if path.is_symlink():
                target = path.resolve(strict=True)
                if target.is_dir() and TOOLS not in target.parents:
                    raise RuntimeError('Cached tool directory must not link outside its protected root.')
                for item in (target, *target.parents):
                    info = item.stat()
                    if info.st_uid != 0 or info.st_mode & 0o022:
                        raise RuntimeError('Cached tool link has an untrusted target.')


def deploy(host, port, admin):
    existing = Path('/etc/linevpn/server.json')
    if existing.exists() and json.loads(existing.read_text()).get('public_ip') != host:
        raise ValueError('Existing LineVPN uses another IP. Update its configuration/certificate explicitly before redeploying.')
    prepare_tools()
    verify_binaries()
    env = os.environ.copy()
    print('Installing verified prebuilt server binaries...', flush=True)
    venv = TOOLS / f'ansible-py{sys.version_info.major}.{sys.version_info.minor}'
    if not (venv / 'bin/python').is_file():
        run([sys.executable, '-m', 'venv', venv])
    run([venv / 'bin/python', '-m', 'pip', 'install', '--require-hashes', '--only-binary=:all:', '--disable-pip-version-check',
         '-r', ROOT / 'deploy/remote-requirements.txt'])
    ansible = ROOT / 'deploy/ansible'
    env.update(ANSIBLE_CONFIG=str(ansible / 'ansible.cfg'),
               ANSIBLE_COLLECTIONS_PATH=str(TOOLS / 'collections'))
    run([venv / 'bin/ansible-galaxy', 'collection', 'install', '-r', ansible / 'requirements.yml',
         '-p', TOOLS / 'collections'], env=env)
    inventory = ansible / 'inventory.local.json'
    inventory.write_text(json.dumps(local_inventory(host, port)), encoding='utf-8')
    inventory.chmod(0o600)
    env['VPN_ADMIN_PASSWORD'] = admin
    try:
        run([venv / 'bin/ansible-playbook', '-i', inventory, ansible / 'deploy.yml'], env=env)
    finally:
        env.pop('VPN_ADMIN_PASSWORD', None)
    certificate = ansible / 'generated/vpn1-api-cert.pem'
    reality_sni = verify_server(host, certificate)
    profile = ansible / 'generated/vpn1-bootstrap.txt'
    print('LINEVPN_PROFILE_B64=' + base64.b64encode(profile.read_bytes()).decode('ascii'))
    print('LINEVPN_CERT_B64=' + base64.b64encode(certificate.read_bytes()).decode('ascii'))
    print('LINEVPN_REALITY_SNI_B64=' + base64.b64encode(reality_sni.encode('utf-8')).decode('ascii'))
    print('LINEVPN_REMOTE_OK=1', flush=True)


def main():
    try:
        if os.geteuid() != 0:
            raise ValueError('Run the bootstrap as root or with sudo.')
        if sys.argv[1:] != ['--stdin']:
            raise ValueError('Expected --stdin bootstrap input.')
        deploy(*read_input(sys.stdin.buffer))
        return 0
    except Exception as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
