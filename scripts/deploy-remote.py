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
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
TOOLS = Path('/opt/linevpn-tools')
GO_VERSION = '1.27.4'


def read_input(path):
    lines = path.read_bytes().decode('utf-8').split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    path.unlink()
    if len(lines) != 4:
        raise ValueError('Expected host, port, SSH password and VPN admin password.')
    host = ipaddress.ip_address(lines[0])
    if not host.is_global:
        raise ValueError('host must be a public IP address.')
    if not lines[1].isascii() or not lines[1].isdigit() or not 1 <= int(lines[1]) <= 65535:
        raise ValueError('Invalid SSH port.')
    admin = lines[3]
    if not 16 <= len(admin.encode('utf-8')) <= 72 or admin != admin.strip():
        raise ValueError('VPN admin password must be 16-72 UTF-8 bytes without surrounding whitespace.')
    return str(host), int(lines[1]), admin


def run(command, *, env=None):
    result = subprocess.run([str(item) for item in command], cwd=ROOT, env=env)
    if result.returncode:
        raise RuntimeError(f'{Path(command[0]).name} failed (exit {result.returncode}).')


def go_archive_metadata(releases):
    filename = f'go{GO_VERSION}.linux-amd64.tar.gz'
    for release in releases:
        if release.get('version') == f'go{GO_VERSION}':
            for item in release.get('files', []):
                if item.get('filename') == filename and item.get('os') == 'linux' and item.get('arch') == 'amd64':
                    checksum = item.get('sha256', '')
                    if len(checksum) == 64 and all(c in '0123456789abcdef' for c in checksum):
                        return filename, checksum
    raise RuntimeError(f'Go {GO_VERSION} checksum was not found in the official download index.')


def install_go():
    target = TOOLS / f'go{GO_VERSION}'
    executable = target / 'bin/go'
    if executable.is_file():
        return executable
    with urllib.request.urlopen('https://go.dev/dl/?mode=json&include=all', timeout=60) as response:
        filename, checksum = go_archive_metadata(json.load(response))
    with tempfile.TemporaryDirectory(prefix='go-', dir=TOOLS) as tmp:
        archive = Path(tmp) / filename
        digest = hashlib.sha256()
        with urllib.request.urlopen('https://go.dev/dl/' + filename, timeout=120) as response, archive.open('wb') as output:
            while chunk := response.read(1024 * 1024):
                digest.update(chunk)
                output.write(chunk)
        if digest.hexdigest() != checksum:
            raise RuntimeError('Go archive SHA-256 mismatch; installation stopped.')
        with tarfile.open(archive, 'r:gz') as bundle:
            for member in bundle.getmembers():
                path = Path(member.name)
                if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'go' or not (member.isfile() or member.isdir()):
                    raise RuntimeError('Unexpected entry in the Go archive.')
            options = {'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}
            bundle.extractall(tmp, **options)
        (Path(tmp) / 'go').rename(target)
    return executable


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
    actions.verify(host, str(certificate))


def deploy(host, port, admin):
    existing = Path('/etc/linevpn/server.json')
    if existing.exists() and json.loads(existing.read_text()).get('public_ip') != host:
        raise ValueError('Existing LineVPN uses another IP. Update its configuration/certificate explicitly before redeploying.')
    TOOLS.mkdir(parents=True, exist_ok=True, mode=0o700)
    go = install_go()
    env = os.environ.copy()
    env.update(PATH=str(go.parent) + os.pathsep + env.get('PATH', ''), GOTOOLCHAIN='local',
               GOMAXPROCS='2', GOFLAGS='-p=1', CGO_ENABLED='0')
    print('Testing and compiling server on VPS...', flush=True)
    run([go, 'test', './internal/policy', './internal/secure', './internal/server', './internal/transport'], env=env)
    run(['bash', ROOT / 'scripts/build-server.sh'], env=env)
    venv = TOOLS / f'ansible-py{sys.version_info.major}.{sys.version_info.minor}'
    if not (venv / 'bin/python').is_file():
        run([sys.executable, '-m', 'venv', venv])
    run([venv / 'bin/python', '-m', 'pip', 'install', '--disable-pip-version-check',
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
    verify_server(host, certificate)
    profile = ansible / 'generated/vpn1-bootstrap.txt'
    print('LINEVPN_PROFILE_B64=' + base64.b64encode(profile.read_bytes()).decode('ascii'))
    print('LINEVPN_CERT_B64=' + base64.b64encode(certificate.read_bytes()).decode('ascii'))
    print('LINEVPN_REMOTE_OK=1', flush=True)


def main():
    try:
        if os.geteuid() != 0:
            raise ValueError('Run the bootstrap as root or with sudo.')
        if len(sys.argv) != 2:
            raise ValueError('Missing protected input file.')
        deploy(*read_input(Path(sys.argv[1])))
        return 0
    except Exception as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
