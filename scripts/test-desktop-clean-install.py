#!/usr/bin/env python3
"""Exercise explicit uninstall/fresh install on disposable native CI hosts."""
import hashlib
import json
import os
import pathlib
import platform
import socket
import subprocess
import sys
import tempfile
import time

from desktop_control_fixture import state as public_state

assert os.environ.get('GITHUB_ACTIONS') == 'true', 'Use a disposable CI host'
mac = platform.system() == 'Darwin'
assert mac or platform.system() == 'Windows'
root = pathlib.Path(__file__).resolve().parents[1]
os.chdir(root)
installer = pathlib.Path(sys.argv[1]).resolve()
data = pathlib.Path('/var/lib/linevpn') if mac else pathlib.Path(os.environ['PROGRAMDATA']) / 'LineVPN'
app = pathlib.Path('/Applications/Сеть.app') if mac else pathlib.Path(os.environ['ProgramFiles']) / 'LineVPN'
agent = pathlib.Path('/Library/Application Support/LineVPN/linevpn-agent') if mac else app / 'resources/agent/linevpn-agent.exe'
manager = root / 'build/macos-tested-setup.app/Contents/Resources/manage.sh'
log = root / ('build/macos-clean-install.log' if mac else 'build/windows-clean-install.log')


def operation(action, expect_success=True, repair=False, package=None):
    if mac:
        command = ['bash', str(manager), action]
    else:
        command = ['msiexec.exe', '/fa' if repair else ('/i' if action == 'install' else '/x'), str(package or installer), '/qn', '/norestart', '/l*v', str(log)]
    with log.open('ab') if mac else open(os.devnull, 'wb') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=240)
    if expect_success:
        assert result.returncode == 0, f'{action} failed/requires reboot: {result.returncode}; see {log}'
    else:
        assert result.returncode != 0, f'{action} unexpectedly succeeded'


def ready():
    deadline = time.monotonic() + 65
    while time.monotonic() < deadline:
        try:
            state = public_state(data, (data / 'ui-token').read_text().strip())
            if state['vpn_enabled'] and state['tunnel'] and state['guard'] and not state.get('power_error'):
                return state
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(.25)
    raise AssertionError('Fresh installation did not start a working tunnel and guard')


def removed():
    assert not data.exists(), 'Private credentials/state survived uninstall'
    assert not app.exists(), 'Installed application survived uninstall'
    assert not agent.exists(), 'Service payload survived uninstall'
    if mac:
        assert not pathlib.Path('/Library/LaunchDaemons/dev.linevpn.agent.plist').exists()
        assert subprocess.run(['launchctl', 'print', 'system/dev.linevpn.agent'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
    else:
        assert subprocess.run(['sc.exe', 'query', 'LineVPN'], stdout=subprocess.DEVNULL).returncode != 0
    subprocess.run(['curl', '--noproxy', '*', '--fail', '--silent', '--output', os.devnull, '--connect-timeout', '4', '--max-time', '10', 'http://1.1.1.1/cdn-cgi/trace'], check=True)
    socket.getaddrinfo('example.com', 443, type=socket.SOCK_STREAM)


ready()
old_token = (data / 'ui-token').read_bytes()
(data / 'clean-install-sentinel').write_text('must disappear')
# Neither repeat /i nor explicit /fa may change an existing installation.
operation('install', expect_success=False)
if not mac:
    operation('install', expect_success=False, repair=True)
    # Related products must also require removal, not an implicit major upgrade.
    with tempfile.TemporaryDirectory(prefix='linevpn-clean-fixture-') as temporary:
        work = pathlib.Path(temporary)
        from package_version import product_version, version_parts
        major, minor, patch = version_parts(product_version())
        version = f'{major}.{minor}.{patch + 1}'
        subprocess.run([sys.executable, 'packaging/windows/package.py', 'apps/desktop/dist/win-unpacked', str(work / 'next.wxs'), '--version', version], check=True)
        subprocess.run(['wix', 'build', str(work / 'next.wxs'), '-arch', 'x64', '-o', str(work / 'next.msi')], check=True)
        operation('install', expect_success=False, package=work / 'next.msi')
assert (data / 'ui-token').read_bytes() == old_token
ready()
gui = None
if not mac:
    # Users uninstall with a live tray UI. Verify removal closes it and helpers.
    gui_env = dict(os.environ)
    gui_env.pop('LINEVPN_SMOKE_TEST_REPORT', None)
    gui = subprocess.Popen([str(app / 'Сеть.exe'), '--background'], env=gui_env)
    time.sleep(1)
    assert gui.poll() is None, 'Installed UI exited before uninstall'
operation('uninstall')
if gui is not None:
    gui.wait(timeout=15)
removed()
operation('install')
state = ready()
assert (data / 'ui-token').read_bytes() != old_token, 'Old UI session reused'
assert not (data / 'clean-install-sentinel').exists()
assert not state.get('account_id') and not state.get('server'), 'Old profile restored'
assert not state.get('pending_protection'), 'Old local rules restored'
if not mac:
    for name in ('Сеть.exe', 'resources/app.asar', 'resources/agent/linevpn-agent.exe'):
        assert hashlib.sha256((app / name).read_bytes()).digest() == hashlib.sha256((root / 'apps/desktop/dist/win-unpacked' / name).read_bytes()).digest(), f'Stale installed payload: {name}'
    shortcut_json = subprocess.check_output(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$products = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' | Get-ItemProperty | Where-Object { $_.DisplayName -in @('Сеть', 'LineVPN') })
if ($products.Count -ne 1 -or $products[0].NoRepair -ne 1) { throw 'Duplicate product or repair still enabled' }
$link = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Сеть.lnk'
if (-not (Test-Path -LiteralPath $link -PathType Leaf)) { throw "Missing Start menu shortcut: $link" }
Copy-Item -LiteralPath $link -Destination build/windows-shortcut.lnk -Force
$shell = New-Object -ComObject WScript.Shell
$target = $shell.CreateShortcut($link).TargetPath
$env:LINEVPN_SMOKE_TEST_REPORT = Join-Path (Get-Location) 'build/windows-clean-gui.txt'
Remove-Item -LiteralPath $env:LINEVPN_SMOKE_TEST_REPORT -ErrorAction SilentlyContinue
$gui = Start-Process $link -ArgumentList '--background' -PassThru
$image = $gui.MainModule.FileName
if (-not $gui.WaitForExit(45000)) { $gui.Kill(); throw 'Start menu launch did not load the installed client UI' }
if ($gui.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $env:LINEVPN_SMOKE_TEST_REPORT)) { throw 'Start menu launch failed' }
if (-not (Get-Content -Raw $env:LINEVPN_SMOKE_TEST_REPORT).StartsWith('PASS:')) { throw 'Start menu launch did not authenticate with the fresh service' }
Remove-Item Env:LINEVPN_SMOKE_TEST_REPORT
@{target=$target; image=$image} | ConvertTo-Json -Compress
'''], encoding='utf-8')
    shortcut = json.loads(shortcut_json)
    # Verify the executable actually launched through the installed shortcut,
    # including its UI and authenticated fresh service session, not just metadata.
    launched_image = shortcut['image']
    assert launched_image and pathlib.Path(launched_image).samefile(app / 'Сеть.exe'), f'Wrong shortcut executable: {shortcut!r}'
# A damaged installed binary must not prevent removing the package.
if not mac:
    subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', r'''
$ErrorActionPreference = 'Stop'
$vpnWorker = Get-Process -Id (Get-CimInstance Win32_Service -Filter "Name='LineVPN'").ProcessId
Stop-Service LineVPN
(Get-Service LineVPN).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
if (-not $vpnWorker.WaitForExit(30000)) { throw 'Service process did not exit before the damaged-payload fixture' }
'''], check=True)
else:
    subprocess.run(['bash', str(manager.parent / 'stop-service.sh')], check=True)
agent.unlink()
operation('uninstall')
removed()
# Force a real startup failure. Successful registration is not readiness.
with socket.socket() as blocker:
    blocker.bind(('127.0.0.1', 17891))
    blocker.listen()
    operation('install', expect_success=False)
    if mac:
        operation('uninstall')  # Apple Installer can leave a partial payload.
    removed()  # Windows rollback must have removed its newly created state.
operation('install')
ready()
print('PASS: repair rejected; uninstall clears state/network; fresh session and payload; missing agent can be removed')
