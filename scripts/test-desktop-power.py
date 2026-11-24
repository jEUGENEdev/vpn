#!/usr/bin/env python3
"""Real native off/on and restart regression; disposable CI hosts only."""
import ipaddress
import json
import os
import pathlib
import platform
import socket
import subprocess
import time
import urllib.request

from desktop_control_fixture import public_opener, request as approve, state as public_state

assert os.environ.get("GITHUB_ACTIONS") == "true", "Use an isolated CI machine"
mac = platform.system() == "Darwin"
assert mac or platform.system() == "Windows"
data = pathlib.Path("/var/lib/linevpn") if mac else pathlib.Path(os.environ["PROGRAMDATA"]) / "LineVPN"
token = (data / "ui-token").read_text().strip()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# Authorize once. The same scoped grant must survive every worker restart.
settings_grant = approve(data, token, 'settings-session', {})['token']


def api(body=None):
    if body is None:
        return public_state(data, token)
    req = urllib.request.Request(
        'https://127.0.0.1:17891/local/control/settings/vpn',
        data=json.dumps(body).encode(),
        headers={'Authorization': 'Bearer ' + settings_grant, 'Content-Type': 'application/json'})
    with public_opener(data).open(req, timeout=30) as response:
        return json.load(response)


def ready(enabled):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            state = api()
        except (OSError, ValueError):
            time.sleep(.25)
            continue
        assert not state.get("power_error"), state.get("power_error")
        if not state.get("power_transition") and state["vpn_enabled"] == enabled:
            assert state["tunnel"] == enabled and state["guard"] == enabled, state
            return
        time.sleep(.25)
    raise AssertionError("Native power transition did not finish")


def direct_works():
    addresses = socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
    assert addresses
    fake = (ipaddress.ip_network("198.18.0.0/15"), ipaddress.ip_network("fd04:6c69:6e65::/96"))
    assert all(not any(ipaddress.ip_address(a[4][0]) in prefix for prefix in fake) for a in addresses), addresses
    with opener.open("http://1.1.1.1/cdn-cgi/trace", timeout=8) as response:
        assert response.status == 200


def tunnel_dns_works():
    # Use the OS resolver and an uncached name, not an explicit @TUN DNS query.
    addresses = socket.getaddrinfo("linevpn-probe-%d.example.com" % time.time_ns(), 443,
                                  family=socket.AF_INET, type=socket.SOCK_STREAM)
    assert addresses and all(ipaddress.ip_address(a[4][0]) in ipaddress.ip_network("198.18.0.0/15") for a in addresses), addresses


for cycle in range(2):
    api({"enabled": False, "confirm": True})
    ready(False)
    direct_works()
    if cycle == 0:
        # Stopping an explicitly disabled service must leave ordinary internet.
        if mac:
            # bootout returns before launchd has finished reaping the job.
            # Use the shipped bounded stop/wait sequence before bootstrap.
            subprocess.run(["sudo", "bash", "packaging/macos/stop-service.sh"], check=True)
        else:
            subprocess.run(["powershell", "-NoProfile", "-Command", "Stop-Service LineVPN"], check=True)
        direct_works()
        if mac:
            subprocess.run(["sudo", "launchctl", "bootstrap", "system", "/Library/LaunchDaemons/dev.linevpn.agent.plist"], check=True)
        else:
            subprocess.run(["powershell", "-NoProfile", "-Command", "Start-Service LineVPN"], check=True)
        ready(False)
        direct_works()
    api({"enabled": True})
    ready(True)
    tunnel_dns_works()
    # The calling platform test pinned this IP without a configured server.
    try:
        opener.open("http://1.1.1.1/cdn-cgi/trace", timeout=4)
    except OSError:
        pass
    else:
        raise AssertionError("Protected address bypassed offline VPN")
print("PASS: full off/on, restored DNS, off survives restart, offline enable blocks protected access")
