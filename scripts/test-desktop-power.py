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

assert os.environ.get("GITHUB_ACTIONS") == "true", "Use an isolated CI machine"
mac = platform.system() == "Darwin"
assert mac or platform.system() == "Windows"
data = pathlib.Path("/var/lib/linevpn") if mac else pathlib.Path(os.environ["PROGRAMDATA"]) / "LineVPN"
token = (data / "ui-token").read_text().strip()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(body=None):
    if body is not None:
        from desktop_control_fixture import request as privileged_request
        return privileged_request(data, token, 'vpn', body)
    from desktop_control_fixture import state as public_state
    return public_state(data,token)


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
            subprocess.run(["sudo", "launchctl", "bootout", "system/dev.linevpn.agent"], check=True)
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
