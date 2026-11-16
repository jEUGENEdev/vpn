#!/usr/bin/env python3
"""Validate Actions configuration and verify the deployed server without logging secrets."""
import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import urllib.request


def settings(env):
    missing = [key for key in ('VPS_HOST', 'VPS_USERNAME', 'VPS_PASSWORD') if not env.get(key)]
    if missing:
        raise ValueError('Add repository Actions secrets: ' + ', '.join(missing))
    try:
        host = ipaddress.ip_address(env['VPS_HOST'])
    except ValueError:
        raise ValueError('VPS_HOST must contain only the public server IP, without ssh/user/port') from None
    if not host.is_global:
        raise ValueError('VPS_HOST must be a public IP address')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}\$?', env['VPS_USERNAME']):
        raise ValueError('VPS_USERNAME must contain only the Linux SSH username')
    port = env.get('VPS_PORT') or '22'
    if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('VPS_PORT must be an integer between 1 and 65535')
    admin = env.get('VPN_ADMIN_PASSWORD', '')
    if admin and (not 16 <= len(admin.encode('utf-8')) <= 72 or admin != admin.strip()):
        raise ValueError('VPN_ADMIN_PASSWORD must contain 16-72 UTF-8 bytes without surrounding whitespace')
    return str(host), int(port)


def verify(host, certificate):
    address = '[' + host + ']' if ':' in host else host
    context = ssl.create_default_context(cafile=certificate)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    with opener.open('https://' + address + ':8443/healthz', timeout=20) as response:
        if response.status != 200 or json.load(response).get('status') != 'ok':
            raise RuntimeError('API health check failed')
    with socket.create_connection((host, 443), timeout=20):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--certificate', help='Verify the API with the certificate fetched over SSH')
    args = parser.parse_args()
    try:
        host, _ = settings(os.environ)
    except ValueError as error:
        print('::error::' + str(error), file=sys.stderr)
        return 1
    if args.certificate:
        try:
            verify(host, args.certificate)
        except Exception as error:
            print('::error::External deployment check failed (' + type(error).__name__ +
                  '). Check TCP 443/8443, the service and its certificate.', file=sys.stderr)
            return 1
        print('Verified HTTPS API with the SSH-fetched certificate and TCP 443 listener.')
    else:
        print('Required deployment secrets are configured and valid.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
