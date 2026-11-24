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
import urllib.error


def settings(env):
    missing = [key for key in ('VPS_HOST', 'VPS_USERNAME', 'VPS_PASSWORD') if not env.get(key)]
    if missing:
        raise ValueError('Add repository Actions secrets: ' + ', '.join(missing))
    try:
        host = ipaddress.ip_address(env['VPS_HOST'])
    except ValueError:
        raise ValueError('VPS_HOST must contain only the public server IP, without ssh/user/port') from None
    if not host.is_global or host.is_multicast or host.is_reserved or getattr(host, 'scope_id', None):
        raise ValueError('VPS_HOST must be a public IP address')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}\$?', env['VPS_USERNAME']):
        raise ValueError('VPS_USERNAME must contain only the Linux SSH username')
    port = env.get('VPS_PORT') or '22'
    if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('VPS_PORT must be an integer between 1 and 65535')
    admin = env.get('VPN_ADMIN_PASSWORD', '')
    if admin and (not 16 <= len(admin.encode('utf-8')) <= 72 or admin != admin.strip() or '\n' in admin or '\r' in admin or '\0' in admin):
        raise ValueError('VPN_ADMIN_PASSWORD must contain 16-72 UTF-8 bytes without surrounding whitespace')
    return str(host), int(port)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('Deployment endpoint redirected')


def verify(host, certificate, reality_sni='www.microsoft.com'):
    address = '[' + host + ']' if ':' in host else host
    context = ssl.create_default_context(cafile=certificate)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
    with opener.open('https://' + address + ':8443/healthz', timeout=20) as response:
        if response.status != 200 or json.loads(response.read(4096)).get('status') != 'ok':
            raise RuntimeError('API health check failed')
    with opener.open('https://' + address + ':8443/', timeout=20) as response:
        if (response.status != 200 or
                not response.headers.get('Content-Type', '').startswith('text/html') or
                b'id="login-form"' not in response.read(65536)):
            raise RuntimeError('Public admin login page is unavailable')
    # The page is public; account data, profiles and mutations require a session.
    protected = [('GET', '/api/admin/accounts'), ('GET', '/api/admin/bootstrap'),
                 ('POST', '/api/admin/bootstrap/rotate'), ('POST', '/api/admin/account'),
                 ('POST', '/api/admin/access-key'), ('POST', '/api/admin/revoke'),
                 ('POST', '/api/admin/logout')]
    for method, path in protected:
        request = urllib.request.Request('https://' + address + ':8443' + path,
            data=b'{}' if method == 'POST' else None,
            headers={'Content-Type': 'application/json'}, method=method)
        try:
            with opener.open(request, timeout=20):
                raise RuntimeError('Admin endpoint accepted an unauthenticated request')
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise RuntimeError('Admin endpoint did not require authentication') from None
    # REALITY forwards an unauthenticated TLS handshake to its configured target.
    # This checks TLS/target identity, not an authenticated VLESS round trip.
    reality_context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=20) as connection:
        with reality_context.wrap_socket(connection, server_hostname=reality_sni):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--certificate', help='Verify the API with the certificate fetched over SSH')
    parser.add_argument('--host', help='Verify a public IP without SSH credentials')
    parser.add_argument('--reality-sni', default='www.microsoft.com')
    args = parser.parse_args()
    try:
        if args.host:
            ip = ipaddress.ip_address(args.host)
            if not ip.is_global or ip.is_multicast or ip.is_reserved:
                raise ValueError('Host must be a public IP')
            host = str(ip)
        else:
            host, _ = settings(os.environ)
    except ValueError as error:
        print('::error::' + str(error), file=sys.stderr)
        return 1
    if args.certificate:
        try:
            verify(host, args.certificate, args.reality_sni)
        except Exception as error:
            print('::error::External deployment check failed (' + type(error).__name__ +
                  '). Check TCP 443/8443, the service and its certificate.', file=sys.stderr)
            return 1
        print('Verified HTTPS API and public admin login with the SSH-fetched certificate, admin authentication and REALITY TLS handshake on 443.')
    else:
        print('Required deployment secrets are configured and valid.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
