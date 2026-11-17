#!/usr/bin/env python3
"""Reject APKs that cannot update the published LineVPN signing identity."""
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def sdk_tool(name):
    sdk = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if sdk:
        candidate = pathlib.Path(sdk) / 'build-tools/35.0.0' / name
        if candidate.is_file():
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    raise ValueError(f'{name} is required to verify the APK; set ANDROID_HOME')


def inspect_apk(apk):
    # Both commands must succeed: parsing metadata is not signature verification.
    signature = subprocess.check_output([sdk_tool('apksigner'), 'verify', '--print-certs', str(apk)], text=True)
    certs = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$', signature, re.MULTILINE)
    badging = subprocess.check_output([sdk_tool('aapt'), 'dump', 'badging', str(apk)], text=True)
    match = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", badging, re.MULTILINE)
    if len(certs) != 1 or not match:
        raise ValueError('Expected one verified APK signer and readable package metadata')
    return dict(application_id=match[1], version_code=int(match[2]), version_name=match[3], certificate_sha256=certs[0].lower())


def validate(info, metadata, previous=None):
    expected = dict(application_id='dev.linevpn.app', version_code=metadata['linevpn']['androidVersionCode'],
                    version_name=metadata['version'] + '-preview',
                    certificate_sha256=metadata['linevpn']['androidCertificateSha256'].lower())
    if not re.fullmatch('[0-9a-f]{64}', expected['certificate_sha256']):
        raise ValueError('Invalid pinned Android certificate')
    if not isinstance(expected['version_code'], int) or not 2 < expected['version_code'] <= 2100000000:
        raise ValueError('Android versionCode must exceed the published preview code 2')
    for field, value in expected.items():
        if info[field] != value:
            raise ValueError(f'APK {field} does not match release metadata. Do not uninstall the existing app; rebuild with the original signing key and correct version.')
    if previous:
        if any(info[k] != previous[k] for k in ('application_id', 'certificate_sha256')):
            raise ValueError('APK cannot update the previous package/signing identity')
        if info['version_code'] < previous['version_code']:
            raise ValueError('APK would downgrade the previous installation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=pathlib.Path)
    parser.add_argument('--previous', type=pathlib.Path, help='Also compare with an existing APK')
    args = parser.parse_args()
    try:
        metadata = json.loads((ROOT / 'apps/desktop/package.json').read_text())
        info = inspect_apk(args.apk)
        validate(info, metadata, inspect_apk(args.previous) if args.previous else None)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + '\n')
    print('PASS: Android package, version and signature match the update identity')


if __name__ == '__main__':
    main()
