"""Reject a distributable APK that cannot update the currently published app."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from package_version import ROOT, android_code, product_version


def expected_certificate():
    manifest = json.loads((ROOT / "installers/current/manifest.json").read_text())
    value = manifest.get("android_certificate_sha256", "").lower().replace(":", "")
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Published Android certificate fingerprint is missing; verify the previous APK first")
    return value


def check_keystore():
    for name in ("ANDROID_KEYSTORE", "ANDROID_STORE_PASSWORD", "ANDROID_KEY_ALIAS", "ANDROID_KEY_PASSWORD"):
        if not os.environ.get(name):
            raise ValueError(f"{name} is required; never generate a new key for an update")
    if not Path(os.environ["ANDROID_KEYSTORE"]).is_absolute():
        raise ValueError("ANDROID_KEYSTORE must be an absolute path")
    # Password stays in the environment, never in command arguments or logs.
    result = subprocess.run([
        "keytool", "-exportcert", "-keystore", os.environ["ANDROID_KEYSTORE"],
        "-storepass:env", "ANDROID_STORE_PASSWORD", "-alias", os.environ["ANDROID_KEY_ALIAS"],
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError("Cannot read the existing Android signing certificate")
    if hashlib.sha256(result.stdout).hexdigest() != expected_certificate():
        raise ValueError("Android signing certificate differs from the published app; update would be rejected")


def inspect_apk(apk):
    build_tools = Path(os.environ["ANDROID_HOME"]) / "build-tools/35.0.0"
    signed = subprocess.check_output([str(build_tools / "apksigner"), "verify", "--print-certs", str(apk)], text=True)
    certificates = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)", signed)
    if len(certificates) != 1 or not re.fullmatch(r"[0-9a-fA-F]{64}", certificates[0]):
        raise ValueError("Expected one verified APK signing certificate")
    badging = subprocess.check_output([str(build_tools / "aapt"), "dump", "badging", str(apk)], text=True)
    package = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", badging, re.M)
    if not package:
        raise ValueError("APK identity/version cannot be read")
    return (*package.groups(), certificates[0].lower())


def check_apk(apk, previous=None):
    info = inspect_apk(apk)
    expected = ("dev.linevpn.app", str(android_code(product_version())), product_version(), expected_certificate())
    if info != expected:
        raise ValueError("APK signer or identity/version does not match this release")
    if previous:
        old = inspect_apk(previous)
        if old[0] != info[0] or old[3] != info[3] or int(old[1]) > int(info[1]):
            raise ValueError("APK cannot update the previous package/signature/version")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", nargs="?", type=Path)
    parser.add_argument("--previous", type=Path, help="Compare with a previous installed APK")
    args = parser.parse_args()
    try:
        if args.previous and not args.apk:
            raise ValueError("--previous requires a new APK")
        check_apk(args.apk, args.previous) if args.apk else check_keystore()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
    print("PASS: Android update signing" + (", package ID and version" if args.apk else " key"))
