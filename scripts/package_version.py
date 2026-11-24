"""One product version for Electron, MSI, PKG and APK packages."""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def version_parts(value):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise ValueError("Installer version must be major.minor.patch")
    parts = tuple(map(int, value.split(".")))
    if parts[0] > 255 or parts[1] > 255 or parts[2] > 999:
        raise ValueError("Installer version exceeds MSI/Android version limits")
    return parts


def product_version():
    value = json.loads((ROOT / "apps/desktop/package.json").read_text(encoding="utf-8"))["version"]
    version_parts(value)
    return value


def android_code(value):
    major, minor, patch = version_parts(value)
    return major * 1_000_000 + minor * 1_000 + patch


def check_consistent():
    current = product_version()
    lock = json.loads((ROOT / "apps/desktop/package-lock.json").read_text(encoding="utf-8"))
    if lock["version"] != current or lock["packages"][""]["version"] != current:
        raise ValueError("Desktop lockfile version does not match package.json")


def check_newer():
    check_consistent()
    current = product_version()
    previous = json.loads((ROOT / "installers/current/manifest.json").read_text(encoding="utf-8"))["version"].split("-", 1)[0]
    if version_parts(current) <= version_parts(previous):
        raise ValueError("Bump apps/desktop/package.json and package-lock.json before publishing another release")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--android-code", action="store_true")
    parser.add_argument("--check-newer", action="store_true")
    parser.add_argument("--check-consistent", action="store_true")
    args = parser.parse_args()
    if args.check_newer:
        check_newer()
    if args.check_consistent:
        check_consistent()
    print(android_code(product_version()) if args.android_code else product_version())
