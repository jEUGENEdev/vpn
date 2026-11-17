"""Exercise the real scanner with deterministic dummy keys, without logging them."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SecretScanningTest(unittest.TestCase):
    def scan(self, source, expected_rule=None, secret=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_dir = root / 'source'
            source_dir.mkdir()
            (source_dir / 'example.txt').write_text(source)
            report = root / 'report.json'
            result = subprocess.run([
                'gitleaks', 'dir', str(source_dir), '--redact', '--no-banner',
                '--config', str(ROOT / '.gitleaks.toml'), '--report-format', 'json',
                '--report-path', str(report),
            ], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 1 if expected_rule else 0, result.stderr)
            findings = json.loads(report.read_text())
            if expected_rule:
                self.assertIn(expected_rule, {item['RuleID'] for item in findings})
            else:
                self.assertEqual(findings, [])
            if secret:
                self.assertNotIn(secret, result.stdout + result.stderr + report.read_text())

    def test_access_key_is_detected_and_redacted(self):
        # Synthetic public fixture, never associated with an account.
        token = 'lnv_' + base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
        self.scan('example: "' + token + '"\n', 'linevpn-access-key', token)

    def test_profile_access_key_is_detected_and_redacted(self):
        token = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
        self.scan('linevpn://192.0.2.1:8443?pin=public&access=' + token + '\n',
                  'linevpn-profile-access', token)

    def test_public_pin_and_documentation_placeholders_are_not_secrets(self):
        self.scan('linevpn://192.0.2.1:8443?pin=public\nlnv_<access-key>\n')


if __name__ == '__main__':
    unittest.main()
