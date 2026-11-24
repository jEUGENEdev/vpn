"""Exercise the actual release preflight; never builds or publishes an installer."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parent.parent


def workflow(name):
    return yaml.load((ROOT / '.github/workflows' / name).read_text(), Loader=yaml.BaseLoader)


class WorkflowTests(unittest.TestCase):
    def test_server_deployment_and_installer_release_have_separate_triggers(self):
        build = workflow('build.yml')
        self.assertEqual(set(build['on']), {'workflow_dispatch'})
        publish = build['on']['workflow_dispatch']['inputs']['publish']
        self.assertEqual(publish['default'], 'false')
        self.assertEqual(publish['type'], 'boolean')
        checks = workflow('checks.yml')
        self.assertIn('pull_request', checks['on'])
        self.assertIn('push', checks['on'])
        self.assertEqual(set(checks['jobs']), {'security', 'test'})
        deploy = workflow('deploy.yml')
        for event in ('push', 'pull_request'):
            paths = deploy['on'][event]['paths']
            self.assertIn('deploy.sh', paths)
            self.assertIn('cmd/linevpn-server/**', paths)
            self.assertIn('internal/ui/admin/**', paths)
            self.assertNotIn('internal/ui/**', paths)
            self.assertNotIn('apps/**', paths)
        self.assertIn('validate-macos', deploy['jobs']['deploy']['needs'])
        self.assertNotIn('android', deploy['jobs']['deploy']['needs'])

    def test_actual_release_preflight_accepts_rebuilds_and_guards_publication(self):
        step = next(s for s in workflow('build.yml')['jobs']['prepare']['steps'] if s.get('id') == 'release')
        cases = [
            # Rebuild an already published version without publication or signing secrets.
            ('false', 'refs/heads/main', '0.4.0', '0.4.0-preview', True),
            ('false', 'refs/heads/feature', '0.4.0', '0.4.0-preview', True),
            ('true', 'refs/heads/main', '0.4.0', '0.4.0-preview', False),
            ('true', 'refs/heads/main', '0.3.0', '0.4.0-preview', False),
            ('true', 'refs/heads/feature', '0.4.1', '0.4.0-preview', False),
            ('true', 'refs/heads/main', '0.4.1', '0.4.0-preview', True),
        ]
        for publish, ref, current, previous, success in cases:
            with self.subTest(publish=publish, ref=ref, current=current), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'scripts').mkdir()
                (root / 'apps/desktop').mkdir(parents=True)
                (root / 'installers/current').mkdir(parents=True)
                shutil.copy2(ROOT / 'scripts/package_version.py', root / 'scripts/package_version.py')
                (root / 'apps/desktop/package.json').write_text(json.dumps({'version': current}))
                (root / 'apps/desktop/package-lock.json').write_text(json.dumps({'version': current, 'packages': {'': {'version': current}}}))
                (root / 'installers/current/manifest.json').write_text(json.dumps({'version': previous}))
                output = root / 'output'
                env = dict(os.environ, PUBLISH_REQUESTED=publish, GITHUB_REF=ref, GITHUB_OUTPUT=str(output))
                result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', step['run']], cwd=root,
                                        env=env, text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                if success:
                    self.assertEqual(output.read_text(), f'publish={publish}\n')
                else:
                    self.assertFalse(output.exists())

    def test_release_dependencies_and_credentials_stay_main_only(self):
        jobs = workflow('build.yml')['jobs']
        for job in ('android', 'windows', 'macos', 'test'):
            self.assertIn('security', jobs[job]['needs'])
            self.assertIn('prepare', jobs[job]['needs'])
        for name in ('ANDROID_STORE_PASSWORD', 'ANDROID_KEY_ALIAS', 'ANDROID_KEY_PASSWORD'):
            self.assertIn("github.ref == 'refs/heads/main'", jobs['android']['env'][name])
            self.assertIn("needs.prepare.outputs.publish == 'true'", jobs['android']['env'][name])
        publish = jobs['publish-current']
        for dependency in ('prepare', 'test', 'android', 'windows', 'macos'):
            self.assertIn(dependency, publish['needs'])
        self.assertIn("github.ref == 'refs/heads/main'", publish['if'])
        self.assertIn('inputs.publish', publish['if'])
        self.assertEqual(workflow('build.yml')['permissions']['contents'], 'read')
        self.assertEqual(publish['permissions']['contents'], 'write')


if __name__ == '__main__':
    unittest.main()
