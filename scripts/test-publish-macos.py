"""Promotion checks use dummy bytes and never publish or run an installer."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('publish_macos', ROOT / 'scripts/publish-macos.py')
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'artifact'
        self.dest = self.root / 'current'
        self.source.mkdir()
        self.dest.mkdir()
        self.name = 'Сеть-0.4.0-macos-universal.dmg'
        self.data = b'fixture disk image' + b'koly' + bytes(508)
        (self.source / self.name).write_bytes(self.data)
        (self.dest / self.name).write_bytes(b'previous DMG')
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.manifest = {
            'version': '0.4.0-preview', 'source_commit': 'a' * 40,
            'built_at': '2026-11-24T17:10:00+00:00',
            'android_certificate_sha256': 'persistent certificate',
            'files': [
                {'name': 'app.apk', 'size': 3, 'sha256': '1' * 64},
                {'name': self.name, 'size': 12, 'sha256': '2' * 64},
                {'name': 'app.msi', 'size': 3, 'sha256': '3' * 64},
            ],
        }
        for name in ('app.apk', 'app.msi'):
            (self.dest / name).write_bytes(b'old')
        (self.dest / 'manifest.json').write_text(json.dumps(self.manifest))
        (self.dest / 'SHA256SUMS').write_text('original checksums\n')
        (self.dest / 'README.md').write_text('# Downloads\n\n## Порядок установки\nKeep instructions.\n')
        self.run = {
            'id': 123, 'event': 'workflow_dispatch', 'head_branch': 'main',
            'path': '.github/workflows/build.yml', 'head_sha': 'b' * 40,
            'status': 'completed', 'conclusion': 'success',
            'head_repository': {'full_name': 'owner/vpn'},
            'repository': {'full_name': 'owner/vpn'},
            'updated_at': '2026-11-24T21:32:00Z',
        }
        self.jobs = {'jobs': [
            {'name': name, 'run_id': 123, 'status': 'completed', 'conclusion': 'success',
             'steps': [{'name': publisher.NATIVE_STEP, 'conclusion': 'success'}]}
            for name in publisher.REQUIRED_JOBS
        ]}

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.dest.iterdir()}

    def promote(self):
        return publisher.promote(self.source, self.dest, self.run, self.jobs,
                                 'owner/vpn', self.digest, minimum_size=1)

    @patch.object(publisher, 'verify_history')
    def test_replaces_only_macos_and_records_exact_provenance(self, history):
        self.promote()
        manifest = json.loads((self.dest / 'manifest.json').read_text())
        self.assertEqual((self.dest / self.name).read_bytes(), self.data)
        for index in (0, 2):
            self.assertEqual(manifest['files'][index], self.manifest['files'][index])
            self.assertEqual((self.dest / manifest['files'][index]['name']).read_bytes(), b'old')
        self.assertEqual(manifest['source_commit'], 'a' * 40)
        self.assertEqual(manifest['android_certificate_sha256'], 'persistent certificate')
        macos = manifest['files'][1]
        self.assertEqual(macos['source_commit'], 'b' * 40)
        self.assertEqual(macos['sha256'], self.digest)
        self.assertEqual(macos['size'], len(self.data))
        self.assertEqual(macos['build_run_id'], 123)
        self.assertIn(self.digest, (self.dest / 'SHA256SUMS').read_text())
        readme = (self.dest / 'README.md').read_text()
        self.assertIn('https://github.com/owner/vpn/actions/runs/123', readme)
        self.assertIn('Keep instructions.', readme)
        self.promote()
        self.assertEqual((self.dest / 'README.md').read_text().count('<!-- macos-build:start -->'), 1)

    @patch.object(publisher, 'verify_history')
    def test_rejects_wrong_run_native_evidence_hash_and_file_before_changes(self, history):
        mutations = [
            lambda: self.run.update(conclusion='failure'),
            lambda: self.run.update(event='pull_request'),
            lambda: self.run.update(head_branch='feature'),
            lambda: self.run.update(path='.github/workflows/checks.yml'),
            lambda: self.run['head_repository'].update(full_name='fork/vpn'),
            lambda: self.run.update(head_sha='not-a-commit'),
            lambda: self.jobs['jobs'].pop(),
            lambda: self.jobs['jobs'][-1].update(conclusion='skipped'),
            lambda: self.jobs['jobs'][-1]['steps'][0].update(conclusion='skipped'),
            lambda: setattr(self, 'digest', '0' * 64),
            lambda: (self.source / 'unexpected.apk').write_bytes(b'bad'),
            lambda: (self.source / self.name).write_bytes(b'not a disk image'),
        ]
        original_run, original_jobs = copy.deepcopy(self.run), copy.deepcopy(self.jobs)
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                before = self.snapshot()
                mutate()
                with self.assertRaises(ValueError):
                    self.promote()
                self.assertEqual(self.snapshot(), before)
                self.run, self.jobs = copy.deepcopy(original_run), copy.deepcopy(original_jobs)
                self.digest = hashlib.sha256(self.data).hexdigest()
                (self.source / self.name).write_bytes(self.data)
                (self.source / 'unexpected.apk').unlink(missing_ok=True)

    @patch.object(publisher, 'verify_history', side_effect=ValueError('rollback'))
    def test_history_rejection_leaves_published_files_intact(self, history):
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'rollback'):
            self.promote()
        self.assertEqual(self.snapshot(), before)

    def test_real_git_history_rejects_rollback_unmerged_build_and_new_version(self):
        repo = self.root / 'repo'
        repo.mkdir()

        def git(*args):
            return subprocess.check_output(['git', *args], cwd=repo, text=True, stderr=subprocess.DEVNULL).strip()

        git('init', '-b', 'main')
        git('config', 'user.name', 'Fixture')
        git('config', 'user.email', 'fixture@example.invalid')
        package = repo / 'apps/desktop/package.json'
        package.parent.mkdir(parents=True)
        package.write_text('{"version":"0.4.0"}')
        git('add', '.')
        git('commit', '-m', 'base')
        base = git('rev-parse', 'HEAD')
        git('commit', '--allow-empty', '-m', 'macOS fix')
        source = git('rev-parse', 'HEAD')
        git('commit', '--allow-empty', '-m', 'publisher')
        publisher.verify_history(source, base, '0.4.0', root=repo)
        with self.assertRaisesRegex(ValueError, 'precede'):
            publisher.verify_history(base, source, '0.4.0', root=repo)
        git('switch', '-c', 'unmerged')
        git('commit', '--allow-empty', '-m', 'not on main')
        unmerged = git('rev-parse', 'HEAD')
        git('switch', 'main')
        with self.assertRaisesRegex(ValueError, 'on main'):
            publisher.verify_history(unmerged, base, '0.4.0', root=repo)
        package.write_text('{"version":"0.4.1"}')
        git('commit', '-am', 'new release')
        with self.assertRaisesRegex(ValueError, 'different product version'):
            publisher.verify_history(source, base, '0.4.0', root=repo)


if __name__ == '__main__':
    unittest.main()
