"""Promote an already checked main-branch DMG without rebuilding other platforms."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
NATIVE_STEP = 'Verify service lifecycle and network recovery on matching host architecture'
REQUIRED_JOBS = ('security / Security checks', 'test',
                 'macos (arm64, macos-15)', 'macos (amd64, macos-15-intel)')


def verify_run(run, jobs, repository):
    if (run.get('status') != 'completed' or run.get('conclusion') != 'success'
            or run.get('event') != 'workflow_dispatch' or run.get('head_branch') != 'main'
            or run.get('path') != '.github/workflows/build.yml'
            or run.get('repository', {}).get('full_name') != repository
            or run.get('head_repository', {}).get('full_name') != repository
            or not re.fullmatch(r'[0-9a-f]{40}', run.get('head_sha', ''))
            or not isinstance(run.get('id'), int)):
        raise ValueError('Only successful installer builds from this repository main are publishable')
    for name in REQUIRED_JOBS:
        matching = [job for job in jobs['jobs'] if job['name'] == name]
        if len(matching) != 1 or any(
                matching[0].get(key) != value for key, value in
                [('run_id', run['id']), ('status', 'completed'), ('conclusion', 'success')]):
            raise ValueError(f'Missing successful build check: {name}')
        if name.startswith('macos ') and not any(
                step['name'] == NATIVE_STEP and step['conclusion'] == 'success'
                for step in matching[0].get('steps', [])):
            raise ValueError(f'Missing successful native lifecycle check: {name}')


def verify_history(source, previous, version, root=ROOT):
    for commit in (source, previous):
        if not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise ValueError('Invalid source commit')
    # HEAD is the latest checked-out main. Never force a branch or roll back a DMG.
    for ancestor, descendant in ((source, 'HEAD'), (previous, source)):
        result = subprocess.run(['git', 'merge-base', '--is-ancestor', ancestor, descendant],
                                cwd=root, check=False)
        if result.returncode != 0:
            raise ValueError('Source must be on main and cannot precede the published macOS build')
    for commit in (source, 'HEAD'):
        package = subprocess.check_output(
            ['git', 'show', f'{commit}:apps/desktop/package.json'], cwd=root, text=True)
        if json.loads(package)['version'] != version:
            raise ValueError('Use the full release workflow for a different product version')


def promote(source, dest, run, jobs, repository, expected_sha256, minimum_size=20_000_000):
    verify_run(run, jobs, repository)
    manifest = json.loads((dest / 'manifest.json').read_text(encoding='utf-8'))
    version = manifest['version'].removesuffix('-preview')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid published version')
    name = f'Сеть-{version}-macos-universal.dmg'
    entries = [entry for entry in manifest['files'] if entry['name'].endswith('.dmg')]
    if len(entries) != 1 or entries[0]['name'] != name:
        raise ValueError('Expected one existing universal macOS installer')
    entry = entries[0]
    verify_history(run['head_sha'], entry.get('source_commit', manifest['source_commit']), version)
    if sorted(path.name for path in source.iterdir()) != [name]:
        raise ValueError('Artifact must contain exactly the expected universal DMG')
    dmg = source / name
    if dmg.is_symlink() or not dmg.is_file() or dmg.stat().st_size < max(512, minimum_size):
        raise ValueError('Missing or truncated disk image')
    with dmg.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        stream.seek(-512, 2)
        if stream.read(4) != b'koly':
            raise ValueError('Not an Apple UDIF disk image')
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha256) or digest != expected_sha256:
        raise ValueError('DMG SHA-256 does not match the explicitly requested build')
    url = f'https://github.com/{repository}/actions/runs/{run["id"]}'
    entry.update(size=dmg.stat().st_size, sha256=digest, source_commit=run['head_sha'],
                 built_at=run['updated_at'], build_run_id=run['id'], build_run_url=url)
    # Keep the base set's provenance; only this file has a newer source/build.
    manifest['source_commit_scope'] = 'Base installer set; per-file source_commit and built_at override it'
    manifest['updated_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    checksums = ''.join(f'{item["sha256"]}  {item["name"]}\n' for item in manifest['files'])
    readme = (dest / 'README.md').read_text(encoding='utf-8')
    start, end = '<!-- macos-build:start -->', '<!-- macos-build:end -->'
    block = (f'{start}\n**Отдельное обновление macOS:** [сборка {run["id"]}]({url}) из '
             f'`{run["head_sha"]}`; нативные проверки Intel и Apple Silicon пройдены. '
             f'DMG опубликован без пересборки. Размер: {dmg.stat().st_size} байт; '
             f'SHA-256: `{digest}`. Android и Windows остаются из базового комплекта.\n{end}')
    if start in readme or end in readme:
        if readme.count(start) != 1 or readme.count(end) != 1 or readme.index(end) < readme.index(start):
            raise ValueError('Malformed macOS publication section in README')
        before, rest = readme.split(start, 1)
        _, after = rest.split(end, 1)
        readme = before + block + after
    else:
        heading = '## Порядок установки'
        if readme.count(heading) != 1:
            raise ValueError('Cannot locate installation instructions in README')
        readme = readme.replace(heading, block + '\n\n' + heading, 1)
    # Validate everything before touching the published set. Only the workflow's
    # final non-forced Git push makes these working-tree changes public.
    shutil.copyfile(dmg, dest / name)
    (dest / 'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    (dest / 'SHA256SUMS').write_text(checksums, encoding='utf-8')
    (dest / 'README.md').write_text(readme, encoding='utf-8')
    print(f'Prepared {name}: {digest} from {url}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('dest', type=Path)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--jobs', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    promote(args.source, args.dest, json.loads(args.run.read_text()),
            json.loads(args.jobs.read_text()), args.repository, args.sha256)
