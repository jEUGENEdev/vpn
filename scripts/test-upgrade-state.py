"""Snapshot/check native CI state without logging credentials.

New applications may be observed while the replacement service starts, but
existing decisions, the profile and local UI token must remain intact.
"""
import hashlib
import json
from pathlib import Path
import sys

mode, data, snapshot = sys.argv[1:]
data, snapshot = Path(data), Path(snapshot)
state = {
    'hashes': {name: hashlib.sha256((data / name).read_bytes()).hexdigest()
               for name in ('profile.json', 'ui-token')},
    'decisions': {key: value['decision'] for key, value in json.loads((data / 'applications.json').read_text()).items()},
}
if mode == 'snapshot':
    snapshot.write_text(json.dumps(state))
elif mode == 'check':
    before = json.loads(snapshot.read_text())
    assert state['hashes'] == before['hashes'], 'Reinstall changed the profile or UI token'
    assert all(state['decisions'].get(key) == value for key, value in before['decisions'].items()), 'Reinstall lost an existing application decision'
else:
    raise SystemExit('Use snapshot or check')
