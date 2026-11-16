#!/usr/bin/env python3
"""Bundle upstream notices for the exact Go module graph used by this build."""
import json, os, pathlib, subprocess, sys
out = pathlib.Path(sys.argv[1]); out.parent.mkdir(parents=True, exist_ok=True)
raw = subprocess.check_output(['go', 'list', '-deps', '-tags=with_gvisor', '-json', './cmd/linevpn-agent'], text=True, timeout=180)
decoder = json.JSONDecoder(); modules = {};
while raw.strip():
    package, consumed = decoder.raw_decode(raw.lstrip()); raw = raw.lstrip()[consumed:]
    module = package.get('Module')
    if module: modules[module['Path']] = module
text = ['LineVPN third-party notices', pathlib.Path('THIRD_PARTY.md').read_text(), '\n']
for module in modules.values():
    if module.get('Main'): continue
    actual = module.get('Replace', module)
    directory = actual.get('Dir')
    if not directory: raise SystemExit('Dependency source missing: '+module['Path'])
    files = sorted(p for p in pathlib.Path(directory).iterdir() if p.is_file() and p.name.lower().split('.')[0] in {'license','licence','copying','notice','patents','copyright'})
    text.append('\n=== '+module['Path']+' '+module.get('Version','')+' ===\n')
    for file in files: text.extend([file.name+'\n',file.read_text(errors='replace'),'\n'])
root = pathlib.Path(subprocess.check_output(['go','env','GOROOT'],text=True).strip())
text.extend(['\n=== Go runtime ===\n',(root/'LICENSE').read_text()])
out.write_text('\n'.join(text),encoding='utf-8')
print('Bundled dependency notices:',out)
