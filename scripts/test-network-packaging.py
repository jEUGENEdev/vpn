#!/usr/bin/env python3
"""Inspect the generated installer, rather than grep its generator source."""
import pathlib
import plistlib
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

root = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temporary:
    work = pathlib.Path(temporary)
    payload = work / 'payload'
    (payload / 'resources/agent').mkdir(parents=True)
    (payload / 'resources/agent/linevpn-agent.exe').write_bytes(b'test payload')
    (payload / 'LineVPN.exe').write_bytes(b'test UI')
    output = work / 'package.wxs'
    subprocess.run([sys.executable, str(root / 'packaging/windows/package.py'), str(payload), str(output)], check=True)
    ns = {'w': 'http://wixtoolset.org/schemas/v4/wxs'}
    tree = ET.parse(output)
    action = tree.find('.//w:CustomAction[@Id="RecoverNetwork"]', ns)
    assert action is not None
    assert action.attrib['Execute'] == 'deferred' and action.attrib['Impersonate'] == 'no'
    assert action.attrib['Return'] == 'check', 'cleanup failure must retain recovery files'
    assert action.attrib['FileRef'] == 'Agent' and action.attrib['ExeCommand'] == '-recover-network'
    scheduled = tree.find('.//w:InstallExecuteSequence/w:Custom[@Action="RecoverNetwork"]', ns)
    assert scheduled is not None and scheduled.attrib['After'] == 'StopServices'
    assert scheduled.attrib['Condition'] == 'REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE', 'upgrades must retain protection'
    service = tree.find('.//w:ServiceControl', ns)
    assert service.attrib['Stop'] == 'both' and service.attrib['Wait'] == 'yes'
    upgrade = tree.find('.//w:MajorUpgrade', ns)
    assert upgrade.attrib['Schedule'] == 'afterInstallInitialize', 'failed upgrades must roll back the old product'
    assert upgrade.attrib.get('AllowSameVersionUpgrades', 'no') == 'no'

plist = plistlib.loads((root / 'packaging/macos/dev.linevpn.agent.plist').read_bytes())
assert plist['ProgramArguments'] == ['/Library/Application Support/LineVPN/service-wrapper.sh']
for script in ('service-wrapper.sh', 'uninstall.sh', 'recover-network.sh', 'preinstall', 'postinstall', 'Uninstall-LineVPN.command'):
    subprocess.run(['bash', '-n', str(root / 'packaging/macos' / script)], check=True)
print('PASS: generated MSI recovery ordering, checked elevated cleanup, upgrade path and macOS supervisor packaging')
