#!/bin/bash
# Explicit emergency escape. Running this disables VPN protection.
set -euo pipefail
if [[ "$EUID" -ne 0 ]]; then echo 'Run with sudo. This disables protection.' >&2; exit 1; fi
/bin/launchctl bootout system/dev.linevpn.agent 2>/dev/null || true
/sbin/pfctl -a linevpn -F rules
# Restore DNS values saved before installation using the system JXA runtime.
if [[ -s /var/lib/linevpn/dns-backup.json ]]; then
/usr/bin/osascript -l JavaScript <<'JXA'
ObjC.import('Foundation');
var app=Application.currentApplication(); app.includeStandardAdditions=true;
var p='/var/lib/linevpn/dns-backup.json';
var data=$.NSData.dataWithContentsOfFile(p);
if(data){ var dict=JSON.parse(ObjC.unwrap($.NSString.alloc.initWithDataEncoding(data,$.NSUTF8StringEncoding))); var quote=s=>"'"+s.replace(/'/g,"'\\''")+"'"; Object.keys(dict).forEach(s=>app.doShellScript('/usr/sbin/networksetup -setdnsservers '+quote(s)+' '+dict[s].map(quote).join(' '))); }
JXA
fi
/usr/bin/dscacheutil -flushcache
