'use strict';
// Use the service-aware installer recipes for every distributable desktop app.
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
let command, args;
if (process.platform === 'win32') {
  command = 'powershell.exe';
  args = ['-NoProfile', '-File', path.join(root, 'scripts/package-windows.ps1')];
} else if (process.platform === 'darwin') {
  command = 'bash';
  args = [path.join(root, 'scripts/package-macos.sh')];
} else {
  console.error('Build the Windows installer on Windows and the macOS installer on macOS.');
  process.exit(1);
}
const result = spawnSync(command, args, {cwd: root, stdio: 'inherit'});
if (result.error) console.error(result.error.message);
process.exit(result.status ?? 1);
