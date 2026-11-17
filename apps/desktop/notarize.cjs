'use strict';
const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// Runs after signing and BEFORE the DMG is assembled. Never modify a signed
// bundle afterwards: its notarization ticket must travel inside the image.
module.exports = async context => {
  if (context.electronPlatformName !== 'darwin' || process.env.LINEVPN_MACOS_SIGNING !== 'release') return;
  const profile = process.env.LINEVPN_MACOS_NOTARY_PROFILE;
  if (!profile) throw Error('LINEVPN_MACOS_NOTARY_PROFILE is required for release');
  const app = path.join(context.appOutDir, context.packager.appInfo.productFilename + '.app');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'linevpn-notary-'));
  const archive = path.join(dir, 'LineVPN.zip');
  const run = (command, args) => execFileSync(command, args, {stdio:'inherit'});
  try {
    run('codesign', ['--verify', '--deep', '--strict', app]);
    run('ditto', ['-c', '-k', '--keepParent', app, archive]);
    run('xcrun', ['notarytool', 'submit', archive, '--keychain-profile', profile, '--wait']);
    run('xcrun', ['stapler', 'staple', app]);
    run('xcrun', ['stapler', 'validate', app]);
    run('spctl', ['--assess', '--type', 'execute', '--verbose=2', app]);
  } finally { fs.rmSync(dir, {recursive:true, force:true}); }
};
