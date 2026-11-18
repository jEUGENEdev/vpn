'use strict';
// Exercise the actual matcher used by electron-builder, including its upgraded
// minimatch dependency. Keep the adversarial compilation in a bounded process.
const assert = require('node:assert/strict');
const path = require('node:path');
const {createRequire} = require('node:module');
const {spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '..');
const desktopRequire = createRequire(path.join(root, 'apps/desktop/package.json'));
const builderRequire = createRequire(desktopRequire.resolve('app-builder-lib/package.json'));
const minimatchPath = builderRequire.resolve('minimatch');
const pattern = Array(18).fill('a/**/../b').join('/');
const result = spawnSync(process.execPath, ['-e', `
  const {Minimatch} = require(${JSON.stringify(minimatchPath)});
  require('node:assert/strict').throws(
    () => new Minimatch(${JSON.stringify(pattern)}, {optimizationLevel: 2}),
    {name: 'RangeError', message: /too many patterns/});
`], {encoding: 'utf8', timeout: 3000});
assert.ifError(result.error);
assert.equal(result.status, 0, result.stderr);

const {FileMatcher} = desktopRequire('app-builder-lib/out/fileMatcher');
const matcher = new FileMatcher(root, path.join(root, 'build/glob-fixture'), x => x,
  ['main.cjs', 'preload.cjs', 'package.json', 'assets/**/*', '!assets/**/*.key']);
const patterns = [];
matcher.computeParsedPatterns(patterns);
const {Minimatch} = builderRequire('minimatch');
assert.ok(patterns.every(pattern => pattern instanceof Minimatch));
const filter = matcher.createFilter();
const file = {isDirectory: () => false};
for (const name of ['main.cjs', 'preload.cjs', 'package.json', 'assets/agent.exe']) {
  assert.equal(filter(path.join(root, name), file), true, name);
}
for (const name of ['notarize.cjs', 'node_modules/picomatch/index.js', 'assets/private.key']) {
  assert.equal(filter(path.join(root, name), file), false, name);
}
console.log('PASS: bounded glob compilation and Electron payload filtering');
