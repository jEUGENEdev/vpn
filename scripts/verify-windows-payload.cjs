'use strict';
// Inspect the actual PE resources, not just electron-builder configuration.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const R = require('../apps/desktop/node_modules/resedit');
const root = path.resolve(__dirname, '..');
const payload = path.resolve(process.argv[2] || path.join(root, 'apps/desktop/dist/win-unpacked'));
const product = require('../apps/desktop/package.json');
const fileVersions = {};
const version = info => [info.fileVersionMS >>> 16, info.fileVersionMS & 65535,
  info.fileVersionLS >>> 16, info.fileVersionLS & 65535].join('.');
function inspect(directory) {
  for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) { inspect(file); continue; }
    if (!/\.(exe|dll)$/i.test(entry.name)) continue;
    const data = fs.readFileSync(file);
    assert.equal(data.subarray(0, 2).toString(), 'MZ', file);
    assert.equal(data.readUInt16LE(data.readUInt32LE(0x3c) + 4), 0x8664, 'Expected x64: ' + file);
    const resources = R.NtExecutableResource.from(R.NtExecutable.from(data, {ignoreCert: true}));
    const infos = R.Resource.VersionInfo.fromEntries(resources.entries);
    const relative = path.relative(payload, file).split(path.sep).join('/');
    if (infos.length) {
      const versions = new Set(infos.map(info => version(info.fixedInfo)));
      assert.equal(versions.size, 1, 'Conflicting PE file versions: ' + relative);
      const languages = [...new Set(infos.flatMap(info => info.getAvailableLanguages().map(item => item.lang)))];
      fileVersions[relative] = {version: [...versions][0], language: languages.join(',')};
    }
    if (relative !== 'LineVPN.exe') continue;
    assert.ok(infos.length, 'Launcher has no Windows version information');
    assert.equal(fileVersions[relative].version, product.version + '.0');
    for (const info of infos) {
      const languages = info.getAllLanguagesForStringValues();
      assert.ok(languages.length, 'Launcher has no localized product name');
      for (const language of languages) {
        const strings = info.getStringValues(language);
        assert.equal(strings.ProductName, 'Сеть');
        assert.equal(strings.FileDescription, 'Сеть');
      }
    }
    const groups = R.Resource.IconGroupEntry.fromEntries(resources.entries);
    assert.equal(groups.length, 1, 'Expected one application icon group');
    const bytes = item => Buffer.from(item.isRaw() ? item.bin : item.generate());
    const supplied = R.Data.IconFile.from(fs.readFileSync(path.join(root, 'apps/desktop/branding/set.ico')));
    assert.deepEqual(groups[0].getIconItemsFromEntries(resources.entries).map(bytes), supplied.icons.map(item => bytes(item.data)));
  }
}
inspect(payload);
assert.ok(fileVersions['LineVPN.exe'], 'Missing LineVPN.exe');
const report = {product_version: product.version, product_name: 'Сеть', file_versions: fileVersions};
if (process.argv[3]) fs.writeFileSync(process.argv[3], JSON.stringify(report, null, 2) + '\n');
console.log('PASS: Windows PE product name, description, version, icons and x64 payload');
