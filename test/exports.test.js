import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import * as api from '../src/index.js';
import * as browser from '../src/browser.js';

const declared = (file) =>
  [...readFileSync(new URL(file, import.meta.url), 'utf8').matchAll(/^export (?:declare )?(?:const|function|class) (\w+)/gm)]
    .map((m) => m[1])
    .sort();

test('index.d.ts declares exactly the runtime exports', () => {
  assert.deepEqual(declared('../index.d.ts'), Object.keys(api).sort());
});

test('browser.d.ts declares exactly the browser exports', () => {
  assert.deepEqual(declared('../browser.d.ts'), Object.keys(browser).sort());
});

test('the package has no runtime dependencies', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.type, 'module');
});
