import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  computeSignature,
  matchRoute,
  normalizeFileForSignature,
  normalizeRoute,
  scrubMessage,
  scrubStack,
} from '../src/index.js';
import { HOSTILE_MESSAGE, HOSTILE_STACK, assertNoPii } from './fixtures.js';

test('scrubMessage removes every forbidden value from a hostile message', () => {
  const out = scrubMessage(HOSTILE_MESSAGE, { maxLength: 2000 });
  assertNoPii(out);
  assert.match(out, /\[email\]/);
  assert.match(out, /\[ip\]/);
  assert.match(out, /https:\/\/app\.example\.com\/orders\/\[n\]\?\[redacted\]/);
});

test('scrubMessage keeps an engine property-access quote but not a quoted value', () => {
  assert.equal(
    scrubMessage("Cannot read properties of undefined (reading 'items')"),
    "Cannot read properties of undefined (reading 'items')",
  );
  assert.equal(scrubMessage('No account for "marie"'), 'No account for "[str]"');
});

test('scrubMessage redacts userinfo, fragments and relative query strings', () => {
  assert.equal(scrubMessage('fetch https://bob:pw@api.test/x#top failed'), 'fetch https://api.test/x#[redacted] failed');
  assert.equal(scrubMessage('GET /search?q=jean&page=2 failed'), 'GET /search?[redacted] failed');
});

test('scrubMessage masks home directories and Windows profiles', () => {
  assert.equal(scrubMessage('ENOENT /home/jdupont/x.json'), 'ENOENT /home/[user]/x.json');
  assert.equal(scrubMessage('ENOENT C:\\Users\\Jean\\x.json'), 'ENOENT C:\\Users\\[user]\\x.json');
});

test('scrubMessage is bounded and tolerant of non-strings', () => {
  assert.equal(scrubMessage(undefined), '');
  assert.equal(scrubMessage({ toString: () => 'boom 7' }), 'boom [n]');
  assert.equal(scrubMessage('x'.repeat(10_000)).length <= 300, true);
  const started = Date.now();
  scrubMessage(`${'a'.repeat(1990)}@`.repeat(3));
  scrubMessage(`password${'-'.repeat(1990)}`);
  assert.ok(Date.now() - started < 1000, 'no pathological regex backtracking');
});

test('scrubStack keeps frames only: no message line, no origin, no query, no home dir', () => {
  const frames = scrubStack(HOSTILE_STACK);
  assert.equal(frames.length, 4);
  assertNoPii(JSON.stringify(frames));
  assert.deepEqual(frames[0], {
    fn: 'handleOrder',
    file: '/home/[user]/app/src/routes/orders/[id]/+page.server.ts',
    line: 42,
    col: 11,
  });
  assert.equal(frames[2].file, '/_app/immutable/chunks/BcD3f9Xy.js');
  assert.equal(frames[3].fn, 'onClick');
});

test('scrubStack accepts an array and caps the frame count', () => {
  const lines = Array.from({ length: 80 }, (_, i) => `    at f${i} (/app/a.js:${i}:1)`);
  assert.equal(scrubStack(lines).length, 30);
  assert.deepEqual(scrubStack('no frames here\nat <anonymous>'), []);
});

test('normalizeRoute drops query and fragment and collapses ids', () => {
  assert.equal(normalizeRoute('/orders/12345/items/abc123def?email=a@b.co#x'), '/orders/:id/items/:id');
  assert.equal(normalizeRoute('/u/550e8400-e29b-41d4-a716-446655440000'), '/u/:id');
  assert.equal(normalizeRoute('/blog/[slug]/edit'), '/blog/[slug]/edit');
  assert.equal(normalizeRoute('/docs/[...rest]'), '/docs/[...rest]');
  assert.equal(normalizeRoute('https://app.test/a/b?c=d'), '/a/b');
  assert.equal(normalizeRoute(''), 'unknown');
  assert.equal(normalizeRoute('/x/jean@example.com'), '/x/:id');
});

test('normalizeRoute output is label-safe and bounded', () => {
  const route = normalizeRoute('/a b/"quoted"/' + 'z'.repeat(400));
  assert.match(route, /^[\w./~:\-[\](){}*]+$/);
  assert.ok(route.length <= 120);
});

test('matchRoute maps a concrete path onto the app route templates', () => {
  const templates = ['/', '/u/[name]', '/u/[name]/posts/[id]', '/(app)/settings', '/docs/[...rest]'];
  assert.equal(matchRoute('/u/jean?x=1', templates), '/u/[name]');
  assert.equal(matchRoute('/u/jean/posts/9', templates), '/u/[name]/posts/[id]');
  assert.equal(matchRoute('/settings', templates), '/(app)/settings');
  assert.equal(matchRoute('/docs/a/b/c', templates), '/docs/[...rest]');
  assert.equal(matchRoute('/unknown/path', templates), '[unmatched]');
});

test('normalizeFileForSignature strips build hashes', () => {
  assert.equal(normalizeFileForSignature('/_app/immutable/chunks/DRaQ1Mha.js'), '/_app/immutable/chunks/[hash].js');
  assert.equal(normalizeFileForSignature('/_app/immutable/entry/app.Cm3x9aBq.js'), '/_app/immutable/entry/app.[hash].js');
  assert.equal(normalizeFileForSignature('/_next/static/chunks/page-5d1c3f8a2b9e4c71.js'), '/_next/static/chunks/page-[hash].js');
  assert.equal(normalizeFileForSignature('/src/lib/Settings.js'), '/src/lib/Settings.js');
});

test('signature is stable across a redeploy and changes with the error', () => {
  const a = [{ fn: 'load', file: '/_app/immutable/chunks/DRaQ1Mha.js', line: 10, col: 5 }];
  const b = [{ fn: 'load', file: '/_app/immutable/chunks/Zx9Kp2Lm.js', line: 99, col: 1 }];
  const sig = computeSignature('TypeError', a, 'msg');
  assert.match(sig, /^[0-9a-f]{16}$/);
  assert.equal(computeSignature('TypeError', b, 'other message'), sig);
  assert.notEqual(computeSignature('RangeError', a, 'msg'), sig);
  assert.notEqual(computeSignature('TypeError', [{ ...a[0], fn: 'save' }], 'msg'), sig);
});

test('signature skips node internals and falls back to the message template', () => {
  const frames = [
    { fn: 'a', file: 'node:internal/process', line: 1, col: 1 },
    { fn: 'load', file: '/app/x.js', line: 1, col: 1 },
  ];
  assert.equal(computeSignature('E', frames, 'm'), computeSignature('E', [frames[1]], 'm'));
  assert.notEqual(computeSignature('E', [], 'one'), computeSignature('E', [], 'two'));
});
