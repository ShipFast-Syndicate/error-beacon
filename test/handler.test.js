import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createErrorsHandler, createLokiForwarder } from '../src/index.js';
import { CONTEXT, HOSTILE_MESSAGE, assertNoPii } from './fixtures.js';

function setup(options = {}) {
  const pushed = [];
  const handler = createErrorsHandler({
    context: CONTEXT,
    forward: async (event) => {
      pushed.push(event);
    },
    ...options,
  });
  return { handler, pushed };
}

function post(body, init = {}) {
  return new Request('https://app.example.test/api/_errors', {
    method: 'POST',
    headers: { 'content-type': 'text/plain', ...(init.headers ?? {}) },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

const hostileBody = {
  name: 'TypeError',
  message: HOSTILE_MESSAGE,
  stack: ['at load (/home/jdupont/app/x.js:1:2)', 'at https://app.example.test/_app/c.js?email=jean.dupont@example.com:3:4'],
  route: '/orders/48213?email=jean.dupont@example.com',
  product: 'attacker',
  ip: '203.0.113.42',
  userId: '48213',
  body: { password: 'hunter2' },
  cookie: 'sessionabc123',
};

test('a hostile browser report is forwarded clean, with server-side identity', async () => {
  const { handler, pushed } = setup();
  const response = await handler(post(hostileBody));
  assert.equal(response.status, 204);
  assert.equal(pushed.length, 1);
  assertNoPii(JSON.stringify(pushed[0]));
  assert.equal(pushed[0].product, 'klar');
  assert.equal(pushed[0].source, 'client');
  assert.equal(pushed[0].route, '/orders/:id');
});

test('end to end through the Loki forwarder: nothing forbidden is pushed', async () => {
  const sent = [];
  const forwarder = createLokiForwarder({
    lokiUrl: 'https://loki.example.test/push',
    accessClientId: 'id',
    accessClientSecret: 'secret',
    fetch: async (url, init) => {
      sent.push(init.body);
      return { ok: true, status: 204 };
    },
  });
  const handler = createErrorsHandler({ context: CONTEXT, forward: (e) => forwarder.push(e) });
  assert.equal((await handler(post(hostileBody))).status, 204);
  assert.equal(sent.length, 1);
  assertNoPii(sent[0]);
});

test('route templates replace a raw browser path', async () => {
  const { handler, pushed } = setup({ routeTemplates: ['/u/[name]', '/'] });
  await handler(post({ message: 'm', route: '/u/jean' }));
  await handler(post({ message: 'm2', route: '/somewhere/else' }));
  assert.deepEqual(pushed.map((e) => e.route), ['/u/[name]', '[unmatched]']);
});

test('only POST is accepted', async () => {
  const { handler, pushed } = setup();
  const response = await handler(new Request('https://app.example.test/api/_errors'));
  assert.equal(response.status, 405);
  assert.equal(response.headers.get('allow'), 'POST');
  assert.equal(pushed.length, 0);
});

test('an oversized body is refused by header and by streaming count', async () => {
  const { handler, pushed } = setup({ maxBodyBytes: 200 });
  const big = JSON.stringify({ message: 'x'.repeat(500) });
  assert.equal((await handler(post(big))).status, 413);
  const lying = new Request('https://app.example.test/api/_errors', {
    method: 'POST',
    headers: { 'content-type': 'text/plain', 'content-length': '10' },
    body: big,
  });
  assert.equal((await handler(lying)).status, 413);
  assert.equal(pushed.length, 0);
});

test('malformed, empty and non-report bodies are 400', async () => {
  const { handler, pushed } = setup();
  assert.equal((await handler(post('{not json'))).status, 400);
  assert.equal((await handler(post(''))).status, 400);
  assert.equal((await handler(post('[]'))).status, 400);
  assert.equal((await handler(post({ nothing: 'useful' }))).status, 400);
  assert.equal(pushed.length, 0);
});

test('a foreign content type is refused', async () => {
  const { handler } = setup();
  const response = await handler(post({ message: 'm' }, { headers: { 'content-type': 'multipart/form-data' } }));
  assert.equal(response.status, 415);
});

test('cross-site callers are refused', async () => {
  const { handler, pushed } = setup({ allowedOrigins: ['https://app.example.test'] });
  assert.equal((await handler(post({ message: 'm' }, { headers: { origin: 'https://evil.test' } }))).status, 403);
  assert.equal((await handler(post({ message: 'm' }, { headers: { 'sec-fetch-site': 'cross-site' } }))).status, 403);
  assert.equal((await handler(post({ message: 'm' }, { headers: { origin: 'https://app.example.test' } }))).status, 204);
  assert.equal(pushed.length, 1);
});

test('the global rate limit answers 429 and refills over time', async () => {
  let t = 0;
  const { handler, pushed } = setup({ rate: { capacity: 2, refillPerSec: 1 }, now: () => t });
  assert.equal((await handler(post({ message: 'a' }))).status, 204);
  assert.equal((await handler(post({ message: 'b' }))).status, 204);
  const limited = await handler(post({ message: 'c' }));
  assert.equal(limited.status, 429);
  assert.ok(limited.headers.get('retry-after'));
  t += 2000;
  assert.equal((await handler(post({ message: 'd' }))).status, 204);
  assert.equal(pushed.length, 3);
});

test('a repeating signature is capped without starving other errors', async () => {
  const { handler, pushed } = setup({ perSignature: { capacity: 2, refillPerSec: 0 } });
  const same = { name: 'TypeError', message: 'same', stack: ['at f (/a.js:1:1)'] };
  const statuses = [];
  for (let i = 0; i < 4; i += 1) statuses.push((await handler(post(same))).status);
  assert.deepEqual(statuses, [204, 204, 429, 429]);
  assert.equal((await handler(post({ name: 'RangeError', message: 'other' }))).status, 204);
  assert.equal(pushed.length, 3);
});

test('a failing forwarder never surfaces to the browser', async () => {
  const { handler } = setup({
    forward: async () => {
      throw new Error('loki down');
    },
  });
  assert.equal((await handler(post({ message: 'm' }))).status, 204);
});

test('waitUntil takes ownership of the forward promise', async () => {
  const waited = [];
  const { handler, pushed } = setup({ waitUntil: (p) => waited.push(p) });
  assert.equal((await handler(post({ message: 'm' }))).status, 204);
  await Promise.all(waited);
  assert.equal(waited.length, 1);
  assert.equal(pushed.length, 1);
});

test('responses carry no body and no caching', async () => {
  const { handler } = setup();
  const response = await handler(post({ message: 'm' }));
  assert.equal(await response.text(), '');
  assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('a bad context fails at construction', () => {
  assert.throws(() => createErrorsHandler({ context: { product: 'x', env: 'prod' }, forward() {} }), /product/);
  assert.throws(() => createErrorsHandler({ context: CONTEXT }), /forward/);
});
