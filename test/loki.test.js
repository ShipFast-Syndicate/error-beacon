import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SERVICE_LABEL, buildEventFromThrown, buildPushBody, createLokiForwarder, resolveContext } from '../src/index.js';
import { CONTEXT, assertNoPii, hostileError } from './fixtures.js';

const context = resolveContext(CONTEXT);
const config = {
  lokiUrl: 'https://loki-push.example.test/loki/api/v1/push',
  accessClientId: 'client-id.access',
  accessClientSecret: 'client-secret-value',
};

function recorder(response = { ok: true, status: 204 }) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    if (response instanceof Error) throw response;
    return response;
  };
  return { calls, fetch };
}

test('push sends the labelled Loki body with the Access headers', async () => {
  const { calls, fetch } = recorder();
  const forwarder = createLokiForwarder({ ...config, fetch });
  const event = buildEventFromThrown(context, hostileError(), { route: '/orders/[id]' });
  const result = await forwarder.push(event);
  assert.deepEqual(result, { ok: true, status: 204 });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, config.lokiUrl);
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers['CF-Access-Client-Id'], config.accessClientId);
  assert.equal(calls[0].init.headers['CF-Access-Client-Secret'], config.accessClientSecret);

  const body = JSON.parse(calls[0].init.body);
  const [stream] = body.streams;
  assert.deepEqual(Object.keys(stream.stream).sort(), ['env', 'product', 'release_sha', 'route', 'service', 'signature']);
  assert.equal(stream.stream.service, SERVICE_LABEL);
  assert.equal(stream.stream.product, 'klar');
  assert.equal(stream.stream.env, 'preview');
  assert.equal(stream.stream.release_sha, 'abcdef012345');
  assert.equal(stream.stream.route, '/orders/[id]');
  assert.equal(stream.stream.signature, event.signature);
  const [ts, line] = stream.values[0];
  assert.match(ts, /^\d{19}$/);
  assert.deepEqual(JSON.parse(line), event);
  assertNoPii(calls[0].init.body);
});

test('the credentials never appear in the body', async () => {
  const { calls, fetch } = recorder();
  await createLokiForwarder({ ...config, fetch }).push(buildEventFromThrown(context, new Error('x')));
  assert.equal(calls[0].init.body.includes(config.accessClientSecret), false);
});

test('push refuses an event that does not match the schema', async () => {
  const { calls, fetch } = recorder();
  const errors = [];
  const forwarder = createLokiForwarder({ ...config, fetch, onError: (r) => errors.push(r) });
  const event = { ...buildEventFromThrown(context, new Error('x')), ip: '203.0.113.42' };
  assert.deepEqual(await forwarder.push(event), { ok: false, reason: 'invalid-event' });
  assert.equal(calls.length, 0);
  assert.equal(errors.length, 1);
});

test('push is a logged no-op when the endpoint is not configured', async () => {
  const { calls, fetch } = recorder();
  const errors = [];
  const forwarder = createLokiForwarder({ fetch, onError: (r) => errors.push(r) });
  assert.deepEqual(await forwarder.push(buildEventFromThrown(context, new Error('x'))), { ok: false, reason: 'not-configured' });
  assert.equal(calls.length, 0);
  assert.match(errors[0], /not configured/);
});

test('push never throws on a Loki rejection, a network failure or a timeout', async () => {
  const event = buildEventFromThrown(context, new Error('x'));
  const quiet = { onError() {} };
  assert.deepEqual(
    await createLokiForwarder({ ...config, ...quiet, fetch: recorder({ ok: false, status: 503 }).fetch }).push(event),
    { ok: false, status: 503, reason: 'loki-rejected' },
  );
  assert.deepEqual(
    await createLokiForwarder({ ...config, ...quiet, fetch: recorder(new Error('down')).fetch }).push(event),
    { ok: false, reason: 'network' },
  );
  const hang = (url, init) => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(Object.assign(new Error('a'), { name: 'AbortError' }))));
  assert.deepEqual(
    await createLokiForwarder({ ...config, ...quiet, fetch: hang, timeoutMs: 20 }).push(event),
    { ok: false, reason: 'network' },
  );
});

test('route and signature labels are bounded per process', async () => {
  const { calls, fetch } = recorder();
  const forwarder = createLokiForwarder({ ...config, fetch, maxRoutes: 2, maxSignatures: 2 });
  for (let i = 0; i < 5; i += 1) {
    const event = buildEventFromThrown(context, { name: `Err${'abcde'[i]}`, message: 'm' }, { route: `/r${'abcde'[i]}` });
    await forwarder.push(event);
  }
  const labels = calls.map((c) => JSON.parse(c.init.body).streams[0].stream);
  assert.equal(new Set(labels.map((l) => l.route)).size, 3);
  assert.equal(new Set(labels.map((l) => l.signature)).size, 3);
  assert.equal(labels[4].route, '[other]');
  assert.equal(labels[4].signature, '[other]');
  // The full signature is still in the log line.
  assert.match(JSON.parse(JSON.parse(calls[4].init.body).streams[0].values[0][1]).signature, /^[0-9a-f]{16}$/);
});

test('buildPushBody keeps label values to a safe charset', () => {
  const event = { ...buildEventFromThrown(context, new Error('x')), route: '/ok' };
  const body = JSON.parse(buildPushBody(event, { route: '/a b"c', signature: 'abc' }));
  assert.equal(body.streams[0].stream.route, '/a_b_c');
});
