import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  EVENT_SCHEMA,
  buildEvent,
  buildEventFromThrown,
  eventFromClientPayload,
  resolveContext,
  validateEvent,
} from '../src/index.js';
import { CONTEXT, assertNoPii, hostileError } from './fixtures.js';

const context = resolveContext(CONTEXT);

test('resolveContext pins identity and shortens the release sha', () => {
  assert.deepEqual(context, { product: 'klar', env: 'preview', release_sha: 'abcdef012345' });
  assert.equal(resolveContext({ product: 'klar', env: 'prod' }).release_sha, 'unknown');
  assert.equal(resolveContext({ product: 'klar', env: 'prod', releaseSha: 'not a sha' }).release_sha, 'unknown');
});

test('resolveContext rejects a bad product or env at start-up', () => {
  assert.throws(() => resolveContext({ product: 'Klar!', env: 'prod' }), /product/);
  assert.throws(() => resolveContext({ product: 'klar', env: 'develop' }), /env/);
  assert.throws(() => resolveContext(undefined), /context/);
});

test('an event built from a hostile error carries nothing forbidden', () => {
  const event = buildEventFromThrown(context, hostileError(), { route: '/orders/48213?email=jean.dupont@example.com' });
  assertNoPii(JSON.stringify(event));
  assert.ok(validateEvent(event));
  assert.deepEqual(Object.keys(event).sort(), Object.keys(EVENT_SCHEMA.properties).sort());
  assert.equal(event.route, '/orders/:id');
  assert.equal(event.product, 'klar');
  assert.equal(event.env, 'preview');
  assert.equal(event.release_sha, 'abcdef012345');
  assert.equal(event.source, 'server');
});

test('extra fields on the error never become event fields', () => {
  const event = buildEvent(context, hostileError());
  for (const forbidden of ['ip', 'email', 'userId', 'user', 'body', 'cookie', 'headers', 'url', 'query']) {
    assert.equal(forbidden in event, false, forbidden);
  }
});

test('non-Error throwables become a scrubbed event', () => {
  const event = buildEventFromThrown(context, 'plain string for jean.dupont@example.com');
  assert.equal(event.message, 'plain string for [email]');
  assert.equal(event.name, 'Error');
  assert.deepEqual(event.frames, []);
  assert.ok(validateEvent(event));
});

test('an error name that is not a plain identifier falls back to Error', () => {
  const event = buildEvent(context, { name: 'jean.dupont@example.com failed', message: 'x' });
  assert.equal(event.name, 'Error');
});

test('a client payload is reduced to name, message, stack and route', () => {
  const event = eventFromClientPayload(context, {
    name: 'TypeError',
    message: 'bad value for jean.dupont@example.com',
    stack: ['at f (/_app/chunk.js:1:2)'],
    route: '/orders/48213',
    product: 'attacker',
    env: 'prod',
    release_sha: 'ffffffffffff',
    ip: '203.0.113.42',
    userId: '48213',
    body: { password: 'hunter2' },
    cookie: 'sessionabc123',
  });
  assert.ok(validateEvent(event));
  assert.equal(event.source, 'client');
  assert.equal(event.product, 'klar');
  assert.equal(event.env, 'preview');
  assert.equal(event.release_sha, 'abcdef012345');
  assertNoPii(JSON.stringify(event));
  assert.equal(event.message, 'bad value for [email]');
});

test('a client payload that is not an error report is refused', () => {
  assert.equal(eventFromClientPayload(context, null), null);
  assert.equal(eventFromClientPayload(context, []), null);
  assert.equal(eventFromClientPayload(context, 'text'), null);
  assert.equal(eventFromClientPayload(context, { stack: 'x' }), null);
});

test('a client stack of the wrong type is ignored, not trusted', () => {
  const event = eventFromClientPayload(context, { message: 'm', stack: { evil: true } });
  assert.deepEqual(event.frames, []);
});

test('validateEvent is a closed check', () => {
  const good = buildEvent(context, new Error('x'));
  assert.ok(validateEvent(good));
  assert.equal(validateEvent({ ...good, ip: '203.0.113.42' }), false);
  assert.equal(validateEvent({ ...good, route: '/a?b=c' }), false);
  assert.equal(validateEvent({ ...good, env: 'develop' }), false);
  assert.equal(validateEvent({ ...good, frames: [{ fn: 'f', file: 'a', line: 1, col: 1, extra: 1 }] }), false);
  assert.equal(validateEvent({ ...good, signature: 'XYZ' }), false);
  assert.equal(validateEvent(null), false);
  const { signature, ...missing } = good;
  assert.equal(validateEvent(missing), false);
});
