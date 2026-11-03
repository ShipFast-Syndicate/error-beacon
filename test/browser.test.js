import assert from 'node:assert/strict';
import { test } from 'node:test';
import { installBrowserBeacon } from '../src/browser.js';
import { createErrorsHandler } from '../src/index.js';
import { CONTEXT, HOSTILE_MESSAGE, HOSTILE_STACK, assertNoPii } from './fixtures.js';

function fakeWindow({ beacon = true } = {}) {
  const listeners = {};
  const sent = [];
  const target = {
    location: { pathname: '/orders/48213', search: '?email=jean.dupont@example.com' },
    addEventListener: (type, fn) => {
      listeners[type] = fn;
    },
    removeEventListener: (type) => {
      delete listeners[type];
    },
    navigator: beacon
      ? {
          sendBeacon: (url, blob) => {
            sent.push({ url, blob });
            return true;
          },
        }
      : undefined,
    fetch: async (url, init) => {
      sent.push({ url, init });
      return { ok: true };
    },
  };
  return { target, listeners, sent };
}

const bodyOf = async (entry) => (entry.blob ? entry.blob.text() : entry.init.body);

test('window errors are posted to the same-origin endpoint, scrubbed before they leave the page', async () => {
  const { target, listeners, sent } = fakeWindow();
  installBrowserBeacon({ target });
  const error = new Error(HOSTILE_MESSAGE);
  error.stack = HOSTILE_STACK;
  Object.assign(error, { email: 'jean.dupont@example.com', userId: '48213' });
  listeners.error({ error, message: HOSTILE_MESSAGE, filename: 'https://app.test/x.js?email=jean.dupont@example.com' });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].url, '/api/_errors');
  const text = await bodyOf(sent[0]);
  assertNoPii(text);
  assert.deepEqual(Object.keys(JSON.parse(text)).sort(), ['message', 'name', 'route', 'stack']);
  assert.equal(JSON.parse(text).route, '/orders/:id');
});

test('unhandled rejections are captured, including non-Error reasons', async () => {
  const { target, listeners, sent } = fakeWindow();
  installBrowserBeacon({ target });
  listeners.unhandledrejection({ reason: 'failed for jean.dupont@example.com' });
  assert.equal(JSON.parse(await bodyOf(sent[0])).message, 'failed for [email]');
});

test('reports are deduplicated and capped per page load', () => {
  const { target, listeners, sent } = fakeWindow();
  installBrowserBeacon({ target, maxReports: 3 });
  for (let i = 0; i < 4; i += 1) listeners.error({ error: new Error('same') });
  assert.equal(sent.length, 1);
  for (const m of ['a', 'b', 'c', 'd']) listeners.error({ error: new TypeError(m) });
  assert.equal(sent.length, 3);
});

test('getRoute supplies a template and a query string is cut anyway', async () => {
  const { target, listeners, sent } = fakeWindow();
  installBrowserBeacon({ target, getRoute: () => '/orders/[id]?email=jean.dupont@example.com' });
  listeners.error({ error: new Error('x') });
  assert.equal(JSON.parse(await bodyOf(sent[0])).route, '/orders/[id]');
});

test('falls back to fetch keepalive without credentials when sendBeacon is missing', async () => {
  const { target, listeners, sent } = fakeWindow({ beacon: false });
  installBrowserBeacon({ target });
  listeners.error({ error: new Error('x') });
  assert.equal(sent[0].init.keepalive, true);
  assert.equal(sent[0].init.credentials, 'omit');
});

test('the uninstall function removes both listeners', () => {
  const { target, listeners } = fakeWindow();
  const uninstall = installBrowserBeacon({ target });
  uninstall();
  assert.deepEqual(Object.keys(listeners), []);
});

test('what the browser sends is accepted by the server handler and stays clean', async () => {
  const { target, listeners, sent } = fakeWindow();
  installBrowserBeacon({ target });
  const error = new Error(HOSTILE_MESSAGE);
  error.stack = HOSTILE_STACK;
  listeners.error({ error });
  const pushed = [];
  const handler = createErrorsHandler({ context: CONTEXT, forward: async (e) => void pushed.push(e) });
  const response = await handler(
    new Request('https://app.test/api/_errors', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: await bodyOf(sent[0]) }),
  );
  assert.equal(response.status, 204);
  assertNoPii(JSON.stringify(pushed));
  assert.equal(pushed[0].frames.length, 4);
});
