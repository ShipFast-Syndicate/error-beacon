import assert from 'node:assert/strict';
import { test } from 'node:test';
import { astroErrorMiddleware, createReporter, nextOnRequestError, sveltekitHandleError } from '../src/index.js';
import { CONTEXT, assertNoPii, hostileError } from './fixtures.js';

function setup(options = {}) {
  const pushed = [];
  const reporter = createReporter({
    context: CONTEXT,
    forward: async (event) => {
      pushed.push(event);
    },
    ...options,
  });
  return { reporter, pushed };
}

test('report scrubs a hostile error and tags it as a server event', async () => {
  const { reporter, pushed } = setup();
  await reporter.report(hostileError(), { route: '/orders/48213?x=1' });
  assert.equal(pushed.length, 1);
  assertNoPii(JSON.stringify(pushed[0]));
  assert.equal(pushed[0].source, 'server');
  assert.equal(pushed[0].route, '/orders/:id');
});

test('report never rejects, even when forward throws', async () => {
  const { reporter } = setup({
    forward: async () => {
      throw new Error('loki down');
    },
  });
  await reporter.report(new Error('x'));
});

test('report drops a crash loop but keeps new signatures', async () => {
  const { reporter, pushed } = setup({ perSignature: { capacity: 2, refillPerSec: 0 } });
  const loop = Object.assign(new Error('same'), { stack: 'Error: same\n    at f (/a.js:1:1)' });
  for (let i = 0; i < 5; i += 1) await reporter.report(loop);
  await reporter.report(Object.assign(new Error('other'), { stack: 'Error: other\n    at g (/b.js:1:1)' }));
  assert.equal(pushed.length, 3);
});

test('SvelteKit adapter reports with the route id and skips 404s', async () => {
  const { reporter, pushed } = setup();
  const handle = sveltekitHandleError(reporter);
  const event = {
    route: { id: '/orders/[id]' },
    url: new URL('https://app.test/orders/48213?email=jean.dupont@example.com'),
    request: { headers: new Headers({ cookie: 'sessionabc123' }) },
    locals: { user: { email: 'jean.dupont@example.com' } },
  };
  assert.deepEqual(await handle({ error: hostileError(), event, status: 500, message: 'Internal Error' }), { message: 'Internal Error' });
  assert.equal(await handle({ error: new Error('nf'), event, status: 404, message: 'Not Found' }).then(() => pushed.length), 1);
  assert.equal(pushed[0].route, '/orders/[id]');
  assertNoPii(JSON.stringify(pushed));
});

test('SvelteKit adapter delegates to the app handler and uses waitUntil when present', async () => {
  const { reporter, pushed } = setup();
  const waited = [];
  const handle = sveltekitHandleError(reporter, (input) => ({ message: `custom ${input.status}` }));
  const event = { route: { id: '/' }, platform: { context: { waitUntil: (p) => waited.push(p) } } };
  assert.deepEqual(await handle({ error: new Error('x'), event, status: 500 }), { message: 'custom 500' });
  await Promise.all(waited);
  assert.equal(waited.length, 1);
  assert.equal(pushed.length, 1);
});

test('Next.js adapter prefers the route template over the request path', async () => {
  const { reporter, pushed } = setup();
  const onRequestError = nextOnRequestError(reporter);
  await onRequestError(hostileError(), { path: '/blog/48213?email=jean.dupont@example.com' }, { routePath: '/blog/[slug]' });
  await onRequestError(new Error('no template'), { path: '/blog/48213?email=jean.dupont@example.com' }, {});
  assert.deepEqual(pushed.map((e) => e.route), ['/blog/[slug]', '/blog/:id']);
  assertNoPii(JSON.stringify(pushed));
});

test('Astro middleware reports and rethrows the original error', async () => {
  const { reporter, pushed } = setup();
  const middleware = astroErrorMiddleware(reporter);
  const boom = new Error('astro boom for jean.dupont@example.com');
  await assert.rejects(
    middleware({ routePattern: '/blog/[slug]', request: { url: 'https://app.test/blog/x?y=1' } }, async () => {
      throw boom;
    }),
    (error) => error === boom,
  );
  assert.equal(pushed[0].route, '/blog/[slug]');
  assert.equal(pushed[0].message, 'astro boom for [email]');
  const ok = new Response('fine');
  assert.equal(await middleware({ request: { url: 'https://app.test/' } }, async () => ok), ok);
  assert.equal(pushed.length, 1);
});

test('Astro middleware falls back to the pathname, never the query', async () => {
  const { reporter, pushed } = setup();
  await assert.rejects(
    astroErrorMiddleware(reporter)({ request: { url: 'https://app.test/orders/48213?email=jean.dupont@example.com' } }, async () => {
      throw new Error('x');
    }),
  );
  assert.equal(pushed[0].route, '/orders/:id');
});
