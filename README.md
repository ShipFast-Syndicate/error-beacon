# @alphabros/error-beacon

The one shared implementation of the first-party production error beacon
(Alpha Bros ADR-0058). Apps consume it; nothing is reimplemented per app, so the PII
contract lives in exactly one place.

## Install

```sh
pnpm add @alphabros/error-beacon
```

The package is public on npm: no `.npmrc`, no token. Requires Node 20+.

Zero runtime dependencies, plain ESM, Web-standard `Request`/`Response`: the same code
runs in Node, Cloudflare Workers/Pages, Vercel (node and edge) and the browser.

## The contract

A captured event **may** carry: stack frames, route template (no query string), release
sha, env (`prod`/`preview`), product, and an error message with values redacted.
It **never** carries: client IP, email, user id, query strings, request bodies,
cookies/auth headers, or anything else that could re-identify a person.

It is enforced by construction, not by blacklist:

- `buildEvent` copies **only** `name`, `message`, `stack` from an error and builds the
  event field by field. An `ip`, `user`, `body` or `cookie` property on the error or in a
  browser payload has no path into the output.
- A stack becomes `{fn, file, line, col}` frames. The first stack line (which repeats the
  message) is dropped; origins, query strings, fragments and home directories are stripped.
- `scrubMessage` redacts emails, URL query/fragment/userinfo, bearer tokens, JWTs,
  `password=`/`api_key:`-style pairs, UUIDs, IPv4/IPv6, long hex/opaque tokens, quoted values
  and every number. Output is capped at 300 characters.
- `product`, `env` and `release_sha` always come from the server-side context, never from a
  browser payload.
- `validateEvent` is a closed check (exact keys and types). The Loki forwarder refuses to push
  anything that fails it.
- The scrub runs in the app process, and again at `/api/_errors` for browser reports.

## Server side

```js
import { createLokiForwarder, createReporter, createErrorsHandler } from '@alphabros/error-beacon';

const context = { product: 'klar', env: 'prod', releaseSha: process.env.RELEASE_SHA };
const forwarder = createLokiForwarder({
  lokiUrl: env.ERROR_BEACON_LOKI_URL,
  accessClientId: env.ERROR_BEACON_CF_ACCESS_CLIENT_ID,
  accessClientSecret: env.ERROR_BEACON_CF_ACCESS_CLIENT_SECRET,
});
const forward = (event) => forwarder.push(event);
const reporter = createReporter({ context, forward });
```

Build `context.releaseSha` from the platform's commit variable (`CF_PAGES_COMMIT_SHA`,
`VERCEL_GIT_COMMIT_SHA`, or the build's own). A missing or malformed value becomes `unknown`.
`env` is `prod` or `preview` (develop/staging is `preview`); anything else throws at start-up.

### SvelteKit — `src/hooks.server.ts`

```ts
import { sveltekitHandleError } from '@alphabros/error-beacon';
export const handleError = sveltekitHandleError(reporter); // optional 2nd arg: your own handler
```

`src/routes/api/_errors/+server.ts`:

```ts
import { createErrorsHandler } from '@alphabros/error-beacon';
const handler = createErrorsHandler({ context, forward, routeTemplates: ROUTE_IDS });
export const POST = ({ request, platform }) => handler(request);
```

### Next.js — `instrumentation.ts`

```ts
import { nextOnRequestError } from '@alphabros/error-beacon';
export const onRequestError = nextOnRequestError(reporter);
```

`app/api/_errors/route.ts`: `export const POST = (request: Request) => handler(request);`

### Astro — `src/middleware.ts`

```ts
import { astroErrorMiddleware } from '@alphabros/error-beacon';
export const onRequest = astroErrorMiddleware(reporter);
```

`src/pages/api/_errors.ts`: `export const POST = ({ request }) => handler(request);`

### Route labels

Pass the framework's **route template** (SvelteKit `event.route.id`, Next `routePath`, Astro
`routePattern`); the adapters already do. A raw path is only a fallback: `normalizeRoute` strips the
query and collapses id-looking segments to `:id`, but it cannot know that `/u/jean` is a username.
For browser reports, give `createErrorsHandler` the app's `routeTemplates`; a path that matches none
becomes `[unmatched]`, which also keeps an outsider from widening the `route` label.

### `/api/_errors` hardening (the endpoint is unauthenticated)

`createErrorsHandler` answers `405` to non-POST, `403` to `Sec-Fetch-Site: cross-site` or an `Origin`
outside `allowedOrigins`, `415` to a foreign content type, `413` past `maxBodyBytes` (default 8 KiB,
enforced on the header and while streaming), `400` to anything that is not an error report, and `429`
to a flood. Rate limiting is a global token bucket (default 20 burst, 30/min sustained) plus a
per-signature bucket, both keyed on event content: **no IP is read, hashed or stored**. State is
per isolate, so it is a best-effort first line. The Loki label budgets below and Cloudflare in front
are the other two. Pass `waitUntil` (Workers `ctx.waitUntil`) so forwarding does not delay the `204`.

## Browser

```js
import { installBrowserBeacon } from '@alphabros/error-beacon/browser';
installBrowserBeacon({ getRoute: () => page.route.id ?? location.pathname });
```

Registers `window.onerror` + `unhandledrejection` and posts `{name, message, stack, route}`
(scrubbed, `sendBeacon`, `fetch keepalive` fallback, no credentials) to the app's own
`/api/_errors`. At most 5 distinct reports per page load. The browser never sees the Loki URL or a
credential.

## Loki labels

`service="error-beacon"`, `product`, `env`, `release_sha` (12 chars), `route`, `signature`. The full
event is the JSON log line (`| json` in LogQL). Cardinality is bounded: product/env are validated,
the sha is fixed per build, and the forwarder admits at most 200 distinct `route` and 500 distinct
`signature` values per process before collapsing the rest to `[other]` (the real signature stays in
the log line). `signature` is a hash of the error type plus the normalized top three frames (function
and hash-stripped file; no line/col, which shift each release), so a redeploy does not make every
error look new.

## Tests

```sh
npm test      # node --test, no install step
```
