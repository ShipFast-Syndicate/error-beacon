// handler.js — the `/api/_errors` endpoint as a Web-standard (Request) => Response
// function, so SvelteKit `+server.ts`, a Next.js route handler, an Astro endpoint
// and a Worker can all mount the same code.
//
// The endpoint is public and unauthenticated by design (the browser must be able to
// call it), so it is a hostile boundary: it caps size, rejects cross-site callers,
// reads only four fields, rebuilds the event from the server-side context and
// rate-limits by content. The browser never talks to Loki.

import { eventFromClientPayload, resolveContext } from './event.js';
import { KeyedLimiter, TokenBucket } from './limits.js';
import { matchRoute } from './scrub.js';

export const DEFAULT_MAX_BODY_BYTES = 8 * 1024;

const BASE_HEADERS = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };

function respond(status, extra = {}) {
  return new Response(null, { status, headers: { ...BASE_HEADERS, ...extra } });
}

async function readCapped(request, maxBytes) {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

/**
 * @param {{
 *   context: {product: string, env: string, releaseSha?: string},
 *   forward: (event: object) => Promise<unknown>,
 *   routeTemplates?: readonly string[],
 *   allowedOrigins?: readonly string[],
 *   maxBodyBytes?: number,
 *   rate?: {capacity: number, refillPerSec: number},
 *   perSignature?: {capacity: number, refillPerSec: number},
 *   waitUntil?: (promise: Promise<unknown>) => void,
 *   now?: () => number,
 * }} options
 * @returns {(request: Request) => Promise<Response>}
 */
export function createErrorsHandler(options) {
  const {
    forward,
    routeTemplates,
    allowedOrigins,
    maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
    rate = { capacity: 20, refillPerSec: 0.5 },
    perSignature = { capacity: 5, refillPerSec: 1 / 12 },
    waitUntil,
    now = Date.now,
  } = options;
  if (typeof forward !== 'function') throw new TypeError('error-beacon: forward is required');
  const context = resolveContext(options.context);
  const global = new TokenBucket({ ...rate, now });
  const bySignature = new KeyedLimiter({ ...perSignature, now });
  const origins = allowedOrigins ? new Set(allowedOrigins) : null;

  return async function handleErrorsRequest(request) {
    if (request.method !== 'POST') return respond(405, { Allow: 'POST' });

    const origin = request.headers.get('origin');
    if (origins && origin && !origins.has(origin)) return respond(403);
    if (request.headers.get('sec-fetch-site') === 'cross-site') return respond(403);

    const type = (request.headers.get('content-type') ?? '').toLowerCase();
    // sendBeacon posts text/plain unless the caller built a typed Blob.
    if (type && !type.startsWith('application/json') && !type.startsWith('text/plain')) return respond(415);

    if (!global.take()) return respond(429, { 'Retry-After': '30' });

    const text = await readCapped(request, maxBodyBytes);
    if (text === null) return respond(413);

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      return respond(400);
    }
    const event = eventFromClientPayload(context, parsed, new Date(now()));
    if (!event) return respond(400);
    if (routeTemplates) {
      const raw = typeof parsed.route === 'string' ? parsed.route : '';
      event.route = matchRoute(raw, routeTemplates);
    }
    if (!bySignature.take(event.signature)) return respond(429, { 'Retry-After': '30' });

    const sent = Promise.resolve()
      .then(() => forward(event))
      .catch(() => {});
    if (waitUntil) waitUntil(sent);
    else await sent;
    return respond(204);
  };
}
