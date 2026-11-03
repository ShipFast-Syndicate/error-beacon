// reporter.js — server-side capture (ADR-0058 §4) and the three framework
// adapters. Adapters only read the error and the route *template* from the
// framework's own objects; they never touch the URL query, headers, cookies, body,
// locals or the session, so there is nothing to scrub out of them.

import { buildEventFromThrown, resolveContext } from './event.js';
import { KeyedLimiter } from './limits.js';

/**
 * @param {{
 *   context: {product: string, env: string, releaseSha?: string},
 *   forward: (event: object) => Promise<unknown>,
 *   perSignature?: {capacity: number, refillPerSec: number},
 *   now?: () => number,
 * }} options
 */
export function createReporter(options) {
  const { forward, perSignature = { capacity: 5, refillPerSec: 1 / 10 }, now = Date.now } = options;
  if (typeof forward !== 'function') throw new TypeError('error-beacon: forward is required');
  const context = resolveContext(options.context);
  const bySignature = new KeyedLimiter({ ...perSignature, now });

  return {
    /**
     * Scrub and forward one error. Never throws and never rejects: reporting must
     * not be able to take a request down.
     * @param {unknown} thrown
     * @param {{route?: unknown, source?: 'server'|'client'}} [meta]
     * @returns {Promise<void>}
     */
    async report(thrown, meta = {}) {
      try {
        const event = buildEventFromThrown(context, thrown, { ...meta, now: new Date(now()) });
        if (!bySignature.take(event.signature)) return;
        await forward(event);
      } catch {
        // Swallowed on purpose; the forwarder already logged the cause.
      }
    },
  };
}

function waitUntilOf(platform) {
  const candidate = platform?.context?.waitUntil ?? platform?.ctx?.waitUntil;
  const owner = platform?.context?.waitUntil ? platform.context : platform?.ctx;
  return typeof candidate === 'function' ? candidate.bind(owner) : null;
}

async function settle(promise, waitUntil) {
  if (waitUntil) waitUntil(promise);
  else await promise;
}

/**
 * SvelteKit `handleError` (hooks.server.ts). Reports unexpected errors with the
 * route id as the route, then hands the original input to `inner` when given, else
 * returns a generic message.
 * @param {ReturnType<typeof createReporter>} reporter
 * @param {(input: any) => any} [inner]
 */
export function sveltekitHandleError(reporter, inner) {
  return async (input) => {
    const { error, event, status } = input;
    if (status !== 404) {
      const route = event?.route?.id ?? event?.url?.pathname ?? '';
      await settle(reporter.report(error, { route }), waitUntilOf(event?.platform));
    }
    return inner ? inner(input) : { message: 'Internal Error' };
  };
}

/**
 * Next.js `onRequestError` (instrumentation.ts). `routePath` is the template
 * (`/blog/[slug]`); `request.path` can carry a query string, so it is only a
 * fallback and is normalized.
 * @param {ReturnType<typeof createReporter>} reporter
 */
export function nextOnRequestError(reporter) {
  return async (error, request, context) => {
    await reporter.report(error, { route: context?.routePath ?? request?.path ?? '' });
  };
}

/**
 * Astro middleware (src/middleware.ts). Reports what the rest of the chain throws
 * and rethrows it unchanged.
 * @param {ReturnType<typeof createReporter>} reporter
 */
export function astroErrorMiddleware(reporter) {
  return async (context, next) => {
    try {
      return await next();
    } catch (error) {
      let route = context?.routePattern;
      if (!route) {
        try {
          route = new URL(context.request.url).pathname;
        } catch {
          route = '';
        }
      }
      await settle(reporter.report(error, { route }), waitUntilOf(context?.locals?.runtime));
      throw error;
    }
  };
}
