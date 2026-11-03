// event.js — the payload contract (ADR-0058 §2/§3).
//
// An event is built field by field from an allowlist. Nothing is copied from the
// input object wholesale, so a field the contract does not name (ip, email, user,
// cookies, body, url, headers...) cannot reach the output whatever the caller or a
// browser sends. `validateEvent` is the matching closed check the forwarder runs
// as its last gate.

import { MAX_MESSAGE_LENGTH, computeSignature, normalizeRoute, scrubMessage, scrubStack } from './scrub.js';

export const EVENT_VERSION = 1;
export const ENVIRONMENTS = ['prod', 'preview'];
export const SOURCES = ['server', 'client'];

const PRODUCT = /^[a-z][a-z0-9-]{1,30}$/;
const SHA = /^[0-9a-f]{7,40}$/;
const ERROR_NAME = /^[A-Za-z_$][\w$.]{0,60}$/;
const SIGNATURE = /^[0-9a-f]{16}$/;

/** JSON Schema for the event line pushed to Loki. Keep in step with validateEvent. */
export const EVENT_SCHEMA = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'Alpha Bros error beacon event',
  type: 'object',
  additionalProperties: false,
  required: ['v', 'ts', 'product', 'env', 'release_sha', 'route', 'source', 'name', 'message', 'signature', 'frames'],
  properties: {
    v: { const: EVENT_VERSION },
    ts: { type: 'string', format: 'date-time' },
    product: { type: 'string', pattern: PRODUCT.source },
    env: { enum: ENVIRONMENTS },
    release_sha: { type: 'string', pattern: '^([0-9a-f]{7,40}|unknown)$' },
    route: { type: 'string', maxLength: 120 },
    source: { enum: SOURCES },
    name: { type: 'string', pattern: ERROR_NAME.source },
    message: { type: 'string', maxLength: MAX_MESSAGE_LENGTH },
    signature: { type: 'string', pattern: SIGNATURE.source },
    frames: {
      type: 'array',
      maxItems: 30,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['fn', 'file', 'line', 'col'],
        properties: {
          fn: { type: 'string', maxLength: 100 },
          file: { type: 'string', maxLength: 200 },
          line: { type: 'integer', minimum: 0 },
          col: { type: 'integer', minimum: 0 },
        },
      },
    },
  },
});

/**
 * Validate the fixed, server-side identity of an app's events. Throws on a bad
 * value so a misconfigured app fails at start-up instead of at the first error.
 * @param {{product: string, env: string, releaseSha?: string}} config
 * @returns {{product: string, env: 'prod'|'preview', release_sha: string}}
 */
export function resolveContext(config) {
  if (!config || typeof config !== 'object') throw new TypeError('error-beacon: context is required');
  const { product, env, releaseSha } = config;
  if (typeof product !== 'string' || !PRODUCT.test(product)) {
    throw new TypeError('error-beacon: product must match /^[a-z][a-z0-9-]{1,30}$/');
  }
  if (!ENVIRONMENTS.includes(env)) {
    throw new TypeError(`error-beacon: env must be one of ${ENVIRONMENTS.join(', ')}`);
  }
  const sha = typeof releaseSha === 'string' ? releaseSha.trim().toLowerCase() : '';
  return { product, env, release_sha: SHA.test(sha) ? sha.slice(0, 12) : 'unknown' };
}

function errorName(value) {
  return typeof value === 'string' && ERROR_NAME.test(value) ? value : 'Error';
}

/**
 * Build a clean event.
 * @param {ReturnType<typeof resolveContext>} context
 * @param {{name?: unknown, message?: unknown, stack?: unknown}} error  only these three fields are read
 * @param {{route?: unknown, source?: 'server'|'client', now?: Date}} [meta]
 */
export function buildEvent(context, error, meta = {}) {
  const source = SOURCES.includes(meta.source) ? meta.source : 'server';
  const name = errorName(error?.name);
  const message = scrubMessage(error?.message);
  const frames = scrubStack(error?.stack);
  return {
    v: EVENT_VERSION,
    ts: (meta.now instanceof Date ? meta.now : new Date()).toISOString(),
    product: context.product,
    env: context.env,
    release_sha: context.release_sha,
    route: normalizeRoute(meta.route),
    source,
    name,
    message,
    signature: computeSignature(name, frames, message),
    frames,
  };
}

/**
 * Build an event from anything a thrown value can be (Error, string, object).
 * @param {ReturnType<typeof resolveContext>} context
 * @param {unknown} thrown
 * @param {Parameters<typeof buildEvent>[2]} [meta]
 */
export function buildEventFromThrown(context, thrown, meta) {
  if (thrown && typeof thrown === 'object') {
    return buildEvent(context, { name: thrown.name, message: thrown.message, stack: thrown.stack }, meta);
  }
  return buildEvent(context, { name: 'Error', message: thrown }, meta);
}

/**
 * Turn an untrusted browser payload into an event. Only name, message, stack and
 * route are read; product, env and release always come from the server context
 * and every other field in the body is ignored.
 * @param {ReturnType<typeof resolveContext>} context
 * @param {unknown} raw  parsed JSON body
 * @returns {ReturnType<typeof buildEvent> | null}  null when the body is not an error report
 */
export function eventFromClientPayload(context, raw, now) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const { name, message, stack, route } = /** @type {Record<string, unknown>} */ (raw);
  const stackOk = typeof stack === 'string' || (Array.isArray(stack) && stack.every((line) => typeof line === 'string'));
  if (typeof message !== 'string' && typeof name !== 'string') return null;
  return buildEvent(
    context,
    { name, message, stack: stackOk ? stack : '' },
    { route: typeof route === 'string' ? route : '', source: 'client', now },
  );
}

const EVENT_KEYS = Object.keys(EVENT_SCHEMA.properties).sort().join(',');
const FRAME_KEYS = 'col,file,fn,line';

/**
 * Closed structural check of an event: exact key set, types, bounds. Content
 * scrubbing already happened in buildEvent; this makes sure nothing else is here.
 * @param {unknown} event
 * @returns {boolean}
 */
export function validateEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return false;
  if (Object.keys(event).sort().join(',') !== EVENT_KEYS) return false;
  const e = /** @type {Record<string, any>} */ (event);
  if (e.v !== EVENT_VERSION) return false;
  if (typeof e.ts !== 'string' || Number.isNaN(Date.parse(e.ts))) return false;
  if (typeof e.product !== 'string' || !PRODUCT.test(e.product)) return false;
  if (!ENVIRONMENTS.includes(e.env)) return false;
  if (typeof e.release_sha !== 'string' || !(e.release_sha === 'unknown' || SHA.test(e.release_sha))) return false;
  if (typeof e.route !== 'string' || e.route.length > 120 || /[?#\s]/.test(e.route)) return false;
  if (!SOURCES.includes(e.source)) return false;
  if (typeof e.name !== 'string' || !ERROR_NAME.test(e.name)) return false;
  if (typeof e.message !== 'string' || e.message.length > MAX_MESSAGE_LENGTH) return false;
  if (typeof e.signature !== 'string' || !SIGNATURE.test(e.signature)) return false;
  if (!Array.isArray(e.frames) || e.frames.length > 30) return false;
  return e.frames.every(
    (frame) =>
      frame &&
      typeof frame === 'object' &&
      Object.keys(frame).sort().join(',') === FRAME_KEYS &&
      typeof frame.fn === 'string' &&
      frame.fn.length <= 100 &&
      typeof frame.file === 'string' &&
      frame.file.length <= 200 &&
      Number.isInteger(frame.line) &&
      frame.line >= 0 &&
      Number.isInteger(frame.col) &&
      frame.col >= 0,
  );
}
