// loki.js — push an event to the studio Loki (ADR-0058 §1/§3).
//
// Wire shape: POST {lokiUrl} with the CF Access service-token headers, exactly as
// claw-relay does for loki-push.alphabros.eu. Labels are the bounded set
// {service, product, env, release_sha, route, signature}; the full event goes in
// the JSON log line, where Grafana reads it with `| json`.
//
// push() never throws: an unreachable Loki must not turn an error report into a
// second error in the app.

import { LabelBudget, OVERFLOW_LABEL } from './limits.js';
import { validateEvent } from './event.js';

export const SERVICE_LABEL = 'error-beacon';
const DEFAULT_TIMEOUT_MS = 3000;

function labelValue(value, max) {
  const text = String(value ?? '').replace(/[^\w./~:\-[\](){}*]/g, '_').slice(0, max);
  return text || 'unknown';
}

/**
 * Loki push body for one event.
 * @param {{ts: string, product: string, env: string, release_sha: string, route: string, signature: string}} event
 * @param {{route?: string, signature?: string}} [labelOverrides]  budgeted label values
 */
export function buildPushBody(event, labelOverrides = {}) {
  const stream = {
    service: SERVICE_LABEL,
    product: event.product,
    env: event.env,
    release_sha: event.release_sha,
    route: labelValue(labelOverrides.route ?? event.route, 120),
    signature: labelValue(labelOverrides.signature ?? event.signature, 16),
  };
  const ns = `${Date.parse(event.ts)}000000`;
  return JSON.stringify({ streams: [{ stream, values: [[ns, JSON.stringify(event)]] }] });
}

/**
 * @param {{
 *   lokiUrl?: string,
 *   accessClientId?: string,
 *   accessClientSecret?: string,
 *   fetch?: typeof fetch,
 *   timeoutMs?: number,
 *   maxRoutes?: number,
 *   maxSignatures?: number,
 *   onError?: (reason: string) => void,
 * }} config
 */
export function createLokiForwarder(config = {}) {
  const {
    lokiUrl,
    accessClientId,
    accessClientSecret,
    fetch: fetchImpl = globalThis.fetch,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxRoutes = 200,
    maxSignatures = 500,
    onError = (reason) => console.error(JSON.stringify({ service: SERVICE_LABEL, level: 'error', msg: reason })),
  } = config;
  const routes = new LabelBudget(maxRoutes);
  const signatures = new LabelBudget(maxSignatures);

  /**
   * @returns {Promise<{ok: boolean, status?: number, reason?: string}>}
   */
  async function push(event) {
    if (!validateEvent(event)) {
      onError('error-beacon: dropped an event that does not match the payload schema');
      return { ok: false, reason: 'invalid-event' };
    }
    if (!lokiUrl || !accessClientId || !accessClientSecret) {
      onError('error-beacon: push skipped, Loki URL or CF Access credentials are not configured');
      return { ok: false, reason: 'not-configured' };
    }
    const body = buildPushBody(event, {
      route: routes.admit(event.route),
      signature: signatures.admit(event.signature),
    });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(lokiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'CF-Access-Client-Id': accessClientId,
          'CF-Access-Client-Secret': accessClientSecret,
        },
        body,
        signal: controller.signal,
      });
      if (!response.ok) {
        onError(`error-beacon: Loki answered ${response.status}`);
        return { ok: false, status: response.status, reason: 'loki-rejected' };
      }
      return { ok: true, status: response.status };
    } catch (error) {
      onError(`error-beacon: push failed (${error instanceof Error && error.name === 'AbortError' ? 'timeout' : 'network'})`);
      return { ok: false, reason: 'network' };
    } finally {
      clearTimeout(timer);
    }
  }

  return { push };
}

export { OVERFLOW_LABEL };
