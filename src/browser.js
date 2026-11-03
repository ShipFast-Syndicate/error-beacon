// browser.js — client capture (ADR-0058 §4). Registers window.onerror and
// unhandledrejection and posts a minimal report to the app's *own* /api/_errors,
// which scrubs again and forwards. The browser never sees the Loki URL or any
// credential.
//
// Only name, message, stack and route are sent: no URL query, no referrer, no
// user agent, no cookies, no DOM. The message and stack are scrubbed here as well
// so that nothing identifying even leaves the page.

import { normalizeRoute, scrubMessage, scrubStack } from './scrub.js';

const DEFAULT_ENDPOINT = '/api/_errors';
const DEFAULT_MAX_REPORTS = 5;

/**
 * @param {{
 *   endpoint?: string,
 *   getRoute?: () => string,
 *   maxReports?: number,
 *   target?: any,
 * }} [options]  `getRoute` should return the framework's route template when it has one
 * @returns {() => void}  uninstall function
 */
export function installBrowserBeacon(options = {}) {
  const { endpoint = DEFAULT_ENDPOINT, maxReports = DEFAULT_MAX_REPORTS } = options;
  const target = options.target ?? globalThis;
  const getRoute = options.getRoute ?? (() => target.location?.pathname ?? '');
  let sent = 0;
  const seen = new Set();

  function send(thrown) {
    if (sent >= maxReports) return;
    const error = thrown && typeof thrown === 'object' ? thrown : { message: thrown };
    const name = typeof error.name === 'string' ? error.name : 'Error';
    const message = scrubMessage(error.message);
    const frames = scrubStack(error.stack);
    const stack = frames.map((f) => `at ${f.fn || '<anonymous>'} (${f.file}:${f.line}:${f.col})`);
    const key = `${name}|${message}|${stack[0] ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    sent += 1;
    let route = '';
    try {
      route = String(getRoute() ?? '');
    } catch {
      // A route we cannot read is reported as 'unknown'.
    }
    const body = JSON.stringify({ name, message, stack, route: normalizeRoute(route) });
    try {
      const nav = target.navigator;
      if (nav && typeof nav.sendBeacon === 'function' && nav.sendBeacon(endpoint, new Blob([body], { type: 'text/plain' }))) return;
      if (typeof target.fetch === 'function') {
        target
          .fetch(endpoint, { method: 'POST', body, keepalive: true, credentials: 'omit', headers: { 'Content-Type': 'text/plain' } })
          .catch(() => {});
      }
    } catch {
      // Reporting must never throw into the page.
    }
  }

  const onError = (event) => send(event?.error ?? { name: 'Error', message: event?.message });
  const onRejection = (event) => send(event?.reason ?? { name: 'UnhandledRejection', message: 'unhandled promise rejection' });
  target.addEventListener('error', onError);
  target.addEventListener('unhandledrejection', onRejection);
  return () => {
    target.removeEventListener('error', onError);
    target.removeEventListener('unhandledrejection', onRejection);
  };
}
