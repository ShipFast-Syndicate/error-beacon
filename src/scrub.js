// scrub.js — the one PII scrub for the error beacon (ADR-0058 §2).
//
// Everything that leaves an app process goes through these functions. They are
// pure, dependency-free and run unchanged in Node, Workers, Vercel Edge and the
// browser. The rule is allowlist-first: a stack becomes a list of
// {fn, file, line, col} frames and nothing else (the first stack line carries the
// error message, so it is dropped and the message is scrubbed on its own); a
// message is reduced to a template with every value-shaped token redacted.

export const MAX_MESSAGE_LENGTH = 300;
export const MAX_FRAMES = 30;
export const MAX_FRAME_FIELD_LENGTH = 200;
export const MAX_ROUTE_LENGTH = 120;

// Regexes below only ever run on input truncated to this length, which bounds the
// work an attacker can make a scrub of an unauthenticated payload cost.
const MAX_SCRUB_INPUT = 2000;

const EMAIL = /[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g;
const URL_LIKE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"`)<>]+/gi;
const RELATIVE_QUERY = /\?[\w%.~[\]-]+=[^\s'"`)<>]*/g;
const BEARER = /\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const SENSITIVE_KV =
  /\b([\w-]*(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|session[_-]?id|credential)[\w-]*)(["']?\s*[:=]\s*["']?)[^\s"',;&]+/gi;
const JWT = /\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*/g;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const IPV6 = /\b[0-9a-f]{1,4}(?::{1,2}[0-9a-f]{1,4}){2,7}\b|\b[0-9a-f]{1,4}::[0-9a-f]{0,4}\b/gi;
const LONG_HEX = /\b[0-9a-f]{16,}\b/gi;
const SHORT_HEX = /\b(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{8,15}\b/gi;
const OPAQUE_TOKEN = /\b(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{24,}\b/g;
const QUOTED = /(["'`])((?:(?!\1)[^\\\n]|\\.){0,200})\1/g;
const DIGITS = /\d+/g;
const HOME_DIR = /([/\\](?:home|Users)[/\\])[^/\\\s:)'"]+/gi;
const WINDOWS_HOME = /([A-Za-z]:[/\\]Users[/\\])[^/\\\s:)'"]+/gi;
// JS engines quote property names when a value is undefined; they are code, not data.
const CODE_QUOTE_CONTEXT = /(?:reading|setting|deleting|property|properties|export|module)\s?$/i;
const IDENTIFIER = /^[A-Za-z_$][\w$]{0,40}$/;

function asString(value) {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return '';
  try {
    return String(value);
  } catch {
    return '';
  }
}

export function scrubPath(path) {
  return asString(path).replace(WINDOWS_HOME, '$1[user]').replace(HOME_DIR, '$1[user]');
}

function scrubUrl(match) {
  let url = match;
  const at = url.indexOf('@');
  const slashes = url.indexOf('//');
  const pathStart = url.indexOf('/', slashes + 2);
  if (at !== -1 && slashes !== -1 && (pathStart === -1 || at < pathStart)) {
    url = url.slice(0, slashes + 2) + url.slice(at + 1);
  }
  const cut = url.search(/[?#]/);
  if (cut === -1) return url;
  return `${url.slice(0, cut)}${url[cut] === '?' ? '?[redacted]' : '#[redacted]'}`;
}

/**
 * Reduce an error message to a template: emails, URL queries, tokens, ids, IPs,
 * quoted values and every number are replaced by placeholders.
 * @param {unknown} input
 * @param {{maxLength?: number}} [options]
 * @returns {string}
 */
export function scrubMessage(input, { maxLength = MAX_MESSAGE_LENGTH } = {}) {
  let text = asString(input).slice(0, MAX_SCRUB_INPUT);
  // eslint-disable-next-line no-control-regex
  text = text.replace(/[\u0000-\u001f\u007f]+/g, ' ');

  text = text
    .replace(URL_LIKE, scrubUrl)
    .replace(EMAIL, '[email]')
    .replace(RELATIVE_QUERY, '?[redacted]')
    .replace(BEARER, '$1 [token]')
    .replace(SENSITIVE_KV, '$1$2[redacted]')
    .replace(JWT, '[token]')
    .replace(UUID, '[uuid]')
    .replace(IPV4, '[ip]')
    .replace(IPV6, '[ip]')
    .replace(LONG_HEX, '[hex]')
    .replace(SHORT_HEX, '[hex]')
    .replace(OPAQUE_TOKEN, '[token]');

  text = scrubPath(text).replace(QUOTED, (whole, quote, body, offset, input) => {
    const before = input.slice(Math.max(0, offset - 16), offset);
    if (IDENTIFIER.test(body) && CODE_QUOTE_CONTEXT.test(before)) return whole;
    return `${quote}[str]${quote}`;
  });

  text = text.replace(DIGITS, '[n]').replace(/\s+/g, ' ').trim();
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

const V8_FRAME = /^\s*at\s+(?:(.+?)\s+\()?(.+?):(\d+):(\d+)\)?\s*$/;
const GECKO_FRAME = /^\s*(.*?)@(.+?):(\d+):(\d+)\s*$/;

function cleanFile(raw) {
  let file = asString(raw).trim();
  if (/eval at /.test(file)) return '[eval]';
  file = file.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '');
  const cut = file.search(/[?#]/);
  if (cut !== -1) file = file.slice(0, cut);
  file = scrubPath(file);
  return file.length > MAX_FRAME_FIELD_LENGTH ? file.slice(0, MAX_FRAME_FIELD_LENGTH) : file;
}

function cleanFunctionName(raw) {
  const fn = asString(raw).trim();
  // Function names are code identifiers; anything else (a template, a URL, a value) is dropped.
  return /^[\w$<>.\s[\]#:-]{1,100}$/.test(fn) ? fn : '';
}

/**
 * Parse a stack (string or array of lines) into scrubbed frames. The leading
 * "Error: message" line never matches a frame pattern, so it is dropped.
 * @param {unknown} stack
 * @returns {{fn: string, file: string, line: number, col: number}[]}
 */
export function scrubStack(stack) {
  const lines = Array.isArray(stack)
    ? stack.map(asString)
    : asString(stack).slice(0, 8000).split('\n');
  const frames = [];
  for (const line of lines) {
    if (frames.length >= MAX_FRAMES) break;
    const text = line.slice(0, 600);
    const match = V8_FRAME.exec(text) ?? GECKO_FRAME.exec(text);
    if (!match) continue;
    const [, fn, file, lineNo, colNo] = match;
    frames.push({
      fn: cleanFunctionName(fn),
      file: cleanFile(file),
      line: Math.min(Number(lineNo), 10_000_000),
      col: Math.min(Number(colNo), 10_000_000),
    });
  }
  return frames;
}

const ID_SEGMENT = [
  /^\d+$/,
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  /^[0-9a-f]{8,}$/i,
  /@/,
  /^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_-]{6,}$/,
];
// Framework route templates: [id], [...rest], :id, {id}, (group), * — kept verbatim.
const TEMPLATE_SEGMENT = /^(?:\[{1,2}\.{0,3}[\w-]+\]{1,2}|:[\w-]+\*?|\{[\w-]+\}|\([\w-]+\)|\*{1,2})$/;

/**
 * Route template for the `route` label: no query string, no fragment, and any
 * segment that looks like an id replaced by `:id`. Callers should pass the
 * framework's template (SvelteKit `event.route.id`, Next `routePath`, Astro
 * `routePattern`); this is the defence in depth for when only a raw path exists.
 * @param {unknown} input
 * @returns {string}
 */
export function normalizeRoute(input) {
  let route = asString(input).slice(0, 500).trim();
  route = route.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '');
  const cut = route.search(/[?#]/);
  if (cut !== -1) route = route.slice(0, cut);
  if (!route) return 'unknown';
  const segments = route
    .split('/')
    .filter(Boolean)
    .slice(0, 8)
    .map((segment) => {
      if (TEMPLATE_SEGMENT.test(segment)) return segment;
      let decoded = segment;
      try {
        decoded = decodeURIComponent(segment);
      } catch {
        // A malformed escape stays as-is and is then caught by the id patterns or the charset filter.
      }
      return ID_SEGMENT.some((pattern) => pattern.test(decoded)) ? ':id' : segment;
    });
  const normalized = `/${segments.join('/')}`.replace(/[^\w./~:\-[\](){}*]/g, '_');
  return normalized.length > MAX_ROUTE_LENGTH ? normalized.slice(0, MAX_ROUTE_LENGTH) : normalized;
}

const UNMATCHED_ROUTE = '[unmatched]';
const PARAM_SEGMENT = /^(?:\[[^\]/]+\]|\[\[[^\]/]+\]\]|:[\w-]+|\{[\w-]+\})$/;
const REST_SEGMENT = /^(?:\[\.{3}[\w-]+\]|\[\[\.{3}[\w-]+\]\]|:[\w-]+\*|\*{1,2})$/;

// Number of wildcard segments if `parts` fits the template, else null. A rest
// segment swallows whatever remains, so it must come last.
function templateParams(tparts, parts) {
  let params = 0;
  for (let i = 0; i < tparts.length; i += 1) {
    const t = tparts[i];
    if (REST_SEGMENT.test(t)) return params + 1;
    if (i >= parts.length) return null;
    if (PARAM_SEGMENT.test(t)) params += 1;
    else if (t !== parts[i]) return null;
  }
  return tparts.length === parts.length ? params : null;
}

/**
 * Map a concrete path onto one of the app's own route templates. A raw browser
 * pathname can carry a slug or a username (`/u/jean`); the template (`/u/[name]`)
 * cannot. A path that matches no template becomes `[unmatched]`, which also keeps
 * the `route` label from being widened by whoever calls the public endpoint.
 * @param {unknown} input
 * @param {readonly string[]} templates
 * @returns {string}
 */
export function matchRoute(input, templates) {
  let path = asString(input).slice(0, 500).trim().replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '');
  const cut = path.search(/[?#]/);
  if (cut !== -1) path = path.slice(0, cut);
  const parts = path.split('/').filter(Boolean);
  let best = null;
  for (const template of templates) {
    const tparts = asString(template)
      .split('/')
      .filter((segment) => segment && !/^\([\w-]+\)$/.test(segment));
    const params = templateParams(tparts, parts);
    if (params !== null && (!best || params < best.params)) best = { template, params };
  }
  if (!best) return UNMATCHED_ROUTE;
  const label = asString(best.template).replace(/[^\w./~:\-[\](){}*]/g, '_');
  return label.length > MAX_ROUTE_LENGTH ? label.slice(0, MAX_ROUTE_LENGTH) : label;
}

function hashyPart(part) {
  if (/^[0-9a-f]{10,}$/i.test(part)) return true;
  if (part.length !== 8 || !/^[A-Za-z0-9_-]+$/.test(part)) return false;
  return /\d/.test(part) || /[A-Z]/.test(part.slice(1)) || /[_-]/.test(part);
}

/**
 * Strip build hashes from a bundle path (`chunks/DRaQ1Mha.js`, `page-5d1c3f8a2b.js`)
 * so a signature survives a redeploy that renames every chunk.
 * @param {string} file
 */
export function normalizeFileForSignature(file) {
  return asString(file)
    .split('/')
    .map((part) =>
      part
        .split('.')
        .map((piece) => {
          if (hashyPart(piece)) return '[hash]';
          const dash = piece.lastIndexOf('-');
          if (dash > 0 && hashyPart(piece.slice(dash + 1)) && piece.slice(dash + 1).length >= 8) {
            return `${piece.slice(0, dash)}-[hash]`;
          }
          return piece;
        })
        .join('.'),
    )
    .join('/');
}

function fnv1a64(text) {
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const bytes = new TextEncoder().encode(text);
  for (const byte of bytes) {
    hash ^= BigInt(byte);
    hash = (hash * prime) & 0xffffffffffffffffn;
  }
  return hash.toString(16).padStart(16, '0');
}

const SIGNATURE_FRAMES = 3;
const NOISE_FRAME = /^(?:node:|\[eval\]|<anonymous>)|\/node_modules\//;

/**
 * Stable grouping key: hash of the error type plus the normalized top frames
 * (function + hash-stripped file, never line/col, which shift on every release).
 * Without frames it falls back to the scrubbed message template. This is a
 * grouping hash, not a security primitive.
 * @param {string} name
 * @param {{fn: string, file: string}[]} frames
 * @param {string} messageTemplate
 */
export function computeSignature(name, frames, messageTemplate) {
  const usable = frames.filter((frame) => frame.file && !NOISE_FRAME.test(frame.file));
  const top = (usable.length ? usable : frames).slice(0, SIGNATURE_FRAMES);
  const parts = top.length
    ? top.map((frame) => `${frame.fn}|${normalizeFileForSignature(frame.file)}`)
    : [messageTemplate];
  return fnv1a64([name, ...parts].join('\n'));
}
