// limits.js — in-process flood control. The public endpoint is unauthenticated, so
// everything here is keyed on event content, never on who sent it: no IP is read,
// hashed or stored anywhere in the beacon.

export class TokenBucket {
  /**
   * @param {{capacity: number, refillPerSec: number, now?: () => number}} options
   */
  constructor({ capacity, refillPerSec, now = Date.now }) {
    this.capacity = capacity;
    this.refillPerSec = refillPerSec;
    this.now = now;
    this.tokens = capacity;
    this.updated = now();
  }

  /** @returns {boolean} true when a token was available */
  take() {
    const t = this.now();
    this.tokens = Math.min(this.capacity, this.tokens + ((t - this.updated) / 1000) * this.refillPerSec);
    this.updated = t;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
}

/** Per-key buckets, bounded so a stream of distinct keys cannot grow memory. */
export class KeyedLimiter {
  constructor({ capacity, refillPerSec, maxKeys = 1000, now = Date.now }) {
    this.options = { capacity, refillPerSec, now };
    this.maxKeys = maxKeys;
    this.buckets = new Map();
  }

  take(key) {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      if (this.buckets.size >= this.maxKeys) this.buckets.clear();
      bucket = new TokenBucket(this.options);
      this.buckets.set(key, bucket);
    }
    return bucket.take();
  }
}

export const OVERFLOW_LABEL = '[other]';

/**
 * Bounds how many distinct values a Loki label can take in this process. Loki
 * indexes every label combination as a stream and has a global stream cap shared
 * with every other log source on ops-monitor, so a label an outsider can steer
 * must not be allowed to grow without limit.
 */
export class LabelBudget {
  constructor(max) {
    this.max = max;
    this.seen = new Set();
  }

  admit(value) {
    if (this.seen.has(value)) return value;
    if (this.seen.size >= this.max) return OVERFLOW_LABEL;
    this.seen.add(value);
    return value;
  }
}
