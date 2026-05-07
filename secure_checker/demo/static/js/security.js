/**
 * security.js
 * Core security primitives: sanitization, output encoding, threat detection,
 * CSRF token management, and rate limiting.
 */

// ─── Output encoding ──────────────────────────────────────────────────────────

/**
 * Encode a string so it is safe to insert into an HTML context.
 * Use this whenever to reflect user data into the DOM via innerHTML
 * (prefer textContent where possible — this is a last-resort safety net).
 *
 * @param {unknown} value
 * @returns {string}
 */
export function encodeHTML(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Encode a value for safe insertion into a URL query parameter.
 * @param {unknown} value
 * @returns {string}
 */
export function encodeURL(value) {
  return encodeURIComponent(String(value));
}

// ─── Sanitization ─────────────────────────────────────────────────────────────

/**
 * Strip characters that have no place in plain-text user input:
 * angle brackets, quotes, ampersands, null bytes, and control characters.
 * This is NOT a replacement for output encoding — do both.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function sanitizeText(value) {
  return String(value)
    .replace(/[<>"'&]/g, '')          // remove HTML-special chars
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // strip control chars (keep \t \n \r)
    .trim();
}

/**
 * Sanitize a filename: allow only alphanumerics, spaces, dots, hyphens,
 * and underscores. Reject path separators and other dangerous chars.
 *
 * @param {string} name
 * @returns {string}
 */
export function sanitizeFilename(name) {
  return name.replace(/[^a-zA-Z0-9._\- ]/g, '').trim();
}

// ─── Threat detection patterns ───────────────────────────────────────────────
// Each pattern is a whitelist FAILURE — matching means the input is dangerous.

const PATTERNS = {
  /** Cross-site scripting vectors */
  xss: /(<script[\s>]|<\/script>|javascript\s*:|on\w+\s*=|<iframe|<object|<embed|<svg[\s>]|<img[^>]+on\w+\s*=|eval\s*\(|expression\s*\(|document\s*\.|window\s*\.|localStorage|sessionStorage|alert\s*\(|confirm\s*\(|prompt\s*\(|setTimeout|setInterval)/i,

  /** SQL injection vectors */
  sql: /('|"|--|#|\/\*|\*\/|;\s*$|xp_\w|UNION\s+(?:ALL\s+)?SELECT|(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC(?:UTE)?|CALL)\s+\w|SLEEP\s*\(|BENCHMARK\s*\(|LOAD_FILE\s*\(|INTO\s+(?:OUT|DUMP)FILE|INFORMATION_SCHEMA|SYS\.TABLES)/i,

  /** Raw HTML tag injection (not caught by XSS pattern) */
  html: /<\/?[a-z][\s\S]*?>/i,

  /** Shell/command injection metacharacters */
  cmd: /[;&|`$\\]|\$\(|\$\{|\x00|%00/,

  /** Directory traversal sequences */
  path: /(?:\.{2,}[/\\]|[/\\]\.{2,}|\/etc\/|\/proc\/|\/sys\/|\/dev\/|\\windows\\|\\system32\\)/i,

  /** Prototype pollution keys */
  proto: /(?:^|\[)(__|constructor|prototype)(?:\]|$)/i,
};

/**
 * Test a string against all threat patterns.
 * Returns a Set of threat keys that matched, or an empty Set if clean.
 *
 * @param {string} value
 * @returns {Set<string>}
 */
export function detectThreats(value) {
  const str = String(value);
  const found = new Set();
  for (const [key, pattern] of Object.entries(PATTERNS)) {
    if (pattern.test(str)) found.add(key);
  }
  return found;
}

/**
 * Scan multiple values (e.g. all form fields) and return a merged Set.
 *
 * @param {string[]} values
 * @returns {Set<string>}
 */
export function scanAll(values) {
  const merged = new Set();
  for (const v of values) {
    for (const t of detectThreats(v)) merged.add(t);
  }
  return merged;
}

// ─── CSRF token ───────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically random CSRF token (24 chars, URL-safe base64).
 * Uses the Web Crypto API — never Math.random().
 *
 * @returns {string}
 */
export function generateCSRF() {
  const bytes = new Uint8Array(18); // 18 bytes → 24 base64 chars
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────

/**
 * Sliding-window rate limiter stored in memory.
 * Tracks timestamps of recent submissions and rejects when over the limit.
 */
export class RateLimiter {
  /**
   * @param {number} limit   Max allowed requests in the window
   * @param {number} windowMs Window size in milliseconds
   */
  constructor(limit = 5, windowMs = 60_000) {
    this.limit = limit;
    this.windowMs = windowMs;
    this._log = [];
  }

  /** Prune entries outside the current window */
  _prune() {
    const cutoff = Date.now() - this.windowMs;
    this._log = this._log.filter(t => t > cutoff);
  }

  /** Current count within the window */
  get count() {
    this._prune();
    return this._log.length;
  }

  /**
   * Attempt to record a new request.
   * @returns {{ allowed: boolean; count: number; remaining: number }}
   */
  attempt() {
    this._prune();
    if (this._log.length >= this.limit) {
      return { allowed: false, count: this._log.length, remaining: 0 };
    }
    this._log.push(Date.now());
    const remaining = this.limit - this._log.length;
    return { allowed: true, count: this._log.length, remaining };
  }

  /** Reset all counters (e.g., after a successful test) */
  reset() {
    this._log = [];
  }
}
