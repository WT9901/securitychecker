/**
 * validators.js
 * Whitelist-based validators for every field in the secure form.
 *
 * Strategy: define the EXACT set of characters / structure that is allowed.
 * Anything outside that set is rejected — the opposite of a blacklist approach,
 * which is always incomplete.
 *
 * Each validator returns { valid: boolean, message: string }.
 */

// ─── Primitive patterns ────────────────────────────────────────────────────────

const RE = {
  /** Human names: letters (including accented), spaces, hyphens, apostrophes */
  name: /^[A-Za-zÀ-ÖØ-öø-ÿ\s'\-]{1,80}$/,

  /** Usernames: alphanumerics + underscore + hyphen, 3-32 chars */
  username: /^[a-zA-Z0-9_\-]{3,32}$/,

  /**
   * Email: intentionally simple — allow reasonable chars either side of @.
   * Full RFC 5322 compliance in a regex is impractical; server-side should
   * verify via send-a-code flow. We reject obvious injection chars.
   */
  email: /^[^\s@<>"'&]{1,64}@[^\s@<>"'&]{1,189}\.[a-zA-Z]{2,}$/,

  /** Phone: digits, spaces, plus, hyphen, parentheses */
  phone: /^[\d\s+\-()]{0,20}$/,

  /**
   * Strong password requirements:
   *  - At least one lowercase letter
   *  - At least one uppercase letter
   *  - At least one digit
   *  - At least one symbol (non-alphanumeric)
   *  - 8–128 characters total
   */
  password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,128}$/,

  /**
   * HTTPS-only URLs. Allows path, query, fragment with a limited safe charset.
   * Blocks javascript:, data:, vbscript: etc.
   */
  url: /^https:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]{1,245}$/,

  /** ISO 8601 date: YYYY-MM-DD */
  date: /^\d{4}-\d{2}-\d{2}$/,

  /**
   * Search queries: alphanumerics, spaces, and a minimal set of
   * punctuation that has no injection potential.
   */
  search: /^[a-zA-Z0-9\s\-_.,!?()]{0,100}$/,

  /** CSS hex color */
  color: /^#[0-9a-fA-F]{6}$/,

  /** Accepted file extensions (matched against sanitized filename) */
  filename: /^[a-zA-Z0-9_\-. ]{1,100}\.(jpg|jpeg|png|webp)$/i,
};

// ─── Individual validators ─────────────────────────────────────────────────────

/**
 * @typedef {{ valid: boolean, message: string }} ValidationResult
 */

/** @param {string} v @returns {ValidationResult} */
export function validateName(v) {
  if (!v) return fail('Name is required.');
  return RE.name.test(v)
    ? ok()
    : fail('Only letters, spaces, hyphens, and apostrophes are allowed.');
}

/** @param {string} v @returns {ValidationResult} */
export function validateUsername(v) {
  if (!v) return fail('Username is required.');
  if (v.length < 3) return fail('Username must be at least 3 characters.');
  if (v.length > 32) return fail('Username must be at most 32 characters.');
  return RE.username.test(v)
    ? ok()
    : fail('Only letters, digits, underscores, and hyphens are allowed.');
}

/** @param {string} v @returns {ValidationResult} */
export function validateEmail(v) {
  if (!v) return fail('Email is required.');
  if (v.length > 254) return fail('Email is too long.');
  return RE.email.test(v)
    ? ok()
    : fail('Enter a valid email address (e.g. user@example.com).');
}

/** @param {string} v @returns {ValidationResult} */
export function validatePhone(v) {
  if (!v) return ok(); // optional
  return RE.phone.test(v)
    ? ok()
    : fail('Only digits, spaces, +, -, and parentheses are allowed.');
}

/** @param {string} v @returns {ValidationResult} */
export function validatePassword(v) {
  if (!v) return fail('Password is required.');
  if (v.length < 8) return fail('Password must be at least 8 characters.');
  if (v.length > 128) return fail('Password must be at most 128 characters.');
  if (!/[a-z]/.test(v)) return fail('Password must contain a lowercase letter.');
  if (!/[A-Z]/.test(v)) return fail('Password must contain an uppercase letter.');
  if (!/\d/.test(v)) return fail('Password must contain a digit.');
  if (!/[^a-zA-Z\d]/.test(v)) return fail('Password must contain a symbol.');
  return ok();
}

/**
 * @param {string} v          Confirm password value
 * @param {string} original   Password value to match against
 * @returns {ValidationResult}
 */
export function validateConfirm(v, original) {
  if (!v) return fail('Please confirm your password.');
  return v === original ? ok() : fail('Passwords do not match.');
}

/** @param {string} v @returns {ValidationResult} */
export function validateURL(v) {
  if (!v) return ok(); // optional
  if (!v.startsWith('https://')) return fail('URL must use HTTPS.');
  return RE.url.test(v)
    ? ok()
    : fail('Enter a valid HTTPS URL (e.g. https://example.com).');
}

/** @param {string} v @returns {ValidationResult} */
export function validateDate(v) {
  if (!v) return ok(); // optional
  if (!RE.date.test(v)) return fail('Date must be in YYYY-MM-DD format.');
  const d = new Date(v);
  if (isNaN(d.getTime())) return fail('Invalid date.');
  if (d > new Date()) return fail('Date cannot be in the future.');
  return ok();
}

/** @param {string} v @returns {ValidationResult} */
export function validateAge(v) {
  if (!v) return ok(); // optional
  const n = Number(v);
  if (!Number.isInteger(n)) return fail('Age must be a whole number.');
  if (n < 13 || n > 120) return fail('Age must be between 13 and 120.');
  return ok();
}

/** @param {string} v @returns {ValidationResult} */
export function validateSelect(v) {
  // Validate against a hardcoded allowlist to prevent forced-browser attacks
  const ALLOWED = ['', 'FI', 'SE', 'NO', 'DE', 'US', 'GB', 'JP', 'AU'];
  return ALLOWED.includes(v) ? ok() : fail('Please select a valid option.');
}

/** @param {string} v @returns {ValidationResult} */
export function validateBio(v) {
  if (v.length > 500) return fail('Bio must be at most 500 characters.');
  return ok();
}

/** @param {string} v @returns {ValidationResult} */
export function validateSearch(v) {
  if (!v) return ok(); // optional
  return RE.search.test(v)
    ? ok()
    : fail('Search may only contain letters, digits, spaces, and - _ . , ! ? ( )');
}

/**
 * @param {File|null} file
 * @returns {ValidationResult}
 */
export function validateFile(file) {
  if (!file) return ok(); // optional
  const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/webp'];
  const MAX_BYTES = 2 * 1024 * 1024; // 2 MB

  if (!ALLOWED_MIME.includes(file.type)) {
    return fail('Only JPEG, PNG, and WebP images are allowed.');
  }
  if (file.size > MAX_BYTES) {
    return fail('File must be smaller than 2 MB.');
  }
  // Sanitize the filename and validate it matches the safe pattern
  const safeName = file.name.replace(/[^a-zA-Z0-9._\- ]/g, '');
  if (!RE.filename.test(safeName)) {
    return fail('Filename contains invalid characters.');
  }
  return ok();
}

/** @param {boolean} checked @returns {ValidationResult} */
export function validateAgreement(checked) {
  return checked ? ok() : fail('You must agree to the terms.');
}

/** @param {string} v @returns {ValidationResult} */
export function validateColor(v) {
  return RE.color.test(v) ? ok() : fail('Enter a valid hex color (e.g. #ff0000).');
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** @returns {ValidationResult} */
function ok() {
  return { valid: true, message: '' };
}

/** @param {string} message @returns {ValidationResult} */
function fail(message) {
  return { valid: false, message };
}

// ─── Password strength scorer ─────────────────────────────────────────────────

/**
 * Returns a score 0–4 indicating password strength.
 * 0 = empty, 1 = very weak, 2 = weak, 3 = good, 4 = strong
 *
 * @param {string} v
 * @returns {{ score: number, label: string }}
 */
export function scorePassword(v) {
  if (!v) return { score: 0, label: 'empty' };
  let score = 0;
  if (v.length >= 8) score++;
  if (/[a-z]/.test(v) && /[A-Z]/.test(v)) score++;
  if (/\d/.test(v)) score++;
  if (/[^a-zA-Z\d]/.test(v)) score++;
  const labels = ['empty', 'very weak', 'weak', 'good', 'strong'];
  return { score, label: labels[score] };
}

// ─── Dispatcher: map rule name → validator ────────────────────────────────────

/**
 * Validate a field by rule name.
 * Called from form.js with (fieldId, ruleKey, extraContext).
 *
 * @param {string} rule
 * @param {string|boolean|File|null} value
 * @param {Record<string,unknown>} [ctx]  Extra context (e.g. { password } for confirm)
 * @returns {ValidationResult}
 */
export function validate(rule, value, ctx = {}) {
  switch (rule) {
    case 'name':     return validateName(value);
    case 'username': return validateUsername(value);
    case 'email':    return validateEmail(value);
    case 'phone':    return validatePhone(value);
    case 'password': return validatePassword(value);
    case 'confirm':  return validateConfirm(value, ctx.password ?? '');
    case 'url':      return validateURL(value);
    case 'date':     return validateDate(value);
    case 'age':      return validateAge(value);
    case 'select':   return validateSelect(value);
    case 'bio':      return validateBio(value);
    case 'search':   return validateSearch(value);
    case 'file':     return validateFile(value);
    case 'agree':    return validateAgreement(value);
    case 'color':    return validateColor(value);
    default:
      return { valid: false, message: `Unknown rule: ${rule}` };
  }
}
