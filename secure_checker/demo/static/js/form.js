/**
 * form.js
 * UI controller for the secure form.
 *
 * Responsibilities:
 *  - Attach event listeners (input, blur, submit, reset)
 *  - Run validators on field change and on submit
 *  - Update field states (ok / err) without innerHTML
 *  - Drive the live threat monitor panel
 *  - Collect, sanitize, and display the final payload
 *
 * Security rules enforced here:
 *  - All DOM writes use textContent — never innerHTML with user data
 *  - select values are validated against an allowlist before use
 *  - The file object is never read into a string; only metadata is used
 */

import { sanitizeText, sanitizeFilename, detectThreats, scanAll, generateCSRF, RateLimiter, encodeHTML } from './security.js';
import { validate, scorePassword } from './validators.js';

// ─── State ─────────────────────────────────────────────────────────────────────

let csrfToken = generateCSRF();
let selectedFile = null;
const rateLimiter = new RateLimiter(5, 60_000);

// ─── DOM helpers ───────────────────────────────────────────────────────────────

/** @param {string} id @returns {HTMLElement} */
const $ = id => document.getElementById(id);

/**
 * Set a field's validation state.
 * @param {string}  fieldId
 * @param {'ok'|'err'|''}  state
 * @param {string}  [message]
 */
function setFieldState(fieldId, state, message = '') {
  const el = $(fieldId);
  const errEl = $(`${fieldId}-err`);
  if (el) el.dataset.state = state;
  if (errEl) errEl.textContent = state === 'err' ? message : '';
}

/** Update CSRF display in header, footer, and hidden input */
function refreshCSRFDisplay() {
  const token = csrfToken;
  const input = $('csrfToken');
  if (input) input.value = token;
  const badge = $('csrfBadge');
  if (badge) badge.textContent = 'CSRF token active';
  const footer = $('footerToken');
  if (footer) footer.textContent = token.slice(0, 8) + '…';
}

/** Update the rate-limit badge */
function refreshRateBadge() {
  const badge = $('rateBadge');
  const status = $('rateStatus');
  const count = rateLimiter.count;
  const text = `${count} / 5`;
  if (badge) badge.textContent = `Rate: ${text}`;
  if (status) {
    status.textContent = count >= 5 ? '⚠️ Rate limit reached' : 'OK';
    status.style.color = count >= 5 ? '#e24b4a' : '#2d7a2d';
  }
}

// ─── Threat monitor ────────────────────────────────────────────────────────────

function getTextInputValues() {
  return [
    ...document.querySelectorAll(
      'input[type="text"], input[type="email"], input[type="url"], ' +
      'input[type="tel"], input[type="search"], textarea'
    ),
  ].map(el => el.value);
}

function updateThreatMonitor() {
  const threats = scanAll(getTextInputValues());
  const keys = ['xss', 'sql', 'html', 'cmd', 'path', 'proto'];
  for (const key of keys) {
    const row = $(`threat-${key}`);
    if (row) {
      const status = threats.has(key) ? 'block' : 'ok';
      const indicator = row.querySelector('.threat-status');
      if (indicator) {
        indicator.dataset.status = status;
        indicator.textContent = status === 'block' ? '🔴 BLOCKED' : '✓ OK';
      }
    }
  }
}

// ─── Password strength bar ──────────────────────────────────────────────────────

function updateStrengthBar(value) {
  const fill = $('strengthFill');
  if (!fill) return;
  const { score } = scorePassword(value);
  fill.dataset.score = score;
  fill.style.width = score === 0 ? '0%' : `${score * 25}%`;
}

// ─── Eye-toggle for password fields ────────────────────────────────────────────

function initPasswordToggles() {
  document.querySelectorAll('.toggle-pw').forEach(btn => {
    btn.addEventListener('click', e => {
      e.preventDefault();
      const input = btn.previousElementSibling;
      if (input && (input.type === 'password' || input.type === 'text')) {
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        btn.textContent = isPassword ? '👁️‍🗨️' : '🔒';
      }
    });
  });
}

// ─── File drop zone ─────────────────────────────────────────────────────────────

function initFileDrop() {
  const zone = $('fileDrop');
  const input = $('fileInput');
  const preview = $('filePreview');
  const inner = $('fileDropInner');
  const img = $('previewImg');
  const nameEl = $('fileName');
  const clearBtn = $('clearFile');

  if (!zone || !input) return;

  function handleFile(file) {
    if (!file) return;
    const result = validate('file', file);
    if (!result.valid) {
      setFieldState('fileInput', 'err', result.message);
      selectedFile = null;
      return;
    }
    selectedFile = file;
    setFieldState('fileInput', 'ok');
    
    if (file.type.startsWith('image/')) {
      const url = URL.createObjectURL(file);
      if (img) {
        img.src = url;
        img.onload = () => URL.revokeObjectURL(url);
      }
      if (preview) preview.hidden = false;
    }
    if (nameEl) nameEl.textContent = sanitizeFilename(file.name);
  }

  input.addEventListener('change', () => handleFile(input.files?.[0]));

  // Drag and drop
  zone.addEventListener('dragover', e => {
    e.preventDefault();
    zone.dataset.dragover = '';
  });
  zone.addEventListener('dragleave', () => delete zone.dataset.dragover);
  zone.addEventListener('drop', e => {
    e.preventDefault();
    delete zone.dataset.dragover;
    handleFile(e.dataTransfer?.files?.[0]);
  });

  clearBtn?.addEventListener('click', () => {
    selectedFile = null;
    input.value = '';
    if (preview) preview.hidden = true;
    if (img) img.src = '';
    if (nameEl) nameEl.textContent = '';
    setFieldState('fileInput', '');
  });
}

// ─── Dynamic field listeners ────────────────────────────────────────────────────

function initFieldListeners() {
  // Bio character counter
  const bio = $('bio');
  const bioCount = $('bio-count');
  if (bio && bioCount) {
    bio.addEventListener('input', () => {
      bioCount.textContent = bio.value.length;
    });
  }

  // Range slider readout
  const expRange = $('expRange');
  const expLabel = $('expLabel');
  if (expRange && expLabel) {
    expRange.addEventListener('input', () => {
      expLabel.textContent = expRange.value + ' years';
    });
  }

  // Color picker hex display
  const colorInput = $('accentColor');
  const colorHex = $('colorHex');
  if (colorInput && colorHex) {
    colorInput.addEventListener('input', () => {
      colorHex.textContent = colorInput.value;
    });
  }

  // Password strength bar
  const pw = $('password');
  if (pw) {
    pw.addEventListener('input', () => updateStrengthBar(pw.value));
  }

  // Attach validate-on-input + blur to all data-rule fields
  document.querySelectorAll('[data-rule]').forEach(el => {
    const rule = el.dataset.rule;
    el.addEventListener('input', () => {
      updateThreatMonitor();
      const result = validate(rule, el.value, { password: $('password')?.value });
      setFieldState(el.id, result.valid ? 'ok' : 'err', result.message);
    });
    el.addEventListener('blur', () => {
      const result = validate(rule, el.value, { password: $('password')?.value });
      setFieldState(el.id, result.valid ? 'ok' : 'err', result.message);
    });
  });

  // Textarea doesn't have a type attribute that matches above — add explicitly
  document.querySelectorAll('textarea').forEach(ta => {
    ta.addEventListener('input', updateThreatMonitor);
  });
}

// ─── Full-form validation on submit ─────────────────────────────────────────────

function validateAll() {
  const pw = $('password')?.value ?? '';
  const fields = [
    { id: 'fullName',   rule: 'name',     value: $('fullName')?.value   },
    { id: 'username',   rule: 'username', value: $('username')?.value   },
    { id: 'email',      rule: 'email',    value: $('email')?.value      },
    { id: 'phone',      rule: 'phone',    value: $('phone')?.value      },
    { id: 'password',   rule: 'password', value: pw                     },
    { id: 'confirmPwd', rule: 'confirm',  value: $('confirmPwd')?.value, ctx: { password: pw } },
    { id: 'website',    rule: 'url',      value: $('website')?.value    },
    { id: 'dob',        rule: 'date',     value: $('dob')?.value        },
    { id: 'age',        rule: 'age',      value: $('age')?.value        },
    { id: 'country',    rule: 'select',   value: $('country')?.value    },
    { id: 'bio',        rule: 'bio',      value: $('bio')?.value        },
    { id: 'searchQ',    rule: 'search',   value: $('searchQ')?.value    },
    { id: 'agree',      rule: 'agree',    value: $('agree')?.checked    },
    { id: 'fileInput',  rule: 'file',     value: selectedFile           },
  ];

  let allOk = true;

  for (const f of fields) {
    const result = validate(f.rule, f.value, f.ctx);
    setFieldState(f.id, result.valid ? 'ok' : 'err', result.message);
    if (!result.valid) allOk = false;
  }

  // Radio group (notification) — required
  const notif = document.querySelector('input[name="notif"]:checked');
  const notifErr = $('notif-err');
  if (!notif) {
    if (notifErr) notifErr.textContent = 'Please select a notification preference.';
    allOk = false;
  } else if (notifErr) {
    notifErr.textContent = '';
  }

  return allOk;
}

// ─── Payload builder ────────────────────────────────────────────────────────────

/**
 * Collect all form values, sanitize every string field,
 * validate selects against the allowlist, and return a plain object.
 * Passwords are intentionally omitted from the display payload.
 */
function buildPayload() {
  const ALLOWED_COUNTRY = ['', 'FI', 'SE', 'NO', 'DE', 'US', 'GB', 'JP', 'AU'];
  const ALLOWED_NOTIF = ['email', 'sms', 'push', 'none'];
  
  const country = $('country')?.value ?? '';
  const notif = document.querySelector('input[name="notif"]:checked')?.value ?? '';
  
  return {
    fullName: sanitizeText($('fullName')?.value ?? ''),
    username: sanitizeText($('username')?.value ?? ''),
    email: sanitizeText($('email')?.value ?? ''),
    phone: sanitizeText($('phone')?.value ?? ''),
    website: sanitizeText($('website')?.value ?? ''),
    dateOfBirth: sanitizeText($('dob')?.value ?? ''),
    age: sanitizeText($('age')?.value ?? ''),
    country: ALLOWED_COUNTRY.includes(country) ? country : '',
    bio: sanitizeText($('bio')?.value ?? ''),
    accentColor: /^#[0-9a-fA-F]{6}$/.test($('accentColor')?.value ?? '') ? $('accentColor').value : '#000000',
    experience: sanitizeText($('expRange')?.value ?? ''),
    notifications: ALLOWED_NOTIF.includes(notif) ? notif : '',
    search: sanitizeText($('searchQ')?.value ?? ''),
    file: selectedFile ? {
      name: sanitizeFilename(selectedFile.name),
      type: selectedFile.type,
      size: selectedFile.size
    } : null,
  };
}

// ─── Output panel ───────────────────────────────────────────────────────────────

function renderOutput(payload) {
  const panel = $('outputPanel');
  const grid = $('outputGrid');
  
  while (grid.firstChild) grid.removeChild(grid.firstChild);
  
  for (const [key, value] of Object.entries(payload)) {
    if (value === null || value === '') continue;
    
    const dt = document.createElement('dt');
    dt.textContent = key;
    const dd = document.createElement('dd');
    
    if (typeof value === 'object') {
      dd.textContent = JSON.stringify(value);
    } else {
      dd.textContent = String(value);
    }
    
    grid.appendChild(dt);
    grid.appendChild(dd);
  }
  
  if (panel) panel.hidden = grid.childElementCount === 0;
}

// ─── Form submit ────────────────────────────────────────────────────────────────

function handleSubmit(e) {
  e.preventDefault();
  
  updateThreatMonitor();
  
  if (!validateAll()) {
    const status = $('submitStatus');
    if (status) {
      status.textContent = 'Please fix the errors above.';
      status.style.color = '#e24b4a';
    }
    return;
  }
  
  const rateCheck = rateLimiter.attempt();
  if (!rateCheck.allowed) {
    const status = $('submitStatus');
    if (status) {
      status.textContent = 'Rate limit reached. Try again in a moment.';
      status.style.color = '#e24b4a';
    }
    return;
  }
  
  const payload = buildPayload();
  payload._csrf = csrfToken;
  payload._submittedAt = new Date().toISOString();
  
  renderOutput(payload);
  
  // Rotate CSRF token
  csrfToken = generateCSRF();
  refreshCSRFDisplay();
  refreshRateBadge();
  
  const status = $('submitStatus');
  if (status) {
    status.textContent = 'Submitted successfully!';
    status.style.color = '#2d7a2d';
  }
}

// ─── Reset ──────────────────────────────────────────────────────────────────────

function handleReset() {
  const form = $('secureForm');
  if (form) form.reset();
  
  selectedFile = null;
  csrfToken = generateCSRF();
  refreshCSRFDisplay();
  rateLimiter.reset();
  refreshRateBadge();
  
  document.querySelectorAll('[data-state]').forEach(el => {
    el.dataset.state = '';
  });
  
  document.querySelectorAll('.err-msg').forEach(el => {
    el.textContent = '';
  });
  
  const preview = $('filePreview');
  if (preview) preview.hidden = true;
  
  const img = $('previewImg');
  if (img) img.src = '';
  
  const status = $('submitStatus');
  if (status) status.textContent = '';
  
  const panel = $('outputPanel');
  if (panel) panel.hidden = true;
  
  updateThreatMonitor();
}

// ─── Init ────────────────────────────────────────────────────────────────────────

export function init() {
  initPasswordToggles();
  initFileDrop();
  initFieldListeners();
  refreshCSRFDisplay();
  refreshRateBadge();
  
  const form = $('secureForm');
  if (form) {
    form.addEventListener('submit', handleSubmit);
    form.addEventListener('reset', handleReset);
  }
  
  updateThreatMonitor();
}
