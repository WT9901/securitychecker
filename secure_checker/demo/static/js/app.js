/**
 * app.js — entry point
 *
 * Bootstraps the form after the DOM is ready.
 * Using type="module" in the script tag gives us:
 *   • Strict mode by default
 *   • Module scope (no globals leaked)
 *   • Deferred execution (DOM already parsed when this runs)
 */

import { init } from './form.js';

// DOMContentLoaded fires before images/fonts; module scripts already defer,
// but we guard anyway for clarity.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
