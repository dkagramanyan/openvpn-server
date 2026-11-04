'use strict';
/* Start-up: runs after every other script has been loaded. */

/* ----------------------------------------------------------------- boot */
window.addEventListener('hashchange', () => { state.route = parseRoute(); if (state.user) renderView(); });
applyTheme();
(async () => {
  state.route = parseRoute();
  try { state.user = await api(portalMode ? '/api/portal/me' : '/api/me', { allow401: true }); } catch (_) { state.user = null; }
  render();
})();
