'use strict';
/* OpenVPN UI: shared helpers, API client, dialogs, app shell, charts and sign-in. No dependencies. */

/* ---------------------------------------------------------------- utils */
const TZ = -new Date().getTimezoneOffset() * 60;
const $ = (sel, root) => (root || document).querySelector(sel);

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k === 'style') el.style.cssText = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k in el && k !== 'list' && typeof v !== 'string') el[k] = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function setChildren(el, ...children) { el.replaceChildren(); return append(el, children); }
function svg(tag, attrs, ...children) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) el.setAttribute(k, v);
  for (const c of children.flat(Infinity)) if (c) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
const ICONS = {
  dash: 'M3 12h6V3H3zM15 21h6V11h-6zM3 21h6v-6H3zM15 8h6V3h-6z',
  users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8',
  sessions: 'M12 8v4l3 3M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z',
  server: 'M20 4H4a1 1 0 0 0-1 1v4a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1zM20 14H4a1 1 0 0 0-1 1v4a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1v-4a1 1 0 0 0-1-1zM6 7h.01M6 17h.01',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
  download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3',
  plus: 'M12 5v14M5 12h14',
  refresh: 'M23 4v6h-6M1 20v-6h6M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15',
  warn: 'M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01',
  back: 'M19 12H5M12 19l-7-7 7-7',
  power: 'M18.4 6.6a9 9 0 1 1-12.8 0M12 2v10',
  lock: 'M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2zM7 11V7a5 5 0 0 1 10 0v4',
  x: 'M18 6 6 18M6 6l12 12',
  sun: 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
};
const icon = name => svg('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true' }, svg('path', { d: ICONS[name] }));
const portalMode = location.pathname.replace(/\/$/, '') === '/portal';

const UNITS = ['B', 'kB', 'MB', 'GB', 'TB', 'PB'];
function fmtBytes(n, digits) {
  n = Number(n) || 0;
  let i = 0;
  while (n >= 1000 && i < UNITS.length - 1) { n /= 1000; i++; }
  const d = digits !== undefined ? digits : (i === 0 ? 0 : n < 10 ? 2 : n < 100 ? 1 : 0);
  return n.toFixed(d) + ' ' + UNITS[i];
}
function fmtBits(bps) {
  bps = (Number(bps) || 0) * 8;
  const u = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s'];
  let i = 0;
  while (bps >= 1000 && i < u.length - 1) { bps /= 1000; i++; }
  return bps.toFixed(i === 0 ? 0 : bps < 10 ? 2 : bps < 100 ? 1 : 0) + ' ' + u[i];
}
function shortVer(v) { return (v || '').split(' ').slice(0, 2).join(' '); }
function fmtNum(n) { return (Number(n) || 0).toLocaleString(); }
function fmtDur(sec) {
  sec = Math.max(0, Math.round(Number(sec) || 0));
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  if (d) return `${d}d ${hh}h`;
  if (hh) return `${hh}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}
function fmtAgo(ts) {
  if (!ts) return 'never';
  const diff = Math.max(0, Date.now() / 1000 - ts);
  if (diff < 45) return 'just now';
  if (diff < 3600) return `${Math.round(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)} h ago`;
  if (diff < 86400 * 14) return `${Math.round(diff / 86400)} d ago`;
  return fmtDate(ts);
}
function fmtDate(ts) { return ts ? new Date(ts * 1000).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' }) : '—'; }
function fmtDateTime(ts) { return ts ? new Date(ts * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '—'; }
function fmtTime(ts) { return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
function fmtDays(days) {
  if (days === null || days === undefined) return '';
  if (days < 0) return 'expired';
  if (days === 0) return 'today';
  if (days < 60) return `${days} d`;
  if (days < 730) return `${Math.round(days / 30)} mo`;
  return `${(days / 365).toFixed(1)} y`;
}

// "udp4:203.0.113.5:1194" -> ["203.0.113.5:1194", "udp"]; addresses without a protocol stay as they are.
function addrParts(a) { const m = /^(udp|tcp)[^:]*:(.*)$/.exec(a || ''); return m ? [m[2], m[1]] : [a || '', null]; }
function fromCell(s) {
  const [addr, proto] = addrParts(s.real_address), via = s.proto || proto;
  return h('td', { class: 'mono small' }, addr || '—', via ? h('span', { class: 'muted', title: via === 'tcp' ? 'Over the TCP fallback' : 'Over UDP' }, ' ' + via) : null);
}
const PLATFORMS = { ios: 'iOS', android: 'Android', win: 'Windows', mac: 'macOS', linux: 'Linux' };
function deviceCell(s) {
  if (!s.platform && !s.client_ver) return h('td', { class: 'muted' }, '—');
  const v = s.client_ver || '', m = /connect\.\w+_([\d.]+)/.exec(v);
  return h('td', { class: 'small', title: v }, PLATFORMS[s.platform] || s.platform || '', h('span', { class: 'muted' }, ' ' + (m ? 'Connect ' + m[1] : v.replace(/_/g, ' '))));
}

/* --------------------------------------------------------------- toasts */
function toast(msg, kind) {
  const el = h('div', { class: 'toast ' + (kind || '') }, msg);
  $('#toasts').append(el);
  setTimeout(() => el.remove(), kind === 'err' ? 7000 : 4000);
}

/* ------------------------------------------------------------------ api */
async function responseError(response, fallback = 'Please try again') {
  let data;
  const content = await response.text();
  if ((response.headers.get('content-type') || '').includes('application/json')) {
    try { data = JSON.parse(content); } catch (_) {}
  }
  const messages = {
    401: 'Your session has expired. Sign in again.',
    403: 'The gateway blocked this request. Connect to your approved Wi-Fi, VPN or relay and try again. If you are already connected, contact your administrator.',
    404: 'This feature is not available on the server yet. Ask your administrator to update the application and gateway.',
    429: 'Too many attempts. Wait a moment and try again.',
    502: 'The service is restarting or unavailable. Wait a moment and retry.',
    503: 'The service is temporarily unavailable. Please retry or contact your administrator.',
  };
  let message = data?.detail || messages[response.status] || fallback;
  if (Array.isArray(message)) message = message.map(item => `${(item.loc || []).slice(1).join('.')}: ${item.msg}`).join('; ');
  const error = new Error(String(message));
  error.status = response.status;
  error.fields = data?.fields || [];
  return error;
}
async function api(path, opts = {}) {
  const init = { method: opts.method || 'GET', credentials: 'same-origin', headers: { 'X-Requested-With': 'fetch' } };
  if (opts.body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(opts.body); }
  let res;
  try { res = await fetch(path, init); } catch (_) { throw new Error('Cannot reach the server. Check your connection and try again.'); }
  if (res.status === 401 && !opts.allow401) { signOut(); throw new Error('Your session has expired. Sign in again.'); }
  if (!res.ok) throw await responseError(res);
  const content = await res.text();
  if (!(res.headers.get('content-type') || '').includes('application/json')) return content;
  try { return JSON.parse(content); }
  catch (_) { throw new Error('The server returned an unreadable response. Refresh the page and retry.'); }
}
async function withToast(promise, okMsg) {
  try { const r = await promise; if (okMsg) toast(okMsg, 'ok'); return r; }
  catch (e) { toast(e.message, 'err'); throw e; }
}

/* -------------------------------------------------------------- dialogs */
function dialog({ title, body, buttons, wide }) {
  return new Promise(resolve => {
    const dlg = h('dialog', { class: 'modal', style: wide ? 'width:min(760px,calc(100vw - 32px))' : '' });
    const close = v => { dlg.close(); dlg.remove(); resolve(v); };
    dlg.append(
      h('div', { class: 'm-h' }, h('h2', null, title), h('button', { class: 'btn ghost sm', onClick: () => close(null), 'aria-label': 'Close' }, icon('x'))),
      h('div', { class: 'm-b' }, body),
      h('div', { class: 'm-f' }, ...(buttons || []).map(b =>
        h('button', { class: 'btn ' + (b.cls || ''), onClick: async () => { const v = b.value !== undefined ? b.value : (b.onClick ? await b.onClick() : true); if (v !== false) close(v); } }, b.label)))
    );
    dlg.addEventListener('cancel', e => { e.preventDefault(); close(null); });
    document.body.append(dlg);
    dlg.showModal();
  });
}
function confirmDialog(title, text, okLabel, danger) {
  return dialog({ title, body: h('p', { style: 'margin:0' }, text), buttons: [
    { label: 'Cancel', value: null }, { label: okLabel || 'Confirm', cls: danger ? 'danger' : 'primary', value: true }] });
}
let fieldNumber = 0;
function field(label, input, help) {
  if (!input.id) input.id = 'field-' + (++fieldNumber);
  return h('div', { class: 'field' }, h('label', { for: input.id }, label), input, help ? h('div', { class: 'help' }, help) : null);
}

/* ---------------------------------------------------------------- state */
const state = {
  user: null,
  route: { name: 'dashboard', param: null },
  range: localStorage.getItem('range') || 'today',
  live: null,
  stream: null,
  view: null,
  timers: [],
};
const RANGES = [['today', 'Today'], ['24h', '24 h'], ['7d', '7 days'], ['30d', '30 days'], ['90d', '90 days'], ['all', 'All']];

function applyTheme() {
  const t = localStorage.getItem('theme') || 'system';
  if (t === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.dataset.theme = t;
}
function parseRoute() {
  const parts = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  return { name: parts[0] || 'dashboard', param: parts[1] ? decodeURIComponent(parts[1]) : null };
}
function go(hash) { location.hash = hash; }
function clearTimers() { state.timers.forEach(clearInterval); state.timers = []; }
function every(ms, fn) { state.timers.push(setInterval(fn, ms)); }

/* --------------------------------------------------------------- stream */
function connectStream() {
  if (state.stream) return;
  const es = new EventSource('/api/stream');
  es.onmessage = e => { try { state.live = JSON.parse(e.data); onLive(); } catch (_) { /* ignore */ } };
  es.onerror = async () => {
    if (es.readyState !== EventSource.CLOSED) return;   // still retrying by itself
    if (state.stream === es) state.stream = null;
    try { await api('/api/me'); } catch (_) { return; }  // a 401 signs out
    setTimeout(() => { if (state.user && !state.stream) connectStream(); }, 5000);
  };
  state.stream = es;
}
function closeStream() { if (state.stream) { state.stream.close(); state.stream = null; } }
function signOut() { state.user = null; closeStream(); render(); }
function onLive() {
  const live = state.live;
  const pill = $('#online-pill');
  if (pill) { pill.textContent = live.connected ? String(live.clients.length) : '!'; pill.className = 'pill' + (live.connected ? '' : ' off'); }
  const dot = $('#mgmt-dot');
  if (dot) dot.className = 'status-dot' + (live.connected ? ' on' : '');
  const txt = $('#mgmt-text');
  if (txt) txt.textContent = live.connected ? (shortVer(live.version) || 'OpenVPN') : 'OpenVPN unreachable';
  if (state.view && state.view.onLive) state.view.onLive(live);
}

/* ----------------------------------------------------------------- shell */
function render() {
  clearTimers();
  state.view = null;
  const app = $('#app');
  app.replaceChildren();
  if (!state.user) { app.append(loginView()); return; }
  if (portalMode || state.user.role === 'client') {
    closeStream();
    app.append(h('main', { class: 'main', id: 'view', style: 'margin-left:0;max-width:1000px;margin-right:auto' }));
    renderView();
    return;
  }
  connectStream();
  app.append(sidebar(), h('main', { class: 'main', id: 'view' }));
  renderView();
}
function sidebar() {
  const link = (name, label, ic, extra) => h('a', { href: '#/' + name, class: state.route.name === name ? 'active' : '' }, icon(ic), h('span', { class: 'label' }, label), extra);
  const live = state.live;
  return h('aside', { class: 'sidebar' },
    h('div', { class: 'brand' }, h('div', { class: 'logo' }, svg('svg', { viewBox: '0 0 24 24' }, svg('path', { d: 'M12 2a7 7 0 0 0-3.5 13.06V20h7v-4.94A7 7 0 0 0 12 2z' }))), 'OpenVPN'),
    h('nav', { class: 'nav' },
      link('dashboard', 'Dashboard', 'dash'),
      link('clients', 'Clients', 'users', h('span', { class: 'pill', id: 'online-pill' }, live && live.connected ? live.clients.length : '…')),
      link('sessions', 'Sessions', 'sessions'),
      link('relay', 'Relay', 'lock'),
      link('server', 'Server', 'server'),
      link('settings', 'Settings', 'settings')),
    h('div', { class: 'sidebar-foot' },
      h('span', { class: 'status-dot' + (live && live.connected ? ' on' : ''), id: 'mgmt-dot' }),
      h('span', { class: 'grow', id: 'mgmt-text' }, live ? (live.connected ? (shortVer(live.version) || 'OpenVPN') : 'OpenVPN unreachable') : 'connecting…'),
      h('button', { class: 'btn ghost sm', title: 'Toggle theme', onClick: () => { const cur = localStorage.getItem('theme') || 'system'; const next = cur === 'dark' ? 'light' : cur === 'light' ? 'system' : 'dark'; localStorage.setItem('theme', next); applyTheme(); toast('Theme: ' + next); } }, icon('sun')),
      h('button', { class: 'btn ghost sm', title: 'Sign out', onClick: async () => { try { await api('/api/logout', { method: 'POST' }); } finally { signOut(); } } }, icon('logout'))));
}
function renderView() {
  const el = $('#view');
  if (!el) return;
  clearTimers();
  el.replaceChildren();
  if (portalMode || state.user.role === 'client') { portalView(el); return; }
  document.querySelectorAll('.nav a').forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#/' + state.route.name));
  const views = { dashboard: dashboardView, clients: clientsView, sessions: sessionsView, relay: relayView, server: serverView, settings: settingsView };
  const fn = state.route.name === 'clients' && state.route.param ? clientDetailView : (views[state.route.name] || dashboardView);
  state.view = fn(el) || null;
}
function topbar(title, sub, ...right) {
  return h('div', { class: 'topbar' }, h('div', null, h('h1', null, title), sub ? h('div', { class: 'sub' }, sub) : null), h('div', { class: 'spacer' }), ...right);
}
function rangeControl(onChange) {
  const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Time range' });
  for (const [v, label] of RANGES) {
    seg.append(h('button', { class: state.range === v ? 'active' : '', onClick: () => { state.range = v; localStorage.setItem('range', v); seg.querySelectorAll('button').forEach(b => b.classList.toggle('active', b.textContent === label)); onChange(v); } }, label));
  }
  return seg;
}
function rangeLabel(r) { return (RANGES.find(x => x[0] === r) || ['', r])[1].toLowerCase(); }
function card(title, body, ...actions) {
  return h('section', { class: 'card' }, title ? h('div', { class: 'card-h' }, h('h2', null, title), ...actions) : null, h('div', { class: 'card-b' }, body));
}
function warnings(list, cls) {
  if (!list || !list.length) return null;
  return h('div', { class: 'warnings' }, list.map(w => h('div', { class: 'warn ' + (cls || '') }, icon('warn'), h('span', null, w))));
}
function stateBadge(c) {
  if (c.online) return h('span', { class: 'badge online' }, 'online');
  if (c.state === 'valid' && c.days_left !== null && c.days_left < 30) return h('span', { class: 'badge expiring' }, 'expiring');
  return h('span', { class: 'badge ' + c.state }, c.state);
}

/* --------------------------------------------------------------- charts */
function niceTicks(max, count) {
  if (max <= 0) return [0, 1];
  const raw = max / count, mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / mag;
  const step = Math.max(1, (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10) * mag);   // whole bytes / bits
  const ticks = [];
  for (let v = 0; v <= max + step * 0.999; v += step) ticks.push(v);
  return ticks;
}
function lineChart(container, opts) {
  const chart = { container, opts, table: false };
  const tip = h('div', { class: 'tooltip hidden' });
  const wrap = h('div', { class: 'chart' });
  const foot = h('div', { class: 'chart-foot' });
  const legend = h('div', { class: 'legend' });
  const tableBtn = h('button', { class: 'btn ghost sm', onClick: () => { chart.table = !chart.table; tableBtn.textContent = chart.table ? 'Chart' : 'Table'; chart.draw(); } }, 'Table');
  foot.append(legend, h('div', { class: 'spacer' }), tableBtn);
  container.replaceChildren(wrap, tip, foot);

  chart.draw = () => {
    const o = chart.opts, W = Math.max(280, container.clientWidth || 600), H = o.height || 220;
    const m = { top: 12, right: 16, bottom: 26, left: 52 };
    const n = o.ts.length;
    legend.replaceChildren(...(o.series.length > 1 ? o.series.map(s => h('span', null, h('span', { class: 'key ' + s.cls }), s.label)) : []));
    if (chart.table) {
      const t = h('table', { class: 'tbl' }, h('thead', null, h('tr', null, h('th', null, 'Time'), ...o.series.map(s => h('th', { class: 'r' }, s.label)))),
        h('tbody', null, o.ts.map((ts, i) => h('tr', null, h('td', null, o.fmtXFull ? o.fmtXFull(ts) : fmtDateTime(ts)), ...o.series.map(s => h('td', { class: 'r num' }, o.fmtY(s.values[i] || 0)))))));
      wrap.replaceChildren(h('div', { class: 'table-wrap', style: `max-height:${H + 40}px;overflow:auto` }, t));
      return;
    }
    if (!n) { wrap.replaceChildren(h('div', { class: 'empty' }, 'No data yet')); return; }
    const max = Math.max(1, ...o.series.map(s => Math.max(...s.values)));
    const ticks = niceTicks(max, 4), yMax = ticks[ticks.length - 1];
    const px = i => m.left + (n === 1 ? 0 : (i / (n - 1)) * (W - m.left - m.right));
    const py = v => m.top + (1 - v / yMax) * (H - m.top - m.bottom);
    const s = svg('svg', { viewBox: `0 0 ${W} ${H}`, width: W, height: H, tabindex: 0, role: 'img', 'aria-label': o.aria || 'chart' });
    const g = svg('g', { class: 'grid' });
    ticks.forEach(t => { g.append(svg('line', { x1: m.left, x2: W - m.right, y1: py(t), y2: py(t) })); s.append(svg('text', { x: m.left - 8, y: py(t) + 4, 'text-anchor': 'end' }, o.fmtY(t))); });
    s.append(g);
    const xt = Math.min(6, n, Math.max(2, Math.floor((W - m.left - m.right) / 96)));
    for (let k = 0; k < xt; k++) { const i = Math.round(k * (n - 1) / Math.max(1, xt - 1)); s.append(svg('text', { x: px(i), y: H - 8, 'text-anchor': k === 0 ? 'start' : k === xt - 1 ? 'end' : 'middle' }, o.fmtX(o.ts[i]))); }
    s.append(svg('line', { class: 'axis', x1: m.left, x2: W - m.right, y1: py(0), y2: py(0), stroke: 'var(--axis)' }));
    for (const ser of o.series) {
      const pts = ser.values.map((v, i) => `${px(i).toFixed(1)},${py(v).toFixed(1)}`);
      const gg = svg('g', { class: ser.cls });
      if (n > 1) gg.append(svg('path', { class: 'area', d: `M${px(0)},${py(0)} L${pts.join(' L')} L${px(n - 1)},${py(0)} Z` }));
      gg.append(svg('path', { class: 'line', d: (n > 1 ? 'M' : 'M') + pts.join(' L') }));
      if (n === 1) gg.append(svg('circle', { cx: px(0), cy: py(ser.values[0]), r: 4, fill: 'currentColor' }));
      s.append(gg);
    }
    const cross = svg('line', { class: 'crosshair hidden', y1: m.top, y2: py(0) });
    const dots = o.series.map(ser => svg('circle', { class: 'dot hidden', r: 4, fill: getComputedStyle(document.documentElement).getPropertyValue(ser.cls === 's2' ? '--series-2' : '--series-1') }));
    s.append(cross, ...dots);
    const hit = svg('rect', { class: 'hit', x: m.left, y: m.top, width: W - m.left - m.right, height: H - m.top - m.bottom });
    s.append(hit);
    let idx = -1;
    const show = i => {
      idx = i; if (i < 0) { cross.classList.add('hidden'); dots.forEach(d => d.classList.add('hidden')); tip.classList.add('hidden'); return; }
      cross.setAttribute('x1', px(i)); cross.setAttribute('x2', px(i)); cross.classList.remove('hidden');
      o.series.forEach((ser, k) => { dots[k].setAttribute('cx', px(i)); dots[k].setAttribute('cy', py(ser.values[i])); dots[k].classList.remove('hidden'); });
      tip.replaceChildren(h('div', { class: 't' }, o.fmtXFull ? o.fmtXFull(o.ts[i]) : fmtDateTime(o.ts[i])),
        ...o.series.map(ser => h('div', { class: 'r' }, h('span', { class: 'key ' + ser.cls }), h('span', { class: 'ink2' }, ser.label), h('span', { class: 'v' }, o.fmtY(ser.values[i])))));
      tip.classList.remove('hidden');
      const rect = container.getBoundingClientRect(), scale = rect.width / W;
      const x = px(i) * scale, left = x + 150 > rect.width ? x - 160 : x + 12;
      tip.style.left = left + 'px'; tip.style.top = (m.top * scale) + 'px';
    };
    const pointer = e => { const r = s.getBoundingClientRect(); const x = (e.clientX - r.left) * (W / r.width); show(Math.max(0, Math.min(n - 1, Math.round((x - m.left) / (W - m.left - m.right) * (n - 1))))); };
    hit.addEventListener('pointermove', pointer);
    hit.addEventListener('pointerleave', () => show(-1));
    s.addEventListener('keydown', e => { if (e.key === 'ArrowLeft') { show(Math.max(0, (idx < 0 ? n - 1 : idx) - 1)); e.preventDefault(); } if (e.key === 'ArrowRight') { show(Math.min(n - 1, idx + 1)); e.preventDefault(); } if (e.key === 'Escape') show(-1); });
    s.addEventListener('blur', () => show(-1));
    wrap.replaceChildren(s);
  };
  chart.update = o => { chart.opts = o; chart.draw(); };
  if (window.ResizeObserver) { let t; new ResizeObserver(() => { clearTimeout(t); t = setTimeout(() => { if (!chart.table) chart.draw(); }, 80); }).observe(container); }
  chart.draw();
  return chart;
}
function sparkline(values) {
  const n = values.length, W = 120, H = 28;
  if (n < 2) return svg('svg', { viewBox: `0 0 ${W} ${H}` });
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => `${(i / (n - 1) * W).toFixed(1)},${(H - 2 - (v / max) * (H - 4)).toFixed(1)}`);
  return svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', 'aria-hidden': 'true' },
    svg('path', { d: `M0,${H} L${pts.join(' L')} L${W},${H} Z`, fill: 'var(--series-1-wash)' }),
    svg('path', { d: 'M' + pts.join(' L'), fill: 'none', stroke: 'var(--series-1)', 'stroke-width': 2, 'vector-effect': 'non-scaling-stroke', 'stroke-linejoin': 'round' }));
}
function bars(rows, opts) {
  opts = opts || {};
  if (!rows.length) return h('div', { class: 'empty' }, opts.empty || 'No traffic in this period');
  const max = Math.max(1, ...rows.map(r => r.value));
  const el = h('div', { class: 'bars' });
  for (const r of rows) {
    const fill = h('div', { class: 'fill', style: `width:${(r.value / max * 100).toFixed(1)}%` });
    const track = h('div', { class: 'track', title: r.title || '' }, fill);
    const label = r.href ? h('a', { class: 'lbl', href: r.href }, r.label) : h('div', { class: 'lbl' }, r.label);
    el.append(label, track, h('div', { class: 'val' }, opts.fmt ? opts.fmt(r.value) : fmtBytes(r.value)));
  }
  return el;
}
function tile(label, value, sub, spark) {
  return h('div', { class: 'card tile' }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), sub ? h('div', { class: 'delta' }, sub) : null, spark ? h('div', { class: 'spark' }, spark) : null);
}

/* ---------------------------------------------------------------- login */
function loginView() {
  const err = h('div', { class: 'err' });
  const user = h('input', { class: 'input', name: 'username', autocomplete: 'username', required: true, autofocus: true });
  const pass = h('input', { class: 'input', name: 'password', type: 'password', autocomplete: 'current-password', required: true });
  const btn = h('button', { class: 'btn primary', type: 'submit', style: 'width:100%;justify-content:center;padding:9px' }, 'Sign in');
  const form = h('form', { class: 'form', onSubmit: async e => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true;
    try { state.user = await api(portalMode ? '/api/portal/login' : '/api/login', { method: 'POST', body: { username: user.value.trim(), password: pass.value }, allow401: true }); render(); }
    catch (ex) { err.textContent = ex.message; } finally { btn.disabled = false; }
  } }, field('Username', user), field('Password', pass), err, btn);
  return h('div', { class: 'login' }, h('div', { class: 'card' },
    h('div', { class: 'brand' }, h('div', { class: 'logo' }, svg('svg', { viewBox: '0 0 24 24' }, svg('path', { d: 'M12 2a7 7 0 0 0-3.5 13.06V20h7v-4.94A7 7 0 0 0 12 2z' }))), 'OpenVPN'),
    form));
}

