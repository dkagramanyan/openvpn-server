'use strict';
/* OpenVPN UI - single page application (no dependencies). */

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

/* --------------------------------------------------------------- toasts */
function toast(msg, kind) {
  const el = h('div', { class: 'toast ' + (kind || '') }, msg);
  $('#toasts').append(el);
  setTimeout(() => el.remove(), kind === 'err' ? 7000 : 4000);
}

/* ------------------------------------------------------------------ api */
async function api(path, opts = {}) {
  const init = { method: opts.method || 'GET', credentials: 'same-origin', headers: { 'X-Requested-With': 'fetch' } };
  if (opts.body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(opts.body); }
  let res;
  try { res = await fetch(path, init); } catch (e) { throw new Error('Network error: ' + e.message); }
  if (res.status === 401 && !opts.allow401) { state.user = null; render(); throw new Error('Session expired'); }
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) {
    let msg = typeof data === 'object' && data && data.detail ? data.detail : (typeof data === 'string' && data) || res.statusText;
    if (Array.isArray(msg)) msg = msg.map(e => `${(e.loc || []).slice(1).join('.')}: ${e.msg}`).join('; ');
    throw new Error(msg);
  }
  return data;
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
function field(label, input, help) { return h('div', { class: 'field' }, h('label', null, label), input, help ? h('div', { class: 'help' }, help) : null); }

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
    try { await api('/api/me', { allow401: true }); } catch (_) { /* handled in api */ }
  };
  state.stream = es;
}
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
      link('server', 'Server', 'server'),
      link('settings', 'Settings', 'settings')),
    h('div', { class: 'sidebar-foot' },
      h('span', { class: 'status-dot' + (live && live.connected ? ' on' : ''), id: 'mgmt-dot' }),
      h('span', { class: 'grow', id: 'mgmt-text' }, live ? (live.connected ? (shortVer(live.version) || 'OpenVPN') : 'OpenVPN unreachable') : 'connecting…'),
      h('button', { class: 'btn ghost sm', title: 'Toggle theme', onClick: () => { const cur = localStorage.getItem('theme') || 'system'; const next = cur === 'dark' ? 'light' : cur === 'light' ? 'system' : 'dark'; localStorage.setItem('theme', next); applyTheme(); toast('Theme: ' + next); } }, icon('sun')),
      h('button', { class: 'btn ghost sm', title: 'Sign out', onClick: async () => { await api('/api/logout', { method: 'POST' }); state.user = null; if (state.stream) { state.stream.close(); state.stream = null; } render(); } }, icon('logout'))));
}
function renderView() {
  const el = $('#view');
  if (!el) return;
  clearTimers();
  el.replaceChildren();
  document.querySelectorAll('.nav a').forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#/' + state.route.name));
  const views = { dashboard: dashboardView, clients: clientsView, sessions: sessionsView, server: serverView, settings: settingsView };
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
  const step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10) * mag;
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
    const xt = Math.min(6, n);
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
    try { state.user = await api('/api/login', { method: 'POST', body: { username: user.value.trim(), password: pass.value }, allow401: true }); state.user = await api('/api/me'); render(); }
    catch (ex) { err.textContent = ex.message; } finally { btn.disabled = false; }
  } }, field('Username', user), field('Password', pass), err, btn);
  return h('div', { class: 'login' }, h('div', { class: 'card' },
    h('div', { class: 'brand' }, h('div', { class: 'logo' }, svg('svg', { viewBox: '0 0 24 24' }, svg('path', { d: 'M12 2a7 7 0 0 0-3.5 13.06V20h7v-4.94A7 7 0 0 0 12 2z' }))), 'OpenVPN'),
    form));
}

/* ------------------------------------------------------------ dashboard */
function dashboardView(el) {
  let data = null;
  const sub = h('span', null, 'loading…');
  const body = h('div', { class: 'stack' });
  el.append(topbar('Dashboard', sub, rangeControl(load)), body);
  const liveTable = h('div');
  const throughputTile = h('div');
  let hourChart, rangeChart;

  function renderLiveTable(live) {
    const cls = live.clients;
    if (!live.connected) { liveTable.replaceChildren(h('div', { class: 'empty' }, 'OpenVPN is not reachable: ', live.error || '')); return; }
    if (!cls.length) { liveTable.replaceChildren(h('div', { class: 'empty' }, 'No clients connected')); return; }
    const now = live.server_time || Math.floor(Date.now() / 1000);
    liveTable.replaceChildren(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, 'Client'), h('th', null, 'From'), h('th', null, 'VPN IP'), h('th', null, 'Connected'), h('th', { class: 'r' }, 'Download'), h('th', { class: 'r' }, 'Upload'), h('th', { class: 'r' }, 'Rate ↓ / ↑'), h('th', null, 'Cipher'), h('th', null))),
      h('tbody', null, cls.map(c => h('tr', null,
        h('td', { class: 'name-cell' }, h('a', { href: '#/clients/' + encodeURIComponent(c.cn) }, h('span', { class: 'dot-live' }), c.cn)),
        h('td', { class: 'mono small' }, c.real_address),
        h('td', { class: 'mono small' }, c.vpn_ip || '—'),
        h('td', null, fmtDur(now - c.connected_since), h('span', { class: 'muted small' }, ' · ' + fmtTime(c.connected_since))),
        h('td', { class: 'r num' }, fmtBytes(c.bytes_out)), h('td', { class: 'r num' }, fmtBytes(c.bytes_in)),
        h('td', { class: 'r num small' }, fmtBits(c.rate_out) + ' / ' + fmtBits(c.rate_in)),
        h('td', { class: 'small muted' }, c.cipher),
        h('td', { class: 'actions' }, h('button', { class: 'btn sm', onClick: async () => { if (await confirmDialog('Disconnect client', `Disconnect ${c.cn}? The client will most likely reconnect automatically.`, 'Disconnect', true)) await withToast(api(`/api/clients/${encodeURIComponent(c.cn)}/disconnect`, { method: 'POST', body: { cid: c.cid } }), 'Disconnect signal sent'); } }, 'Disconnect'))))))));
  }
  function renderThroughput(live) {
    throughputTile.replaceChildren(tile('Current throughput', [fmtBits(live.rate_out), h('small', null, '↓')], `↑ ${fmtBits(live.rate_in)} · ${live.connected ? live.clients.length + ' connected' : 'offline'}`));
  }

  async function load() {
    body.classList.add('loading');
    try {
      data = await api(`/api/overview?range=${state.range}&tz=${TZ}`);
    } catch (e) { toast(e.message, 'err'); body.classList.remove('loading'); return; }
    const live = data.live; state.live = live;
    sub.textContent = live.connected ? `${shortVer(live.version) || 'OpenVPN'} · ${data.counts.valid} active client${data.counts.valid === 1 ? '' : 's'}` : 'OpenVPN unreachable';
    const t = data.totals, rl = rangeLabel(state.range);
    const dl = data.series.map(p => p.bytes_out), ul = data.series.map(p => p.bytes_in);
    renderThroughput(live);
    const hourOpts = { ts: data.hour.map(p => p.ts), series: [{ label: 'Download', cls: 's1', values: data.hour.map(p => p.bytes_out / 60) }, { label: 'Upload', cls: 's2', values: data.hour.map(p => p.bytes_in / 60) }], fmtY: fmtBits, fmtX: fmtTime, fmtXFull: ts => fmtTime(ts), height: 200, aria: 'Throughput in the last hour' };
    const bucket = data.bucket;
    const fmtX = bucket >= 86400 ? fmtDate : (state.range === '7d' ? ts => new Date(ts * 1000).toLocaleString([], { weekday: 'short', hour: '2-digit' }) : fmtTime);
    const rangeOpts = { ts: data.series.map(p => p.ts), series: [{ label: 'Download', cls: 's1', values: dl }, { label: 'Upload', cls: 's2', values: ul }], fmtY: v => fmtBytes(v, 0), fmtX, fmtXFull: bucket >= 86400 ? fmtDate : fmtDateTime, height: 220, aria: 'Traffic per ' + (bucket >= 86400 ? 'day' : bucket >= 3600 ? 'hour' : '10 minutes') };
    if (!body.children.length) {
      const hourEl = h('div'), rangeEl = h('div');
      body.append(
        h('div', { id: 'warnings' }),
        h('div', { class: 'grid kpi', id: 'kpi' }),
        h('div', { class: 'grid two' }, card('Throughput · last 60 minutes', hourEl), card('Top clients · ' + rl, h('div', { id: 'top' }))),
        card('Traffic · ' + rl, rangeEl),
        card('Connected clients', liveTable));
      hourChart = lineChart(hourEl, hourOpts); rangeChart = lineChart(rangeEl, rangeOpts);
    } else { hourChart.update(hourOpts); rangeChart.update(rangeOpts); body.querySelectorAll('.card-h h2').forEach(x => { if (x.textContent.startsWith('Top clients')) x.textContent = 'Top clients · ' + rl; if (x.textContent.startsWith('Traffic ·')) x.textContent = 'Traffic · ' + rl; }); }
    $('#warnings', body).replaceChildren(warnings(data.warnings) || '');
    $('#kpi', body).replaceChildren(
      tile('Online now', [live.connected ? live.clients.length : '—', h('small', null, `of ${data.counts.valid}`)], data.counts.expiring ? `${data.counts.expiring} expiring soon` : `${data.counts.revoked} revoked`),
      tile('Download · ' + rl, fmtBytes(t.bytes_out), `${fmtNum(t.sessions)} session${t.sessions === 1 ? '' : 's'} · ${t.clients} client${t.clients === 1 ? '' : 's'}`, sparkline(dl.slice(-24))),
      tile('Upload · ' + rl, fmtBytes(t.bytes_in), 'from clients to the server', sparkline(ul.slice(-24))),
      throughputTile);
    $('#top', body).replaceChildren(bars(data.top.map(c => ({ label: c.name, value: c.bytes_in + c.bytes_out, href: '#/clients/' + encodeURIComponent(c.name), title: `↓ ${fmtBytes(c.bytes_out)} · ↑ ${fmtBytes(c.bytes_in)}` }))));
    renderLiveTable(live);
    body.classList.remove('loading');
  }
  load();
  every(60000, load);
  return { onLive: live => { renderLiveTable(live); renderThroughput(live); if (data) sub.textContent = live.connected ? `${shortVer(live.version) || 'OpenVPN'} · ${data.counts.valid} active client${data.counts.valid === 1 ? '' : 's'}` : 'OpenVPN unreachable'; } };
}

/* -------------------------------------------------------------- clients */
function clientsView(el) {
  let rows = [], filter = 'all', search = '', sort = { key: 'default', asc: true };
  const table = h('div');
  const count = h('span');
  const searchIn = h('input', { class: 'input search', placeholder: 'Search clients…', onInput: e => { search = e.target.value.toLowerCase(); draw(); } });
  const filters = h('div', { class: 'seg' });
  for (const [k, l] of [['all', 'All'], ['online', 'Online'], ['valid', 'Valid'], ['expiring', 'Expiring'], ['revoked', 'Revoked']]) {
    filters.append(h('button', { class: k === filter ? 'active' : '', onClick: e => { filter = k; filters.querySelectorAll('button').forEach(b => b.classList.toggle('active', b === e.currentTarget)); draw(); } }, l));
  }
  el.append(topbar('Clients', count, searchIn, rangeControl(load), h('button', { class: 'btn primary', onClick: () => newClientDialog(load) }, icon('plus'), 'New client')),
    h('div', { class: 'row', style: 'margin-bottom:12px' }, filters), h('section', { class: 'card' }, table));

  function draw() {
    let list = rows.filter(c => {
      if (search && !(c.name.toLowerCase().includes(search) || (c.note || '').toLowerCase().includes(search) || (c.static_ip || '').includes(search))) return false;
      if (filter === 'online') return c.online;
      if (filter === 'valid') return c.state === 'valid';
      if (filter === 'expiring') return c.state === 'valid' && c.days_left !== null && c.days_left < 30;
      if (filter === 'revoked') return c.state === 'revoked' || c.state === 'expired';
      return true;
    });
    const key = { name: c => c.name.toLowerCase(), expires: c => c.expires || 0, seen: c => c.total.last_seen || 0, dl: c => c.traffic.bytes_out, ul: c => c.traffic.bytes_in, sessions: c => c.total.sessions }[sort.key];
    if (key) list = list.slice().sort((a, b) => (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0) * (sort.asc ? 1 : -1));
    count.textContent = `${rows.filter(c => c.state === 'valid').length} active · ${rows.filter(c => c.online).length} online · ${rows.length} total`;
    const th = (label, k, cls) => h('th', { class: (cls || '') + (k ? ' sortable' : '') + (sort.key === k ? ' sorted' + (sort.asc ? ' asc' : '') : ''), onClick: k ? () => { sort = { key: k, asc: sort.key === k ? !sort.asc : k === 'name' }; draw(); } : null }, label);
    if (!list.length) { table.replaceChildren(h('div', { class: 'empty' }, rows.length ? 'No clients match' : 'No clients yet - create the first one')); return; }
    table.replaceChildren(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, th('Name', 'name'), th('Status'), th('Expires', 'expires'), th('Last seen', 'seen'), th('Download', 'dl', 'r'), th('Upload', 'ul', 'r'), th('Sessions', 'sessions', 'r'), h('th', null))),
      h('tbody', null, list.map(c => h('tr', { class: 'clickable', onClick: e => { if (!e.target.closest('button,a')) go('#/clients/' + encodeURIComponent(c.name)); } },
        h('td', { class: 'name-cell' }, c.name, c.note ? h('span', { class: 'sub' }, c.note) : null),
        h('td', null, h('div', { class: 'row', style: 'gap:6px' }, stateBadge(c), c.tfa ? h('span', { class: 'badge plain', title: 'Two-factor authentication enabled' }, '2FA') : null, c.static_ip ? h('span', { class: 'subnet', title: 'Static IP' }, c.static_ip) : null, c.previous ? h('span', { class: 'badge plain expiring', title: 'Previous certificate still valid' }, 'renewed') : null)),
        h('td', { class: 'num' }, c.expires ? [fmtDate(c.expires), h('span', { class: 'muted small' }, ' · ' + fmtDays(c.days_left))] : '—'),
        h('td', null, c.online ? h('span', { class: 'ink2' }, 'now') : fmtAgo(c.total.last_seen)),
        h('td', { class: 'r num' }, fmtBytes(c.traffic.bytes_out)), h('td', { class: 'r num' }, fmtBytes(c.traffic.bytes_in)),
        h('td', { class: 'r num' }, fmtNum(c.total.sessions)),
        h('td', { class: 'actions' }, c.state === 'valid' ? h('a', { class: 'btn sm', href: `/api/clients/${encodeURIComponent(c.name)}/ovpn`, download: c.name + '.ovpn', title: 'Download profile' }, icon('download')) : null)))))));
  }
  async function load() {
    table.classList.add('loading');
    try { rows = (await api(`/api/clients?range=${state.range}&tz=${TZ}`)).clients; draw(); } catch (e) { toast(e.message, 'err'); }
    table.classList.remove('loading');
  }
  load();
  every(30000, load);
  return { onLive: live => { const on = new Set(live.clients.map(c => c.cn)); let changed = false; rows.forEach(r => { const o = on.has(r.name); if (o !== r.online) { r.online = o; changed = true; } }); if (changed) draw(); } };
}

function newClientDialog(after) {
  const name = h('input', { class: 'input', placeholder: 'e.g. alice-laptop', pattern: '[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}', required: true, autofocus: true });
  const days = h('input', { class: 'input', type: 'number', min: 1, max: 3650, placeholder: 'default from easy-rsa vars' });
  const ip = h('input', { class: 'input', placeholder: '10.0.71.10 for guest access' });
  const pass = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', placeholder: 'optional' });
  const note = h('input', { class: 'input', placeholder: 'optional' });
  const tfa = h('input', { type: 'checkbox' });
  const body = h('div', { class: 'form cols' },
    h('div', { class: 'full' }, field('Client name', name, 'Letters, digits, _ . @ - (becomes the certificate common name)')),
    field('Validity (days)', days), field('Static IP', ip, 'Guest subnet = internet only'),
    field('Key passphrase', pass, 'Encrypts the private key inside the profile'), field('Note', note),
    h('label', { class: 'check full' }, tfa, 'Require a TOTP code (two-factor authentication)'));
  dialog({ title: 'New client', body, buttons: [{ label: 'Cancel', value: null }, { label: 'Create', cls: 'primary', onClick: async () => {
    if (!name.checkValidity()) { name.reportValidity(); return false; }
    try {
      const r = await api('/api/clients', { method: 'POST', body: { name: name.value.trim(), days: days.value ? Number(days.value) : null, passphrase: pass.value || null, static_ip: ip.value.trim() || null, tfa: tfa.checked, note: note.value } });
      toast(`Client ${r.client.name} created`, 'ok');
      after && after();
      if (r.tfa_uri) tfaDialog(r.client.name, r.tfa_uri);
      return true;
    } catch (e) { toast(e.message, 'err'); return false; }
  } }] });
}
function tfaDialog(name, uri) {
  const img = h('img', { src: `/api/clients/${encodeURIComponent(name)}/tfa/qr.svg?t=${Date.now()}`, alt: 'TOTP enrolment QR code' });
  dialog({ title: `Two-factor setup · ${name}`, body: h('div', { class: 'qr' }, h('div', { class: 'code' }, img),
    h('div', { class: 'stack', style: 'flex:1;min-width:220px;gap:8px' },
      h('p', { style: 'margin:0' }, 'Scan the code with an authenticator app (Google Authenticator, Aegis, 1Password…). When connecting, the username is the client name and the password is the current 6-digit code.'),
      h('div', { class: 'uri mono muted' }, uri))), buttons: [{ label: 'Done', cls: 'primary', value: true }] });
}

/* -------------------------------------------------------- client detail */
function clientDetailView(el) {
  const name = state.route.param;
  let c = null;
  const body = h('div', { class: 'stack' });
  const title = h('h1', null, name);
  const badges = h('div', { class: 'row', style: 'gap:6px' });
  const actions = h('div', { class: 'row' });
  el.append(h('div', { class: 'topbar' }, h('a', { class: 'btn ghost sm', href: '#/clients', title: 'Back' }, icon('back')), h('div', null, title, badges), h('div', { class: 'spacer' }), actions), body);
  const enc = encodeURIComponent(name);
  const act = (label, fn, cls) => h('button', { class: 'btn ' + (cls || ''), onClick: fn }, label);

  async function load() {
    body.classList.add('loading');
    try { c = await api(`/api/clients/${enc}?tz=${TZ}`); } catch (e) { toast(e.message, 'err'); body.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
    setChildren(badges, stateBadge(c), c.tfa ? h('span', { class: 'badge plain' }, '2FA') : null, c.static_ip ? h('span', { class: 'subnet' }, 'static ' + c.static_ip) : null, c.previous ? h('span', { class: 'badge plain expiring' }, 'renewed · previous cert still valid') : null);
    setChildren(actions, 
      c.state === 'valid' ? h('a', { class: 'btn primary', href: `/api/clients/${enc}/ovpn`, download: name + '.ovpn' }, icon('download'), 'Download profile') : null,
      c.online ? act('Disconnect', async () => { if (await confirmDialog('Disconnect', `Disconnect all sessions of ${name}?`, 'Disconnect', true)) { await withToast(api(`/api/clients/${enc}/disconnect`, { method: 'POST', body: {} }), 'Disconnected'); } }) : null,
      c.state === 'valid' ? act(c.tfa ? 'Show 2FA code' : 'Enable 2FA', async () => {
        if (c.tfa) { tfaDialog(name, c.tfa_uri); return; }
        if (await confirmDialog('Enable two-factor authentication', 'A new TOTP secret will be generated and "auth-user-pass" added to the profile. Re-deliver the profile afterwards. Note: 2FA is only checked when it is enforced on the Server page.', 'Enable')) {
          const r = await withToast(api(`/api/clients/${enc}/tfa`, { method: 'POST', body: { enabled: true } }), '2FA enabled'); tfaDialog(name, r.tfa_uri); load();
        } }) : null,
      c.state === 'valid' && c.tfa ? act('Disable 2FA', async () => { if (await confirmDialog('Disable 2FA', `Remove the TOTP secret of ${name}?`, 'Disable', true)) { await withToast(api(`/api/clients/${enc}/tfa`, { method: 'POST', body: { enabled: false } }), '2FA disabled'); load(); } }) : null,
      c.state === 'valid' ? act('Static IP', () => staticIpDialog(c, load)) : null,
      c.state === 'valid' && !c.previous ? act('Renew', async () => { if (await confirmDialog('Renew certificate', 'A new certificate is issued for the same key. The previous certificate stays valid until you revoke it, so the client keeps working while you deliver the new profile.', 'Renew')) { await withToast(api(`/api/clients/${enc}/renew`, { method: 'POST', body: {} }), 'Certificate renewed'); load(); } }) : null,
      c.previous ? act('Revoke previous cert', async () => { if (await confirmDialog('Revoke previous certificate', 'The old certificate will be added to the CRL. Make sure the client already uses the new profile.', 'Revoke', true)) { await withToast(api(`/api/clients/${enc}/revoke-previous`, { method: 'POST' }), 'Previous certificate revoked'); load(); } }, 'danger') : null,
      c.state !== 'revoked' ? act('Revoke', async () => { if (await confirmDialog('Revoke certificate', `${name} will be disconnected and can no longer connect. This cannot be undone.`, 'Revoke', true)) { await withToast(api(`/api/clients/${enc}/revoke`, { method: 'POST', body: {} }), 'Certificate revoked'); load(); } }, 'danger') : null,
      c.state !== 'valid' ? act('Delete', async () => { if (await confirmDialog('Delete client', `Remove the profile, static IP and 2FA data of ${name}? Traffic history is kept.`, 'Delete', true)) { await withToast(api(`/api/clients/${enc}`, { method: 'DELETE' }), 'Client deleted'); go('#/clients'); } }, 'danger') : null);

    const cert = c.cert, t = c.total;
    const kv = (pairs) => h('dl', { class: 'kv' }, pairs.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
    const dailyEl = h('div');
    const noteIn = h('textarea', { class: 'input', style: 'min-height:60px', placeholder: 'Notes about this client…' }, c.note || '');
    body.replaceChildren(
      h('div', { class: 'grid kpi' },
        tile('Download · total', fmtBytes(t.bytes_out), 'server → client'), tile('Upload · total', fmtBytes(t.bytes_in), 'client → server'),
        tile('Sessions', fmtNum(t.sessions), t.first_seen ? 'first seen ' + fmtDate(t.first_seen) : 'never connected'),
        tile('Time online', fmtDur(t.online_seconds), c.online ? 'connected now' : 'last seen ' + fmtAgo(t.last_seen))),
      h('div', { class: 'grid two' },
        card('Traffic · last 30 days', dailyEl),
        h('div', { class: 'stack' },
          card('Certificate', kv([
            ['Status', h('span', null, h('span', { class: 'badge ' + cert.state }, cert.state), cert.reason ? ' · ' + cert.reason : '')],
            ['Serial', h('span', { class: 'mono small' }, cert.serial)],
            ['Valid from', fmtDateTime(cert.not_before)],
            ['Expires', h('span', null, fmtDateTime(cert.not_after), c.days_left !== null ? h('span', { class: 'muted' }, ` (${fmtDays(c.days_left)})`) : null)],
            cert.revoked_at ? ['Revoked', fmtDateTime(cert.revoked_at)] : null,
            ['Fingerprint', h('span', { class: 'mono small' }, cert.fingerprint)],
            c.previous ? ['Previous cert', h('span', null, `serial ${c.previous.serial.slice(0, 16)}… valid until ${fmtDate(c.previous.not_after)} - revoke it once the new profile is deployed`)] : null,
            c.history.length ? ['History', `${c.history.length} revoked certificate${c.history.length > 1 ? 's' : ''}`] : null,
            ['Static IP', c.static_ip || 'dynamic (trusted subnet)'],
            ['2FA', c.tfa ? 'enabled' : 'off'],
          ].filter(Boolean))),
          card('Note', h('div', { class: 'stack', style: 'gap:8px' }, noteIn, h('div', null, h('button', { class: 'btn sm', onClick: () => withToast(api(`/api/clients/${enc}/note`, { method: 'PUT', body: { note: noteIn.value } }), 'Note saved') }, 'Save note')))))),
      card('Sessions · last 100', sessionsTable(c.sessions, false)));
    lineChart(dailyEl, { ts: c.daily.map(p => p.ts), series: [{ label: 'Download', cls: 's1', values: c.daily.map(p => p.bytes_out) }, { label: 'Upload', cls: 's2', values: c.daily.map(p => p.bytes_in) }], fmtY: v => fmtBytes(v, 0), fmtX: fmtDate, fmtXFull: fmtDate, height: 220, aria: 'Daily traffic' });
    body.classList.remove('loading');
  }
  load();
  return { onLive: live => { if (!c) return; const on = live.clients.some(x => x.cn === name); if (on !== c.online) load(); } };
}
function staticIpDialog(c, after) {
  const ip = h('input', { class: 'input', value: c.static_ip || '', placeholder: 'leave empty for a dynamic address' });
  dialog({ title: 'Static IP · ' + c.name, body: h('div', { class: 'form' }, field('IPv4 address', ip, 'Use an address from the guest subnet to restrict this client to internet access only. Applies on the next connection.')),
    buttons: [{ label: 'Cancel', value: null }, { label: 'Save', cls: 'primary', onClick: async () => { try { await api(`/api/clients/${encodeURIComponent(c.name)}/static-ip`, { method: 'PUT', body: { ip: ip.value.trim() || null } }); toast('Static IP saved', 'ok'); after(); return true; } catch (e) { toast(e.message, 'err'); return false; } } }] });
}
function sessionsTable(list, withName) {
  if (!list.length) return h('div', { class: 'empty' }, 'No sessions recorded');
  return h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
    h('thead', null, h('tr', null, withName ? h('th', null, 'Client') : null, h('th', null, 'Connected'), h('th', null, 'Duration'), h('th', null, 'From'), h('th', null, 'VPN IP'), h('th', { class: 'r' }, 'Download'), h('th', { class: 'r' }, 'Upload'), h('th', null, 'Cipher'))),
    h('tbody', null, list.map(s => h('tr', null,
      withName ? h('td', { class: 'name-cell' }, h('a', { href: '#/clients/' + encodeURIComponent(s.client_name) }, s.client_name)) : null,
      h('td', { class: 'num' }, fmtDateTime(s.connected_at)),
      h('td', null, s.disconnected_at ? fmtDur(s.disconnected_at - s.connected_at) : h('span', { class: 'ink2' }, h('span', { class: 'dot-live' }), fmtDur(Date.now() / 1000 - s.connected_at))),
      h('td', { class: 'mono small' }, s.real_address || '—'), h('td', { class: 'mono small' }, s.vpn_ip || '—'),
      h('td', { class: 'r num' }, fmtBytes(s.bytes_out)), h('td', { class: 'r num' }, fmtBytes(s.bytes_in)),
      h('td', { class: 'small muted' }, s.cipher || ''))))));
}

/* ------------------------------------------------------------- sessions */
function sessionsView(el) {
  let offset = 0, total = 0, name = '', active = false;
  const LIMIT = 100;
  const table = h('div');
  const pager = h('div', { class: 'row', style: 'justify-content:flex-end;padding:10px 16px' });
  const nameIn = h('input', { class: 'input search', placeholder: 'Filter by client name', onChange: e => { name = e.target.value.trim(); offset = 0; load(); } });
  const activeIn = h('label', { class: 'check' }, h('input', { type: 'checkbox', onChange: e => { active = e.target.checked; offset = 0; load(); } }), 'Active only');
  const count = h('span');
  el.append(topbar('Sessions', count, nameIn, activeIn, h('button', { class: 'btn', onClick: load }, icon('refresh'), 'Refresh')), h('section', { class: 'card' }, table, pager));
  async function load() {
    table.classList.add('loading');
    try {
      const r = await api(`/api/sessions?limit=${LIMIT}&offset=${offset}&active=${active}${name ? '&name=' + encodeURIComponent(name) : ''}`);
      total = r.total; count.textContent = `${fmtNum(total)} session${total === 1 ? '' : 's'}`;
      table.replaceChildren(sessionsTable(r.sessions, true));
      pager.replaceChildren(h('span', { class: 'muted small' }, total ? `${offset + 1}–${Math.min(offset + LIMIT, total)} of ${fmtNum(total)}` : ''),
        h('button', { class: 'btn sm', disabled: offset === 0, onClick: () => { offset = Math.max(0, offset - LIMIT); load(); } }, 'Previous'),
        h('button', { class: 'btn sm', disabled: offset + LIMIT >= total, onClick: () => { offset += LIMIT; load(); } }, 'Next'));
    } catch (e) { toast(e.message, 'err'); }
    table.classList.remove('loading');
  }
  load();
  return null;
}

/* --------------------------------------------------------------- server */
function serverView(el) {
  const body = h('div', { class: 'stack' });
  const sub = h('span');
  el.append(topbar('Server', sub, h('button', { class: 'btn danger', onClick: async () => { if (await confirmDialog('Restart OpenVPN', 'All connected clients will be disconnected and reconnect automatically. Configuration changes are applied on restart.', 'Restart', true)) await withToast(api('/api/server/restart', { method: 'POST' }), 'OpenVPN is restarting'); } }, icon('power'), 'Restart OpenVPN')), body);
  let info = null;
  const kv = pairs => h('dl', { class: 'kv' }, pairs.filter(Boolean).map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
  const expiry = (c, warnDays) => { if (!c || !c.not_after) return '—'; const d = Math.floor((c.not_after - Date.now() / 1000) / 86400); return h('span', { class: d < warnDays ? 'badge expiring' : '' }, `${fmtDate(c.not_after)} (${fmtDays(d)})`); };

  async function load() {
    try { info = await api('/api/server'); } catch (e) { toast(e.message, 'err'); return; }
    const live = info.live, p = info.pki, crl = p.crl;
    sub.textContent = live.connected ? `${shortVer(live.version)} · management connected ${fmtAgo(live.connected_since)}` : 'management interface unreachable';
    const tfaToggle = h('input', { type: 'checkbox', checked: info.tfa_enforced, onChange: async e => {
      const on = e.target.checked;
      if (!await confirmDialog(on ? 'Enforce two-factor authentication' : 'Stop enforcing 2FA', on ? 'Every client must then send its name and a TOTP code. Clients without an enrolled secret will be rejected. OpenVPN must be restarted to apply.' : 'Clients will connect with certificates only. OpenVPN must be restarted to apply.', on ? 'Enforce' : 'Disable', !on)) { e.target.checked = !on; return; }
      await withToast(api('/api/server/tfa', { method: 'PUT', body: { enforced: on } }), 'Saved - restart OpenVPN to apply'); load();
    } });
    body.replaceChildren(
      h('div', { class: 'grid two' },
        card('Status', kv([
          ['OpenVPN', live.version || '—'],
          ['Management', h('span', null, h('span', { class: 'status-dot' + (live.connected ? ' on' : ''), style: 'display:inline-block;margin-right:6px' }), live.connected ? `${info.management.host}:${info.management.port}${info.management.password ? ' (password protected)' : ''}` : (live.error || 'disconnected'))],
          ['Data channel offload', live.stats && live.stats.dco_enabled !== undefined ? (live.stats.dco_enabled === '1' ? 'enabled (kernel)' : 'not available on this kernel') : '—'],
          ['Connected clients', live.connected ? String(live.clients.length) : '—'],
          ['Since process start', live.load && live.load.bytesin !== undefined ? `↓ ${fmtBytes(live.load.bytesout)} · ↑ ${fmtBytes(live.load.bytesin)}` : '—'],
          ['Client profiles point to', `${info.remote.host || '(not set)'}:${info.remote.port} ${info.remote.proto}`],
          ['UI version', info.ui_version],
        ])),
        card('PKI', kv([
          ['Certificate authority', h('span', null, p.ca ? p.ca.cn : '—', ' · expires ', expiry(p.ca, 90))],
          ['Server certificate', h('span', null, p.server ? p.server.cn : '—', ' · expires ', expiry(p.server, 30))],
          ['Key algorithm', p.algo === 'ec' ? `EC ${p.curve || ''}` : `RSA ${p.key_size || ''}`],
          ['Default client validity', `${p.cert_days} days`],
          ['tls-crypt key', p.tls_key ? 'present' : h('span', { class: 'badge revoked' }, 'missing')],
          ['Revocation list', crl.exists ? h('span', null, `${crl.revoked} revoked · next update `, expiry({ not_after: crl.next_update }, 30)) : h('span', { class: 'badge revoked' }, 'missing')],
        ]), h('button', { class: 'btn sm', onClick: () => withToast(api('/api/server/crl', { method: 'POST' }), 'CRL regenerated').then(load) }, 'Regenerate CRL'))),
      card('Two-factor authentication', h('div', { class: 'stack', style: 'gap:8px' },
        h('label', { class: 'check' }, tfaToggle, h('b', null, 'Require a TOTP code from every client')),
        h('p', { class: 'small muted', style: 'margin:0' }, 'Adds "auth-user-pass-verify" to server.conf. Enrol clients first (Clients → client → Enable 2FA), then enforce and restart. Clients without a secret cannot connect while enforced.'))),
      configEditor(), logsCard(), eventsCard());
  }
  function configEditor() {
    const tabs = h('div', { class: 'tabs' });
    const ta = h('textarea', { class: 'input code', spellcheck: false });
    const hint = h('div', { class: 'small muted' });
    let which = 'server';
    const files = { server: 'server.conf', client: 'client.conf (profile template)', vars: 'easy-rsa vars' };
    async function open(w) {
      which = w; tabs.querySelectorAll('button').forEach(b => b.classList.toggle('active', b.dataset.w === w));
      try { const r = await api('/api/server/config/' + w); ta.value = r.content; hint.textContent = r.path + (w === 'server' ? ' · restart OpenVPN after saving' : w === 'client' ? ' · all profiles are regenerated after saving' : ' · used for new certificates'); } catch (e) { toast(e.message, 'err'); }
    }
    for (const [w, label] of Object.entries(files)) tabs.append(h('button', { dataset: { w }, onClick: () => open(w) }, label));
    open('server');
    return card('Configuration', h('div', { class: 'stack', style: 'gap:10px' }, tabs, ta, h('div', { class: 'row' }, h('button', { class: 'btn primary', onClick: async () => { const r = await withToast(api('/api/server/config/' + which, { method: 'PUT', body: { content: ta.value } }), 'Saved'); if (r.restart_required) toast('Restart OpenVPN to apply the new server.conf'); } }, 'Save'), h('button', { class: 'btn', onClick: () => open(which) }, 'Reload'), hint)));
  }
  function logsCard() {
    const pre = h('pre', { class: 'log mono' });
    const tabs = h('div', { class: 'tabs' });
    let which = 'openvpn';
    const auto = h('input', { type: 'checkbox', checked: true });
    const quiet = h('input', { type: 'checkbox', checked: true, onChange: () => load() });
    async function load() {
      try {
        let text = await api(`/api/server/log?which=${which}&lines=${quiet.checked ? 600 : 300}`);
        if (quiet.checked && which === 'openvpn') text = text.split('\n').filter(l => !/MANAGEMENT: (CMD '|Client (dis)?connected)/.test(l)).slice(-300).join('\n');
        pre.textContent = text || '(empty)'; pre.scrollTop = pre.scrollHeight;
      } catch (e) { pre.textContent = e.message; }
    }
    for (const [w, l] of [['openvpn', 'openvpn.log'], ['oath', '2FA log'], ['status', 'status file']]) tabs.append(h('button', { class: w === which ? 'active' : '', onClick: e => { which = w; tabs.querySelectorAll('button').forEach(b => b.classList.toggle('active', b === e.currentTarget)); load(); } }, l));
    load(); every(10000, () => { if (auto.checked) load(); });
    return card('Logs', h('div', { class: 'stack', style: 'gap:10px' }, tabs, pre), h('label', { class: 'check small', title: 'Hide the management-interface polling lines' }, quiet, 'hide polling'), h('label', { class: 'check small' }, auto, 'auto-refresh'), h('button', { class: 'btn sm', onClick: load }, icon('refresh')));
  }
  function eventsCard() {
    const wrap = h('div');
    async function load() {
      try {
        const r = await api('/api/events?limit=100');
        wrap.replaceChildren(r.events.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' }, h('thead', null, h('tr', null, h('th', null, 'Time'), h('th', null, 'Event'), h('th', null, 'Client'), h('th', null, 'By'), h('th', null, 'Detail'))),
          h('tbody', null, r.events.map(e => h('tr', null, h('td', { class: 'num nowrap' }, fmtDateTime(e.ts)), h('td', null, e.kind.replace(/_/g, ' ')), h('td', null, e.client_name ? h('a', { href: '#/clients/' + encodeURIComponent(e.client_name) }, e.client_name) : ''), h('td', null, e.actor || ''), h('td', { class: 'small muted' }, e.detail || '')))))) : h('div', { class: 'empty' }, 'No events'));
      } catch (e) { toast(e.message, 'err'); }
    }
    load(); every(30000, load);
    return card('Audit log', wrap);
  }
  load();
  return { onLive: live => { if (info && info.live.connected !== live.connected) load(); } };
}

/* ------------------------------------------------------------- settings */
function settingsView(el) {
  const body = h('div', { class: 'stack' });
  el.append(topbar('Settings'), body);
  (async () => {
    let s;
    try { s = await api('/api/settings'); } catch (e) { toast(e.message, 'err'); return; }
    const host = h('input', { class: 'input', value: s.remote.host, placeholder: 'vpn.example.com or public IP' });
    const port = h('input', { class: 'input', type: 'number', min: 1, max: 65535, value: s.remote.port });
    const proto = h('select', { class: 'input' }, h('option', { value: 'tcp', selected: s.remote.proto === 'tcp' }, 'tcp'), h('option', { value: 'udp', selected: s.remote.proto === 'udp' }, 'udp'));
    const cur = h('input', { class: 'input', type: 'password', autocomplete: 'current-password' });
    const nw = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', minlength: 8 });
    const nw2 = h('input', { class: 'input', type: 'password', autocomplete: 'new-password' });
    const theme = h('div', { class: 'seg' });
    const curTheme = localStorage.getItem('theme') || 'system';
    for (const t of ['system', 'light', 'dark']) theme.append(h('button', { class: t === curTheme ? 'active' : '', onClick: e => { localStorage.setItem('theme', t); applyTheme(); theme.querySelectorAll('button').forEach(b => b.classList.toggle('active', b === e.currentTarget)); } }, t));
    body.append(
      h('div', { class: 'grid two' },
        card('Public address for client profiles', h('div', { class: 'form' }, h('div', { class: 'form cols' }, h('div', { class: 'full' }, field('Host', host)), field('Port', port), field('Protocol', proto)),
          h('p', { class: 'small muted', style: 'margin:0' }, 'Written as the "remote" line of config/client.conf. Existing profiles are regenerated; clients need the new file only if the address changed. The protocol must match "proto" in server.conf.'),
          h('div', null, h('button', { class: 'btn primary', onClick: async () => { await withToast(api('/api/settings', { method: 'PUT', body: { host: host.value.trim(), port: Number(port.value), proto: proto.value } }), 'Saved and profiles regenerated'); } }, 'Save')))),
        card('Change password', h('div', { class: 'form' }, field('Current password', cur), field('New password', nw, 'At least 8 characters'), field('Repeat new password', nw2),
          h('div', null, h('button', { class: 'btn primary', onClick: async () => { if (nw.value !== nw2.value) { toast('Passwords do not match', 'err'); return; } await withToast(api('/api/me/password', { method: 'POST', body: { current: cur.value, new: nw.value } }), 'Password changed'); cur.value = nw.value = nw2.value = ''; } }, 'Change password'))))),
      h('div', { class: 'grid two' },
        card('Appearance', h('div', { class: 'row' }, theme)),
        card('About', h('dl', { class: 'kv' }, h('dt', null, 'UI version'), h('dd', null, s.version), h('dt', null, 'Signed in as'), h('dd', null, state.user.username), h('dt', null, 'Poll interval'), h('dd', null, `${s.poll_interval} s`), h('dt', null, '2FA issuer'), h('dd', null, s.tfa_issuer)))));
  })();
  return null;
}

/* ----------------------------------------------------------------- boot */
window.addEventListener('hashchange', () => { state.route = parseRoute(); if (state.user) renderView(); });
applyTheme();
(async () => {
  state.route = parseRoute();
  try { state.user = await api('/api/me', { allow401: true }); } catch (_) { state.user = null; }
  render();
})();
