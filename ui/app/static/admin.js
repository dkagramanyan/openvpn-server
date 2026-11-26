'use strict';
/* Administrator pages: dashboard, clients, client detail, sessions and server. */

/* ------------------------------------------------------ portal accounts */
async function portalAccessDialog(name) {
  const url = `/api/clients/${encodeURIComponent(name)}/portal`;
  let info;
  try { info = await api(url); } catch (e) { toast(e.message, 'err'); return; }
  const telegram = h('input', { class: 'input', value: info.telegram ? '@' + info.telegram : '', placeholder: '@username', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Telegram username' });
  const linkState = h('p', { class: 'small muted', style: 'margin:0' });
  const login = h('div', { class: 'stack', style: 'gap:8px' });
  const showTelegram = () => setChildren(linkState,
    !info.bot ? 'The bot is off: set OVPN_TELEGRAM_BOT_TOKEN in .env and recreate the UI container.'
      : !info.telegram ? `Without a username the bot does not answer this client. Bot: t.me/${info.bot_username || '…'}`
      : info.telegram_linked ? `Linked to the Telegram account of ${info.telegram_name || '@' + info.telegram}. Only that account gets answers.`
      : `Not linked yet: ask them to open t.me/${info.bot_username || '…'} and press Start.`);
  const showLogin = password => setChildren(login,
    h('p', { style: 'margin:0' }, info.enabled ? `Portal login: ${info.username}` : 'No portal login yet. The bot creates it when they ask for a password.'),
    password ? h('div', { class: 'uri mono', 'aria-label': 'New portal password' }, password) : null,
    password ? h('p', { class: 'small muted', style: 'margin:0' }, 'Shown only now. Earlier sign-ins of this login have ended.') : null,
    h('div', { class: 'row' }, h('button', { class: 'btn', onClick: async () => {
      try { const r = await withToast(api(url + '/password', { method: 'POST', body: {} }), 'New password issued'); info.enabled = true; info.username = r.username; showLogin(r.password); } catch (_) {}
    } }, 'New password'),
    info.enabled ? h('button', { class: 'btn danger', title: 'While a Telegram username is set, the bot gives them a new login when they ask', onClick: async () => {
      try { await withToast(api(url, { method: 'DELETE' }), 'Portal access disabled'); info.enabled = false; showLogin(); } catch (_) {}
    } }, 'Disable portal login') : null));
  showTelegram(); showLogin();
  dialog({ title: 'Telegram & portal · ' + name, body: h('div', { class: 'form' },
    h('p', null, 'The client gets profile links and their portal password from the Telegram bot. To cut them off, revoke the client; a disabled portal login comes back when they ask the bot.'),
    h('div', { class: 'row', style: 'align-items:flex-end' }, field('Telegram username', telegram),
      h('button', { class: 'btn', onClick: async () => {
        try { info = await withToast(api(`/api/clients/${encodeURIComponent(name)}/telegram`, { method: 'PUT', body: { username: telegram.value } }), 'Telegram username saved'); showTelegram(); } catch (_) {}
      } }, 'Save')),
    linkState, login),
    buttons: [{ label: 'Done', cls: 'primary', value: true }] });
}



/* ------------------------------------------------------------ dashboard */
// Traffic comes over OpenVPN and over the Apple relay; "bytes_*" is their sum.
const SOURCES = [['all', 'All'], ['vpn', 'OpenVPN'], ['relay', 'Apple relay']];
// A value of a traffic object ({bytes_in, bytes_out, vpn: {...}, relay: {...}}) or of a chart
// point ({bytes_in, vpn_in, relay_in, ...}) for one source. dir: "in" = upload, "out" = download.
function trafficOf(t, dir, src) {
  if (!t) return 0;
  if (!src || src === 'all') return t['bytes_' + dir] || 0;
  return (t[src] ? t[src]['bytes_' + dir] : t[`${src}_${dir}`]) || 0;
}
function splitText(t, dir) {
  return `OpenVPN ${fmtBytes(trafficOf(t, dir, 'vpn'))} · relay ${fmtBytes(trafficOf(t, dir, 'relay'))}`;
}
// "12.3 GB" with the OpenVPN / relay parts in small print when the relay carried some of it.
function trafficCell(t, dir) {
  return h('td', { class: 'r num', title: splitText(t, dir) }, fmtBytes(trafficOf(t, dir)),
    trafficOf(t, dir, 'relay') ? h('span', { class: 'split' }, `relay ${fmtBytes(trafficOf(t, dir, 'relay'))}`) : null);
}
function viaTag(s) {
  if (s.via !== 'relay') return h('span', { class: 'via-tag', title: s.proto === 'tcp' ? 'OpenVPN over the TCP fallback' : 'OpenVPN' }, 'OpenVPN' + (s.proto ? ' ' + s.proto : ''));
  const t = { http2: 'h2', http3: 'h3', 'http2+http3': 'h2 + h3' }[s.transport] || '';
  return h('span', { class: 'via-tag relay', title: 'Apple relay' + (t ? ' over ' + s.transport.replace(/http/g, 'HTTP/').replace('+', ' and ') : '') }, 'Relay' + (t ? ' ' + t : ''));
}

function dashboardView(el) {
  const sectionsBox = sectionsCard('/api/sections', { clients: true });
  let data = null, src = 'all';
  const sub = h('span', null, 'loading…');
  const body = h('div', { class: 'stack' });
  el.append(topbar('Dashboard', sub, rangeControl(load)), body);
  const liveTable = h('div');
  const throughputTile = h('div', { style: 'display:grid' }), onlineTile = h('div', { style: 'display:grid' });
  const sourceSeg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Traffic source' }, SOURCES.map(([v, label]) =>
    h('button', { class: v === src ? 'active' : '', onClick: e => { src = v; sourceSeg.querySelectorAll('button').forEach(b => b.classList.toggle('active', b === e.currentTarget)); draw(); } }, label)));
  let hourChart, rangeChart;

  function renderLiveTable(live) {
    const rows = [...live.clients.map(c => ({ via: 'vpn', name: c.cn, c })), ...(live.relay || []).map(c => ({ via: 'relay', name: c.client, c }))]
      .sort((a, b) => a.name.localeCompare(b.name) || a.via.localeCompare(b.via));
    if (!rows.length) {
      liveTable.replaceChildren(h('div', { class: 'empty' }, live.connected ? 'No clients connected' : ['OpenVPN is not reachable: ', live.error || '']));
      return;
    }
    const now = live.server_time || Math.floor(Date.now() / 1000);
    liveTable.replaceChildren(
      live.connected ? null : warnings(['OpenVPN is not reachable: ' + (live.error || 'not connected')]),
      h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, 'Client'), h('th', null, 'Via'), h('th', null, 'From'), h('th', null, 'VPN IP'), h('th', null, 'Connected'), h('th', { class: 'r' }, 'Download'), h('th', { class: 'r' }, 'Upload'), h('th', { class: 'r' }, 'Rate ↓ / ↑'), h('th', null))),
      h('tbody', null, rows.map(({ via, name, c }) => via === 'vpn' ? h('tr', null,
        h('td', { class: 'name-cell' }, h('a', { href: '#/clients/' + encodeURIComponent(name) }, h('span', { class: 'dot-live' }), name)),
        h('td', null, viaTag({ via: 'vpn', proto: addrParts(c.real_address)[1] })),
        fromCell(c),
        h('td', { class: 'mono small' }, c.vpn_ip || '—'),
        h('td', null, fmtDur(now - c.connected_since), h('span', { class: 'muted small' }, ' · ' + fmtTime(c.connected_since))),
        h('td', { class: 'r num' }, fmtBytes(c.bytes_out)), h('td', { class: 'r num' }, fmtBytes(c.bytes_in)),
        h('td', { class: 'r num small' }, fmtBits(c.rate_out) + ' / ' + fmtBits(c.rate_in)),
        h('td', { class: 'actions' }, h('button', { class: 'btn sm', onClick: async () => { if (await confirmDialog('Disconnect client', `Disconnect ${name}? The client will most likely reconnect automatically.`, 'Disconnect', true)) await withToast(api(`/api/clients/${encodeURIComponent(name)}/disconnect`, { method: 'POST', body: { cid: c.cid } }), 'Disconnect signal sent'); } }, 'Disconnect')))
        : h('tr', null,
        h('td', { class: 'name-cell' }, h('a', { href: '#/clients/' + encodeURIComponent(name) }, h('span', { class: 'dot-live' }), name)),
        h('td', null, viaTag({ via: 'relay' })),
        h('td', { class: 'small muted', colSpan: 3 }, `${fmtNum(c.active)} open connection${c.active === 1 ? '' : 's'} · ${c.tcp} TCP / ${c.udp} UDP · ${c.destinations} destination${c.destinations === 1 ? '' : 's'}`),
        h('td', { class: 'r num', title: 'Since the relay started' }, fmtBytes(c.bytes_down)), h('td', { class: 'r num', title: 'Since the relay started' }, fmtBytes(c.bytes_up)),
        h('td', { class: 'r num small' }, fmtBits(c.rate_down) + ' / ' + fmtBits(c.rate_up)),
        h('td', null)))))));
  }
  function renderLive(live) {
    const relay = live.relay || [], on = onlineClients(live);
    const down = live.rate_out + relay.reduce((n, c) => n + c.rate_down, 0), up = live.rate_in + relay.reduce((n, c) => n + c.rate_up, 0);
    throughputTile.replaceChildren(tile('Current throughput', [fmtBits(down), h('small', null, '↓')], `↑ ${fmtBits(up)} · OpenVPN and relay`));
    const vpn = [...on.values()].filter(v => v.vpn).length, rel = [...on.values()].filter(v => v.relay).length;
    onlineTile.replaceChildren(tile('Online now', [live.connected || live.relay_ready ? on.size : '—', data ? h('small', null, `of ${data.counts.valid}`) : null],
      `${vpn} OpenVPN${live.connected ? '' : ' (unreachable)'} · ${rel} relay${live.relay_ready ? '' : ' (unreachable)'}`));
    sub.textContent = (live.connected ? shortVer(live.version) || 'OpenVPN' : 'OpenVPN unreachable') + (data ? ` · ${data.counts.valid} valid client${data.counts.valid === 1 ? '' : 's'}` : '');
    renderLiveTable(live);
  }
  function draw() {
    if (!data) return;
    const t = data.totals, rl = rangeLabel(state.range), pick = (p, dir) => trafficOf(p, dir, src);
    const what = src === 'all' ? '' : ' · ' + SOURCES.find(x => x[0] === src)[1];
    const dl = data.series.map(p => pick(p, 'out')), ul = data.series.map(p => pick(p, 'in'));
    const hourOpts = { ts: data.hour.map(p => p.ts), series: [{ label: 'Download', cls: 's1', values: data.hour.map(p => pick(p, 'out') / 60) }, { label: 'Upload', cls: 's2', values: data.hour.map(p => pick(p, 'in') / 60) }], fmtY: fmtBits, fmtX: fmtTime, fmtXFull: ts => fmtTime(ts), height: 200, aria: 'Throughput in the last hour' };
    const bucket = data.bucket;
    const fmtX = bucket >= 86400 ? fmtDate : bucket >= 3600 ? ts => new Date(ts * 1000).toLocaleString([], { weekday: 'short', hour: '2-digit' }) : fmtTime;
    const rangeOpts = { ts: data.series.map(p => p.ts), series: [{ label: 'Download', cls: 's1', values: dl }, { label: 'Upload', cls: 's2', values: ul }], fmtY: v => fmtBytes(v, 0), fmtX, fmtXFull: bucket >= 86400 ? fmtDate : fmtDateTime, height: 220, aria: 'Traffic per ' + (bucket >= 86400 ? 'day' : bucket >= 3600 ? 'hour' : '10 minutes') };
    if (!body.children.length) {
      const hourEl = h('div'), rangeEl = h('div');
      body.append(
        h('div', { id: 'warnings' }),
        h('div', { class: 'grid kpi', id: 'kpi' }),
        h('div', { class: 'row', style: 'justify-content:space-between;flex-wrap:wrap' }, h('span', { class: 'small muted' }, 'Charts and top clients show'), sourceSeg),
        h('div', { class: 'grid two' }, h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', { id: 'hour-title' })), h('div', { class: 'card-b' }, hourEl)), h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', { id: 'top-title' })), h('div', { class: 'card-b', id: 'top' }))),
        h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', { id: 'range-title' })), h('div', { class: 'card-b' }, rangeEl)),
        sectionsBox.card,
        card('Connected clients', liveTable),
        h('div', { id: 'rej' }));
      hourChart = lineChart(hourEl, hourOpts); rangeChart = lineChart(rangeEl, rangeOpts);
    } else { hourChart.update(hourOpts); rangeChart.update(rangeOpts); }
    $('#hour-title', body).textContent = 'Throughput · last 60 minutes' + what;
    $('#top-title', body).textContent = 'Top clients · ' + rl + what;
    $('#range-title', body).textContent = 'Traffic · ' + rl + what;
    $('#warnings', body).replaceChildren(warnings(data.warnings) || '');
    const plural = (n, word) => `${fmtNum(n)} ${word}${n === 1 ? '' : 's'}`;
    $('#kpi', body).replaceChildren(
      onlineTile,
      tile('Active users · ' + rl, t.clients, `with traffic: ${t.vpn_clients} over OpenVPN, ${t.relay_clients} over the relay · ${plural(t.vpn_visits, 'OpenVPN visit')}, ${plural(t.relay_sessions, 'relay session')}`),
      tile('Download · ' + rl, fmtBytes(t.bytes_out), splitText(t, 'out'), sparkline(data.series.map(p => p.bytes_out).slice(-24))),
      tile('Upload · ' + rl, fmtBytes(t.bytes_in), splitText(t, 'in'), sparkline(data.series.map(p => p.bytes_in).slice(-24))),
      throughputTile);
    $('#top', body).replaceChildren(bars(data.top.map(c => ({ label: clientLabel(c.name), value: pick(c, 'in') + pick(c, 'out'), href: c.name.includes('#') ? null : '#/clients/' + encodeURIComponent(c.name), title: `↓ ${fmtBytes(pick(c, 'out'))} · ↑ ${fmtBytes(pick(c, 'in'))}` + (src === 'all' ? ` · of it relay ↓ ${fmtBytes(trafficOf(c, 'out', 'relay'))} ↑ ${fmtBytes(trafficOf(c, 'in', 'relay'))}` : '') })).filter(r => r.value > 0).sort((a, b) => b.value - a.value)));
    $('#rej', body).replaceChildren(data.rejections.length ? card('Rejected OpenVPN connection attempts · last 24 h', rejectionsTable(data.rejections, true)) : '');
  }
  async function load() {
    body.classList.add('loading');
    try {
      data = await api(`/api/overview?${rangeQuery()}`);
      sectionsBox.load();
    } catch (e) { toast(e.message, 'err'); body.classList.remove('loading'); return; }
    state.live = data.live;
    showPeriod(data);
    draw();
    renderLive(data.live);
    body.classList.remove('loading');
  }
  load();
  every(60000, load);
  return { onLive: live => { if (data) renderLive(live); } };
}

/* -------------------------------------------------------------- clients */
// A small menu under a button; it lives in <body>, so a scrolling table cannot cut it off.
function menuButton(label, items, cls) {
  let menu = null;
  const close = () => { if (menu) { menu.remove(); menu = null; document.removeEventListener('click', outside, true); window.removeEventListener('scroll', close, true); window.removeEventListener('resize', close); } };
  const outside = e => { if (menu && !menu.contains(e.target) && !button.contains(e.target)) close(); };
  const button = h('button', { class: 'btn ' + (cls || 'sm'), 'aria-haspopup': 'menu', onClick: () => {
    if (menu) { close(); return; }
    menu = h('div', { class: 'menu', role: 'menu', onClick: e => { if (e.target.closest('a,button')) setTimeout(close, 0); } }, items());
    document.body.append(menu);
    const r = button.getBoundingClientRect(), w = menu.offsetWidth, hgt = menu.offsetHeight;
    menu.style.left = Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8)) + 'px';
    menu.style.top = (r.bottom + hgt + 8 > window.innerHeight && r.top - hgt - 4 > 0 ? r.top - hgt - 4 : r.bottom + 4) + 'px';
    document.addEventListener('click', outside, true); window.addEventListener('scroll', close, true); window.addEventListener('resize', close);
  } }, label);
  return button;
}
// Traffic of the period in up to 24 steps (both directions together).
function sparkline(values) {
  const el = h('span', { class: 'spark' });
  const max = Math.max(0, ...(values || []));
  if (!max) { el.classList.add('flat'); el.title = 'No traffic in this period'; return el; }
  const n = values.length, W = 96, H = 24, x = i => n === 1 ? W / 2 : 1 + i * (W - 2) / (n - 1), y = v => H - 2 - (H - 5) * v / max;
  const points = values.map((v, i) => `${x(i).toFixed(1)},${y(Number(v) || 0).toFixed(1)}`);
  if (n === 1) points.push(`${(W / 2 + 6).toFixed(1)},${y(values[0]).toFixed(1)}`), points.unshift(`${(W / 2 - 6).toFixed(1)},${y(values[0]).toFixed(1)}`);
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" aria-hidden="true"><polygon class="area" points="${points[0].split(',')[0]},${H - 1} ${points.join(' ')} ${points[points.length - 1].split(',')[0]},${H - 1}"/><polyline class="line" points="${points.join(' ')}"/></svg>`;
  el.title = `Peak ${fmtBytes(max)} per step`;
  return el;
}
function clientsView(el) {
  const saved = (() => { try { return JSON.parse(localStorage.getItem('clients:view') || '{}') || {}; } catch (_) { return {}; } })();
  const FILTERS = [['all', 'All'], ['online', 'Online'], ['vpn', 'On OpenVPN'], ['relay', 'On relay'], ['valid', 'Valid'], ['expiring', 'Expiring'], ['revoked', 'Revoked']];
  const SORTS = ['default', 'name', 'expires', 'seen', 'dl', 'ul', 'sessions'];
  let rows = [], search = '', showInactive = false;
  let filter = FILTERS.some(f => f[0] === saved.filter) ? saved.filter : 'all';
  let sort = saved.sort && SORTS.includes(saved.sort.key) ? { key: saved.sort.key, asc: !!saved.sort.asc } : { key: 'default', asc: true };
  const selected = new Set();
  const remember = () => { try { localStorage.setItem('clients:view', JSON.stringify({ filter, sort })); } catch (_) {} };
  const phone = window.matchMedia('(max-width: 640px)');
  const table = h('div');
  const count = h('span');
  const bulk = h('div', { class: 'bulk-bar', hidden: true });
  const searchIn = h('input', { class: 'input search', placeholder: 'Search clients…', onInput: e => { search = e.target.value.toLowerCase(); draw(); } });
  const filters = h('div', { class: 'seg' });
  el.append(topbar('Clients', count, searchIn, rangeControl(load), h('button', { class: 'btn primary', onClick: () => newClientDialog(load) }, icon('plus'), 'New client')),
    h('div', { class: 'row', style: 'margin-bottom:12px' }, filters), bulk, h('section', { class: 'card' }, table));
  const onPhone = () => { if (table.isConnected) draw(); else phone.removeEventListener('change', onPhone); };
  phone.addEventListener('change', onPhone);

  const matches = {
    all: () => true, online: c => c.online, vpn: c => (c.online_via || []).includes('vpn'), relay: c => (c.online_via || []).includes('relay'),
    valid: c => c.state === 'valid', expiring: c => c.state === 'valid' && c.days_left !== null && c.days_left < 30,
    revoked: c => c.state === 'revoked' || c.state === 'expired' };
  const inactive = c => c.state !== 'valid';
  const enc = c => encodeURIComponent(c.name);

  function drawFilters() {
    filters.replaceChildren(...FILTERS.map(([k, l]) => {
      const n = rows.filter(matches[k]).length;
      return h('button', { class: k === filter ? 'active' : '', onClick: () => { filter = k; remember(); draw(); } }, l, k === 'all' ? null : h('span', { class: 'n' }, n));
    }));
  }
  function activity(c) {
    if (!c.online) return h('span', { title: c.total.last_seen ? 'Last seen ' + fmtDateTime(c.total.last_seen) : '' }, c.total.last_seen ? fmtAgo(c.total.last_seen) : 'never');
    const via = c.online_via || [], tags = [];
    if (via.includes('vpn')) {
      const protos = [...new Set((c.sessions_live || []).map(s => s.proto).filter(Boolean))];
      tags.push(h('span', { class: 'via-tag', title: `${(c.sessions_live || []).length} OpenVPN device(s) connected` }, 'OpenVPN' + (protos.length === 1 ? ' ' + protos[0] : '')));
    }
    if (via.includes('relay')) tags.push(h('span', { class: 'via-tag relay', title: c.relay_live ? `${fmtNum(c.relay_live.active)} open relay connections` : 'Apple relay' }, 'Relay'));
    return h('span', { class: 'activity' }, h('span', { class: 'ink2' }, h('span', { class: 'dot-live' }),
      c.online_since ? fmtDur(Date.now() / 1000 - c.online_since) : c.relay_live ? `${fmtNum(c.relay_live.active)} conn.` : 'now'), tags);
  }
  function badges(c) {
    return h('div', { class: 'row', style: 'gap:6px' }, stateBadge(c), c.tfa ? h('span', { class: 'badge plain', title: 'Two-factor authentication enabled' }, '2FA') : null,
      c.guest ? h('span', { class: 'subnet', title: 'Guest: internet and the personal portal, no LAN' }, 'guest') : c.static_ip ? h('span', { class: 'subnet', title: 'Static IP' }, c.static_ip) : null,
      c.previous ? h('span', { class: 'badge plain expiring', title: 'Previous certificate still valid' }, 'renewed') : null);
  }
  function topSection(c) {
    const t = c.top_section;
    if (!t) return null;
    return h('span', { class: 'split', title: 'The podkop section with the most traffic in this period' }, `${t.section === '' ? 'direct' : t.section === '?' ? 'section unknown' : t.section} ${Math.round(t.share * 100)}%`);
  }
  function download(c, cls) {
    if (c.state !== 'valid') return null;
    return menuButton([icon('download'), 'Download'], () => [
      h('a', { class: 'btn', role: 'menuitem', href: `/api/clients/${enc(c)}/ovpn`, download: c.name + '.ovpn' }, icon('download'), 'OpenVPN config'),
      relayButton(c),
      h('button', { class: 'btn', role: 'menuitem', onClick: () => shareDialog(c.name, c.relay_available, c.xray_available) }, 'Share link…')], cls);
  }
  function check(c) {
    return h('input', { type: 'checkbox', class: 'pick', checked: selected.has(c.name), 'aria-label': 'Select ' + c.name,
      onChange: e => { if (e.target.checked) selected.add(c.name); else selected.delete(c.name); drawBulk(); const all = table.querySelector('.pick-all'); if (all) all.checked = false; } });
  }
  async function each(names, label, call) {
    let done = 0; const failed = [];
    table.classList.add('loading');
    for (const name of names) {
      try { await call(name); done++; } catch (e) { failed.push(`${name}: ${e.message}`); }
    }
    table.classList.remove('loading');
    toast(failed.length ? `${label}: ${done} done, ${failed.length} failed (${failed[0]})` : `${label}: ${done} client${done === 1 ? '' : 's'}`, failed.length ? 'err' : 'ok');
    selected.clear(); load();
  }
  function drawBulk() {
    for (const name of [...selected]) if (!rows.some(c => c.name === name)) selected.delete(name);
    const picked = rows.filter(c => selected.has(c.name));
    bulk.hidden = !picked.length;
    if (!picked.length) return;
    const valid = picked.filter(c => c.state === 'valid'), live = picked.filter(c => c.state !== 'revoked');
    const access = guest => async () => {
      const list = valid.filter(c => c.guest !== guest).map(c => c.name);
      if (!list.length) { toast(guest ? 'They are guests already' : 'They have full access already', 'ok'); return; }
      if (await confirmDialog(guest ? 'Make guests' : 'Give full access', `${list.join(', ')}: ${guest ? 'the internet and the personal portal, no LAN' : 'the internet, your LAN and this server'}. Connected OpenVPN devices reconnect now, the relay follows within seconds.`, guest ? 'Make guests' : 'Give full access'))
        each(list, 'Access changed', name => api(`/api/clients/${encodeURIComponent(name)}/access`, { method: 'PUT', body: { guest } }));
    };
    bulk.replaceChildren(h('strong', null, `${picked.length} selected`),
      h('button', { class: 'btn sm', disabled: !valid.length, onClick: access(true) }, 'Make guest'),
      h('button', { class: 'btn sm', disabled: !valid.length, onClick: access(false) }, 'Give full access'),
      h('button', { class: 'btn sm danger', disabled: !live.length, onClick: async () => {
        const list = live.map(c => c.name);
        if (await confirmDialog('Revoke certificates', `${list.join(', ')} will be disconnected and can no longer connect, over OpenVPN or the relay. This cannot be undone.`, 'Revoke', true))
          each(list, 'Revoked', name => api(`/api/clients/${encodeURIComponent(name)}/revoke`, { method: 'POST', body: {} }));
      } }, 'Revoke'),
      h('button', { class: 'btn sm ghost', onClick: () => { selected.clear(); draw(); } }, 'Clear'));
  }

  const show = (...nodes) => table.replaceChildren(...nodes.filter(Boolean));
  function draw() {
    const rl = rangeLabel(state.range);
    drawFilters();
    let list = rows.filter(c => {
      if (search && !(c.name.toLowerCase().includes(search) || (c.note || '').toLowerCase().includes(search) || (c.static_ip || '').includes(search))) return false;
      return matches[filter](c);
    });
    const key = { name: c => c.name.toLowerCase(), expires: c => c.expires || 0, seen: c => c.online ? Infinity : c.total.last_seen || 0, dl: c => c.traffic.bytes_out, ul: c => c.traffic.bytes_in, sessions: c => c.total.sessions }[sort.key];
    if (key) list = list.slice().sort((a, b) => (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0) * (sort.asc ? 1 : -1));
    // Revoked and expired clients wait under one line, unless they are what was asked for.
    const fold = filter === 'all' && !search;
    const hiddenCount = fold ? list.filter(inactive).length : 0;
    if (fold && !showInactive) list = list.filter(c => !inactive(c));
    else if (fold) list = list.filter(c => !inactive(c)).concat(list.filter(inactive));
    count.textContent = `${rows.filter(c => c.state === 'valid').length} valid · ${rows.filter(c => c.online).length} online · ${rows.filter(c => c.traffic.bytes_in + c.traffic.bytes_out > 0).length} with traffic ${rl === 'all' ? 'ever' : rl} · ${rows.length} total`;
    drawBulk();
    const more = hiddenCount ? h('button', { class: 'fold', onClick: () => { showInactive = !showInactive; draw(); } },
      showInactive ? 'Hide revoked and expired' : `Show ${hiddenCount} inactive (revoked or expired)`) : null;
    if (!list.length) { show(h('div', { class: 'empty' }, rows.length ? (more ? 'No active clients' : 'No clients match') : 'No clients yet - create the first one'), more); return; }
    const open = c => e => { if (!e.target.closest('button,a,input,label')) go('#/clients/' + enc(c)); };
    if (phone.matches) {
      show(h('div', { class: 'client-cards' }, list.map(c => h('div', { class: 'client-card' + (inactive(c) ? ' inactive' : ''), onClick: open(c) },
        h('div', { class: 'cc-h' }, check(c), h('div', { class: 'name-cell' }, c.name, c.note ? h('span', { class: 'sub' }, c.note) : null), download(c)),
        h('div', { class: 'cc-b' }, badges(c), h('span', { class: 'small' }, activity(c))),
        h('div', { class: 'cc-t' }, sparkline(c.spark),
          h('span', { class: 'num', title: splitText(c.traffic, 'out') }, '↓ ' + fmtBytes(trafficOf(c.traffic, 'out'))),
          h('span', { class: 'num', title: splitText(c.traffic, 'in') }, '↑ ' + fmtBytes(trafficOf(c.traffic, 'in'))), topSection(c))))), more);
      return;
    }
    const th = (label, k, cls) => h('th', { class: (cls || '') + (k ? ' sortable' : '') + (sort.key === k ? ' sorted' + (sort.asc ? ' asc' : '') : ''), onClick: k ? () => { sort = { key: k, asc: sort.key === k ? !sort.asc : k === 'name' }; remember(); draw(); } : null }, label);
    const pickAll = h('input', { type: 'checkbox', class: 'pick pick-all', 'aria-label': 'Select all shown', checked: list.length > 0 && list.every(c => selected.has(c.name)),
      onChange: e => { list.forEach(c => e.target.checked ? selected.add(c.name) : selected.delete(c.name)); draw(); } });
    show(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl clients' },
      h('thead', null, h('tr', null, h('th', { class: 'pick-cell' }, pickAll), th('Name', 'name'), th('Status'), th('Expires', 'expires'), th('Activity', 'seen'),
        th('Traffic · ' + rl), th('Download', 'dl', 'r'), th('Upload', 'ul', 'r'), th('Sessions', 'sessions', 'r'), h('th', null))),
      h('tbody', null, list.map(c => h('tr', { class: 'clickable' + (inactive(c) ? ' inactive' : '') + (selected.has(c.name) ? ' picked' : ''), onClick: open(c) },
        h('td', { class: 'pick-cell' }, check(c)),
        h('td', { class: 'name-cell' }, c.name, c.note ? h('span', { class: 'sub' }, c.note) : null),
        h('td', null, badges(c)),
        h('td', { class: 'num' }, c.expires ? [fmtDate(c.expires), h('span', { class: 'muted small' }, ' · ' + fmtDays(c.days_left))] : '—'),
        h('td', null, activity(c)),
        h('td', { class: 'spark-cell' }, sparkline(c.spark), topSection(c)),
        trafficCell(c.traffic, 'out'), trafficCell(c.traffic, 'in'),
        h('td', { class: 'r num', title: `All time: ${fmtNum(c.total.vpn_visits)} OpenVPN visits (${fmtNum(c.total.vpn_connections)} connections) · ${fmtNum(c.total.relay_sessions)} relay sessions` }, fmtNum(c.total.sessions)),
        h('td', { class: 'actions' }, download(c))))))), more);
  }
  async function load() {
    table.classList.add('loading');
    try { const r = await api(`/api/clients?${rangeQuery()}`); rows = r.clients; showPeriod(r); draw(); } catch (e) { toast(e.message, 'err'); }
    table.classList.remove('loading');
  }
  load();
  every(30000, load);
  return { onLive: live => {
    const on = onlineClients(live); let changed = false;
    rows.forEach(r => {
      const v = on.get(r.name), via = v ? ['vpn', 'relay'].filter(k => v[k]) : [];
      if (via.join() !== (r.online_via || []).join()) { r.online = via.length > 0; r.online_via = via; changed = true; }
    });
    if (changed) draw();
  } };
}

function newClientDialog(after) {
  const name = h('input', { class: 'input', placeholder: 'e.g. alice-laptop', pattern: '[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}', required: true, autofocus: true });
  const days = h('input', { class: 'input', type: 'number', min: 1, max: 3650, placeholder: 'default from easy-rsa vars' });
  const ip = h('input', { class: 'input' });
  let guest = false;
  const accessHelp = h('div', { class: 'help' });
  const access = h('div', { class: 'seg', role: 'group', 'aria-label': 'Access', style: 'align-self:flex-start' });
  const setAccess = g => {
    guest = g;
    access.querySelectorAll('button').forEach((b, i) => b.classList.toggle('active', (i === 1) === g));
    accessHelp.textContent = g ? 'The internet and the personal portal (password, profile downloads): no LAN, not this server or other VPN clients.' : 'Internet, your LAN and this server.';
    ip.disabled = g;
    if (g) ip.value = '';
    ip.placeholder = g ? 'a free guest address per device' : 'optional - dynamic if empty';
  };
  access.append(h('button', { type: 'button', onClick: () => setAccess(false) }, 'Full access'), h('button', { type: 'button', onClick: () => setAccess(true) }, 'Guest'));
  setAccess(false);
  const pass = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', placeholder: 'optional' });
  const note = h('input', { class: 'input', placeholder: 'optional' });
  const tfa = h('input', { type: 'checkbox' });
  const body = h('div', { class: 'form cols' },
    h('div', { class: 'full' }, field('Client name', name, 'Letters, digits, _ . @ - (becomes the certificate common name)')),
    h('div', { class: 'full field' }, h('label', null, 'Access'), access, accessHelp),
    field('Validity (days)', days), field('Static IP', ip),
    field('Key passphrase', pass, 'Encrypts the private key inside the profile'), field('Note', note),
    h('label', { class: 'check full' }, tfa, 'Require a TOTP code (two-factor authentication)'));
  dialog({ title: 'New client', body, buttons: [{ label: 'Cancel', value: null }, { label: 'Create', cls: 'primary', onClick: async () => {
    if (!name.checkValidity()) { name.reportValidity(); return false; }
    try {
      const r = await api('/api/clients', { method: 'POST', body: { name: name.value.trim(), days: days.value ? Number(days.value) : null, passphrase: pass.value || null, static_ip: ip.value.trim() || null, guest, tfa: tfa.checked, note: note.value } });
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
  let src = 'all', dailyChart = null, redrawDaily = () => {};
  const sourceSeg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Traffic source' }, SOURCES.map(([v, label]) =>
    h('button', { class: v === src ? 'active' : '', onClick: e => { src = v; sourceSeg.querySelectorAll('button').forEach(b => b.classList.toggle('active', b === e.currentTarget)); redrawDaily(); } }, label)));
  const flowsCard = relayFlowsCard(name);
  const sectionsBox = sectionsCard(`/api/clients/${enc}/sections`, { period: true });

  async function load() {
    body.classList.add('loading');
    try { c = await api(`/api/clients/${enc}?tz=${TZ}`); } catch (e) { toast(e.message, 'err'); body.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
    setChildren(badges, stateBadge(c), c.tfa ? h('span', { class: 'badge plain' }, '2FA') : null, c.guest ? h('span', { class: 'subnet' }, 'guest') : c.static_ip ? h('span', { class: 'subnet' }, 'static ' + c.static_ip) : null, c.previous ? h('span', { class: 'badge plain expiring' }, 'renewed · previous cert still valid') : null);
    setChildren(actions, 
      c.state === 'valid' ? h('a', { class: 'btn primary', href: `/api/clients/${enc}/ovpn`, download: name + '.ovpn' }, icon('download'), 'OpenVPN config') : null,
      c.state === 'valid' ? relayButton(c) : null,
      c.state === 'valid' ? act('Telegram & portal', () => portalAccessDialog(name)) : null,
      c.relay_available ? act('Revoke relay access', async () => { if (await confirmDialog('Revoke relay access', 'Installed Apple relay profiles will stop working. Download a new profile to enable access again.', 'Revoke', true)) { await withToast(api(`/api/clients/${enc}/relay`, { method: 'DELETE' }), 'Relay access revoked'); load(); } }, 'danger') : null,
      c.online ? act('Disconnect', async () => { if (await confirmDialog('Disconnect', `Disconnect all sessions of ${name}?`, 'Disconnect', true)) { await withToast(api(`/api/clients/${enc}/disconnect`, { method: 'POST', body: {} }), 'Disconnected'); } }) : null,
      c.state === 'valid' ? act(c.tfa ? 'Show 2FA code' : 'Enable 2FA', async () => {
        if (c.tfa) { tfaDialog(name, c.tfa_uri); return; }
        if (await confirmDialog('Enable two-factor authentication', 'A new TOTP secret will be generated and "auth-user-pass" added to the profile. Re-deliver the profile afterwards. Note: 2FA is only checked when it is enforced on the Server page.', 'Enable')) {
          const r = await withToast(api(`/api/clients/${enc}/tfa`, { method: 'POST', body: { enabled: true } }), '2FA enabled'); tfaDialog(name, r.tfa_uri); load();
        } }) : null,
      c.state === 'valid' && c.tfa ? act('Disable 2FA', async () => { if (await confirmDialog('Disable 2FA', `Remove the TOTP secret of ${name}?`, 'Disable', true)) { await withToast(api(`/api/clients/${enc}/tfa`, { method: 'POST', body: { enabled: false } }), '2FA disabled'); load(); } }) : null,
      c.state === 'valid' ? act('Share link', () => shareDialog(name, c.relay_available, c.xray_available)) : null,
      c.state === 'valid' && !c.guest ? act('Static IP', () => staticIpDialog(c, load)) : null,
      c.state !== 'revoked' && !c.previous ? act('Renew', async () => { if (await confirmDialog('Renew certificate', 'A new certificate is issued for the same key. The previous certificate stays valid until you revoke it, so the client keeps working while you deliver the new profile.', 'Renew')) { await withToast(api(`/api/clients/${enc}/renew`, { method: 'POST', body: {} }), 'Certificate renewed'); load(); } }) : null,
      c.previous ? act('Revoke previous cert', async () => { if (await confirmDialog('Revoke previous certificate', 'The old certificate will be added to the CRL. Make sure the client already uses the new profile.', 'Revoke', true)) { await withToast(api(`/api/clients/${enc}/revoke-previous`, { method: 'POST' }), 'Previous certificate revoked'); load(); } }, 'danger') : null,
      c.state !== 'revoked' ? act('Revoke', async () => { if (await confirmDialog('Revoke certificate', `${name} will be disconnected and can no longer connect. This cannot be undone.`, 'Revoke', true)) { await withToast(api(`/api/clients/${enc}/revoke`, { method: 'POST', body: {} }), 'Certificate revoked'); load(); } }, 'danger') : null,
      c.state === 'revoked' ? act('Delete', async () => { if (await confirmDialog('Delete client', `Remove the profile, static IP and 2FA data of ${name}? Traffic history is kept.`, 'Delete', true)) { await withToast(api(`/api/clients/${enc}`, { method: 'DELETE' }), 'Client deleted'); go('#/clients'); } }, 'danger') : null);

    const cert = c.cert, t = c.total;
    const accessSeg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Access' }, [['Full access', false], ['Guest', true]].map(([label, g]) =>
      h('button', { class: c.guest === g ? 'active' : '', disabled: c.state !== 'valid', onClick: async () => {
        if (c.guest === g) return;
        const text = g ? `${name} will reach the internet and the personal portal: no LAN, not this server or other VPN clients.` : `${name} will reach the internet, your LAN and this server.`;
        if (await confirmDialog(g ? 'Make guest' : 'Give full access', text + ' The same rule applies to OpenVPN and the relay: connected OpenVPN devices reconnect now, the relay follows within seconds.', g ? 'Make guest' : 'Give full access')) {
          await withToast(api(`/api/clients/${enc}/access`, { method: 'PUT', body: { guest: g } }), 'Access changed'); load();
        } } }, label)));
    const kv = (pairs) => h('dl', { class: 'kv' }, pairs.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
    const dailyEl = h('div');
    sourceSeg.querySelectorAll('button').forEach((b, i) => b.classList.toggle('active', SOURCES[i][0] === src));
    const noteIn = h('textarea', { class: 'input', style: 'min-height:60px', placeholder: 'Notes about this client…' }, c.note || '');
    body.replaceChildren(
      h('div', { class: 'grid kpi' },
        tile('Download · total', fmtBytes(t.bytes_out), splitText(t, 'out')), tile('Upload · total', fmtBytes(t.bytes_in), splitText(t, 'in')),
        tile('Sessions', fmtNum(t.sessions), `${fmtNum(t.vpn_visits)} OpenVPN visits (${fmtNum(t.vpn_connections)} connections) · ${fmtNum(t.relay_sessions)} relay sessions`),
        tile(c.online ? 'Online now' : 'Last seen', c.online ? viaLabel({ vpn: c.online_via.includes('vpn'), relay: c.online_via.includes('relay') }) : fmtAgo(t.last_seen),
          (t.first_seen ? 'first seen ' + fmtDate(t.first_seen) : 'never connected') + (t.online_seconds ? ` · ${fmtDur(t.online_seconds)} on OpenVPN` : ''))),
      h('div', { class: 'grid two' },
        h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Traffic · last 30 days'), sourceSeg), h('div', { class: 'card-b' }, dailyEl)),
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
            ['Access', accessSeg],
            ['Address', c.guest ? 'a free guest address per device' : c.static_ip ? `static ${c.static_ip} (first device; others get a dynamic one)` : 'dynamic'],
            ['2FA', c.tfa ? 'enabled' : 'off'],
          ].filter(Boolean))),
          card('Note', h('div', { class: 'stack', style: 'gap:8px' }, noteIn, h('div', null, h('button', { class: 'btn sm', onClick: () => withToast(api(`/api/clients/${enc}/note`, { method: 'PUT', body: { note: noteIn.value } }), 'Note saved') }, 'Save note')))))),
      c.rejections.length ? card('Rejected OpenVPN connection attempts · last 30 days', rejectionsTable(c.rejections, false)) : '',
      sectionsBox.card,
      card('Sessions · last 100', sessionsTable(c.sessions, false), h('a', { class: 'btn sm', href: '#/sessions/' + enc }, 'Every session')),
      c.relay_available || c.xray_available ? relayDevicesCard(name) : '',
      flowsCard);
    sectionsBox.load();
    const dailyOpts = () => ({ ts: c.daily.map(p => p.ts), series: [{ label: 'Download', cls: 's1', values: c.daily.map(p => trafficOf(p, 'out', src)) }, { label: 'Upload', cls: 's2', values: c.daily.map(p => trafficOf(p, 'in', src)) }], fmtY: v => fmtBytes(v, 0), fmtX: fmtDate, fmtXFull: fmtDate, height: 220, aria: 'Daily traffic' });
    dailyChart = lineChart(dailyEl, dailyOpts());
    redrawDaily = () => dailyChart.update(dailyOpts());
    body.classList.remove('loading');
  }
  load();
  return { onLive: live => { if (!c) return; const v = onlineClients(live).get(name), via = v ? ['vpn', 'relay'].filter(k => v[k]) : []; if (via.join() !== (c.online_via || []).join()) load(); } };
}
// The client's configs: device-bound Apple relay profiles and Xray keys, which share one
// number per client, and the older unbound relay profiles (one shared credential, not counted).
function xrayKeyDialog(name, r) {
  const box = h('div', { class: 'code' }, h('img', { src: 'data:image/svg+xml;base64,' + btoa(r.qr_svg), alt: 'QR code of the key' }));
  dialog({ title: `Xray key · ${name}`, body: h('div', { class: 'stack', style: 'gap:10px' },
    h('textarea', { class: 'input mono', readonly: true, rows: 5, 'aria-label': 'Xray key', onFocus: e => e.target.select() }, r.link),
    h('div', { class: 'qr' }, box),
    h('p', { class: 'small muted', style: 'margin:0' }, 'One key per device. Xray gives internet access only, not the LAN.')),
    buttons: [{ label: 'Copy', onClick: async () => { await navigator.clipboard.writeText(r.link); toast('Key copied', 'ok'); return false; } }, { label: 'Done', cls: 'primary', value: true }] });
}
function relayDevicesCard(name) {
  const enc = encodeURIComponent(name);
  const body = h('div', null, h('div', { class: 'small muted' }, 'Loading…'));
  const STATE = { active: 'installed', waiting: 'downloaded, not installed yet', expired: 'never installed (expired)', revoked: 'revoked' };
  const table = (heads, rows) => h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
    h('thead', null, h('tr', null, heads.map(t => h('th', null, t)))), h('tbody', null, rows)));
  async function load() {
    let r;
    try { r = await api(`/api/clients/${enc}/relay-devices`); } catch (e) { body.replaceChildren(h('div', { class: 'small muted' }, e.message)); return; }
    const devices = r.devices.filter(d => d.state !== 'expired').map(d => h('tr', null,
      h('td', null, 'Apple relay'), h('td', { class: 'mono small' }, d.id),
      h('td', null, h('span', { class: 'badge ' + (d.state === 'active' ? 'valid' : d.state === 'revoked' ? 'revoked' : 'plain') }, STATE[d.state])),
      h('td', null, fmtDateTime(d.enrolled_at || d.created_at)),
      h('td', null, d.last_seen ? fmtAgo(d.last_seen) : '—'),
      h('td', null, d.state === 'active' || d.state === 'waiting' ? h('button', { class: 'btn sm danger', onClick: async () => {
        if (await confirmDialog('Remove device', `The relay stops working on this device of ${name} (${d.id}).`, 'Remove', true)) {
          await withToast(api(`/api/clients/${enc}/relay-devices/${encodeURIComponent(d.id)}`, { method: 'DELETE' }), 'Device removed'); load();
        } } }, 'Remove') : '')));
    const keys = r.xray_keys.map(k => h('tr', null,
      h('td', null, 'Xray'), h('td', { class: 'mono small' }, k.id), h('td', null, h('span', { class: 'badge valid' }, 'issued')),
      h('td', null, fmtDateTime(k.created_at)), h('td', null, '—'),
      h('td', null, h('div', { class: 'row', style: 'gap:6px' },
        h('button', { class: 'btn sm', onClick: async () => { try { xrayKeyDialog(name, await api(`/api/clients/${enc}/xray-keys/${encodeURIComponent(k.id)}`)); } catch (e) { toast(e.message, 'err'); } } }, 'Show'),
        h('button', { class: 'btn sm danger', onClick: async () => {
          if (await confirmDialog('Remove Xray key', `The key ${k.id} stops working.`, 'Remove', true)) {
            await withToast(api(`/api/clients/${enc}/xray-keys/${encodeURIComponent(k.id)}`, { method: 'DELETE' }), 'Key removed'); load();
          } } }, 'Remove')))));
    const own = h('input', { class: 'input', type: 'number', min: 0, max: 100, style: 'width:6rem', placeholder: String(r.default_limit), value: r.own_limit === null ? '' : r.own_limit, 'aria-label': 'Configs for this client' });
    body.replaceChildren(
      h('div', { class: 'row', style: 'gap:10px;align-items:center;margin-bottom:10px;flex-wrap:wrap' },
        h('span', null, `${r.used} of ${r.limit} configs in use`),
        h('span', { class: 'small muted' }, 'Apple relay devices and Xray keys together. For this client:'),
        own,
        h('button', { class: 'btn sm', onClick: async () => { await withToast(api(`/api/clients/${enc}/config-limit`, { method: 'PUT', body: { limit: own.value === '' ? null : Number(own.value) } }), 'Saved'); load(); } }, 'Save'),
        r.xray ? h('button', { class: 'btn sm primary', onClick: async () => { try { const k = await api(`/api/clients/${enc}/xray-keys`, { method: 'POST', body: {} }); load(); xrayKeyDialog(name, k); } catch (e) { toast(e.message, 'err'); } } }, 'New Xray key') : ''),
      r.bound ? '' : h('p', { class: 'small muted', style: 'margin:0 0 10px' }, 'New Apple relay profiles are not bound to a device and are not counted (Settings → Apple relay).'),
      devices.length || keys.length ? table(['Type', 'Config', 'State', 'Since', 'Last seen', ''], [...devices, ...keys]) : '',
      r.shared ? h('div', { class: 'row', style: 'margin-top:10px;gap:10px;align-items:center' },
        h('span', { class: 'small' }, 'Apple relay profiles without device binding (one shared credential, works on any device): active.'),
        h('button', { class: 'btn sm danger', onClick: async () => {
          if (await confirmDialog('Revoke unbound profiles', `Every relay profile of ${name} without device binding stops working. Device-bound profiles keep working.`, 'Revoke', true)) {
            await withToast(api(`/api/clients/${enc}/relay-shared`, { method: 'DELETE' }), 'Unbound profiles revoked'); load();
          } } }, 'Revoke')) : '');
  }
  load();
  return card('Configs · Apple relay devices and Xray keys', body);
}
// The client's Apple relay connections: the open ones, then the saved log with its destinations.
function relayFlowsCard(name) {
  const LIMIT = 25;
  let offset = 0, q = '', loading = false;
  const live = h('div'), table = h('div'), pager = h('div', { class: 'row', style: 'justify-content:flex-end;padding-top:10px' });
  const note = h('p', { class: 'small muted', style: 'margin:10px 0 0' });
  const search = h('input', { class: 'input search', placeholder: 'Filter by destination', 'aria-label': 'Filter relay connections by destination', onChange: e => { q = e.target.value.trim(); offset = 0; load(); } });
  const reason = value => (value || '').replace(/_/g, ' ');
  const rowsTable = (rows, open) => h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
    h('thead', null, h('tr', null, [open ? 'Opened' : 'Ended', 'Protocol', 'Destination', 'Result', 'Duration'].map(t => h('th', null, t)), h('th', { class: 'r' }, 'Download'), h('th', { class: 'r' }, 'Upload'))),
    h('tbody', null, rows.map(r => h('tr', null,
      h('td', { class: 'num nowrap' }, fmtDateTime(r.ts)),
      h('td', { class: 'small' }, r.protocol || '—', r.transport ? h('span', { class: 'muted' }, ' · ' + ({ http2: 'h2', http3: 'h3' }[r.transport] || r.transport)) : null),
      h('td', { class: 'mono small' }, r.target || '—'),
      h('td', { class: 'small' }, open ? h('span', { class: 'ink2' }, h('span', { class: 'dot-live' }), 'open') : r.kind === 'closed' && r.reason === 'connection_closed' ? 'ok' : [r.kind === 'closed' ? 'ended' : r.kind, h('span', { class: 'muted' }, ' · ' + reason(r.reason) + (r.upstream_error ? ' · ' + reason(r.upstream_error) : ''))]),
      h('td', null, fmtDur(r.duration_ms / 1000)),
      h('td', { class: 'r num' }, fmtBytes(r.bytes_down)), h('td', { class: 'r num' }, fmtBytes(r.bytes_up)))))));
  async function load() {
    if (loading) return;
    loading = true;
    try {
      const r = await api(`/api/clients/${encodeURIComponent(name)}/relay-flows?limit=${LIMIT}&offset=${offset}&q=${encodeURIComponent(q)}`);
      const text = q.toLowerCase(), open = r.active.filter(f => !text || (f.target || '').toLowerCase().includes(text)).sort((a, b) => b.ts - a.ts);
      live.replaceChildren(open.length ? h('div', { class: 'stack', style: 'gap:6px;margin-bottom:14px' }, h('strong', null, `${fmtNum(open.length)} open now`), rowsTable(open, true)) : '');
      table.replaceChildren(r.flows.length ? rowsTable(r.flows, false) : h('div', { class: 'empty' }, q ? 'No saved connection matches' : 'No relay connections in the last ' + r.retention_days + ' days'));
      pager.replaceChildren(h('span', { class: 'muted small' }, r.total ? `${offset + 1}–${Math.min(offset + LIMIT, r.total)} of ${fmtNum(r.total)}` : ''),
        h('button', { class: 'btn sm', disabled: offset === 0, onClick: () => { offset = Math.max(0, offset - LIMIT); load(); } }, 'Newer'),
        h('button', { class: 'btn sm', disabled: offset + LIMIT >= r.total, onClick: () => { offset += LIMIT; load(); } }, 'Older'));
      note.textContent = `Finished connections are kept for ${r.retention_days} days` + (r.ready ? '.' : '. The relay is not reachable now, so open connections are not shown.');
    } catch (e) { table.replaceChildren(h('div', { class: 'empty' }, e.message)); }
    finally { loading = false; }
  }
  load(); every(15000, () => { if (offset === 0) load(); });
  return card('Relay connections · last 7 days', h('div', null, live, table, pager, note), search, h('button', { class: 'btn sm', title: 'Refresh', onClick: load }, icon('refresh')));
}
// History of an earlier certificate with the same name is stored as "name#time".
function clientLabel(key) { return key.includes('#') ? key.split('#')[0] + ' (earlier)' : key; }
function rejectionsTable(list, withName) {
  return h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
    h('thead', null, h('tr', null, withName ? h('th', null, 'Client') : null, h('th', null, 'Reason'), h('th', null, 'From'), h('th', { class: 'r' }, 'Attempts'), h('th', null, 'Last'))),
    h('tbody', null, list.map(r => h('tr', null,
      withName ? h('td', null, r.client || h('span', { class: 'muted' }, 'unknown')) : null,
      h('td', null, r.reason), h('td', { class: 'mono small' }, r.address), h('td', { class: 'r num' }, fmtNum(r.count)), h('td', { class: 'num' }, fmtAgo(r.last_ts)))))));
}
function shareDialog(name, relayAvailable, xrayAvailable) {
  const hours = h('select', { class: 'input' }, [['1', '1 hour'], ['24', '24 hours'], ['168', '7 days']].map(([v, l]) => h('option', { value: v, selected: v === '24' }, l)));
  const kind = h('select', { class: 'input' }, [['openvpn', 'OpenVPN', true], ['relay', 'Apple relay', relayAvailable], ['xray', 'Xray', xrayAvailable]].filter(o => o[2]).map(([v, l]) => h('option', { value: v }, l)));
  const out = h('div', { class: 'stack', style: 'gap:10px' });
  const copy = (text, what) => navigator.clipboard.writeText(text).then(() => toast(what + ' copied', 'ok'), () => toast('Copying needs HTTPS - select the link instead', 'err'));
  const make = async () => {
    let r;
    try { r = await api(`/api/clients/${encodeURIComponent(name)}/share`, { method: 'POST', body: { hours: Number(hours.value), kind: kind.value } }); } catch (e) { toast(e.message, 'err'); return; }
    out.replaceChildren(h('div', { class: 'qr' }, h('div', { class: 'code' }, h('img', { src: 'data:image/svg+xml;base64,' + btoa(r.qr_svg), alt: 'QR code of the link' })),
      h('div', { class: 'stack', style: 'flex:1;min-width:220px;gap:8px' },
        h('p', { style: 'margin:0' }, `${{ relay: 'Scan it with the camera of the iPhone or iPad: Safari offers the relay profile.', xray: 'Scan it with the phone camera: the page shows the Xray key once.', openvpn: 'Scan it with the phone camera: OpenVPN Connect imports the profile.' }[r.kind]} Or send the link: it opens a page that offers the profile, so a messenger's link preview does not use it up. The profile can be fetched once; the link expires ${fmtDateTime(r.expires_at)}.`),
        h('div', { class: 'uri mono muted' }, r.url),
        h('div', { class: 'row' }, h('button', { class: 'btn sm', onClick: () => copy(r.url, 'Link') }, 'Copy link'), r.import_url ? h('button', { class: 'btn sm', onClick: () => copy(r.import_url, 'Import link') }, 'Copy import link') : null))),
      r.public ? '' : warnings(['No website hostname is set in Settings → Network (nor OVPN_PROFILE_BASE_URL), so the link uses this admin address and only works where that is reachable.']));
  };
  dialog({ title: `Share profile · ${name}`, wide: true, body: h('div', { class: 'stack' },
    h('div', { class: 'row', style: 'align-items:flex-end' }, relayAvailable || xrayAvailable ? field('Profile', kind) : null, field('Valid for', hours), h('button', { class: 'btn primary', onClick: make }, 'Create link')), out),
    buttons: [{ label: 'Done', cls: 'primary', value: true }] });
}
function staticIpDialog(c, after) {
  const ip = h('input', { class: 'input', value: c.static_ip || '', placeholder: 'leave empty for a dynamic address' });
  dialog({ title: 'Static IP · ' + c.name, body: h('div', { class: 'form' }, field('IPv4 address', ip, `An address of the VPN subnet outside the dynamic pool and outside the guest range ${state.user.guest_sub}. The first device of this client to connect gets it. Applies on the next connection.`)),
    buttons: [{ label: 'Cancel', value: null }, { label: 'Save', cls: 'primary', onClick: async () => { try { await api(`/api/clients/${encodeURIComponent(c.name)}/static-ip`, { method: 'PUT', body: { ip: ip.value.trim() || null } }); toast('Static IP saved', 'ok'); after(); return true; } catch (e) { toast(e.message, 'err'); return false; } } }] });
}
function sessionsTable(list, withName) {
  if (!list.length) return h('div', { class: 'empty' }, 'No sessions recorded');
  const nameCell = s => h('td', { class: 'name-cell' }, s.client_name.includes('#') ? h('span', { class: 'muted', title: 'An earlier certificate with this name' }, clientLabel(s.client_name)) : h('a', { href: '#/clients/' + encodeURIComponent(s.client_name) }, s.client_name));
  const open = s => s.via === 'relay' ? s.state !== 'ended' : !s.disconnected_at;
  return h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
    h('thead', null, h('tr', null, withName ? h('th', null, 'Client') : null, h('th', null, 'Via'), h('th', null, 'Connected'), h('th', null, 'Duration'), h('th', null, 'From'), h('th', null, 'VPN IP'), h('th', null, 'Device'), h('th', { class: 'r' }, 'Download'), h('th', { class: 'r' }, 'Upload'))),
    h('tbody', null, list.map(s => s.via === 'relay' ? h('tr', null,
      withName ? nameCell(s) : null, h('td', null, viaTag(s)),
      h('td', { class: 'num' }, fmtDateTime(s.connected_at)),
      h('td', null, s.state === 'active' ? h('span', { class: 'ink2' }, h('span', { class: 'dot-live' }), fmtDur(Date.now() / 1000 - s.connected_at)) : fmtDur(s.last_seen - s.connected_at),
        s.state === 'idle' ? h('span', { class: 'muted small', title: 'No open connection; a new session starts after five minutes without one' }, ' · idle') : null),
      // The relay sits behind the gateway: it sees no client address and no device.
      h('td', { class: 'small muted', colSpan: 3 }, `${fmtNum(s.connections)} connection${s.connections === 1 ? '' : 's'}${s.open ? ` · ${fmtNum(s.open)} open` : ''}${s.denied || s.failed ? ` · ${fmtNum(s.denied)} blocked, ${fmtNum(s.failed)} failed` : ''}`),
      h('td', { class: 'r num' }, fmtBytes(s.bytes_out)), h('td', { class: 'r num' }, fmtBytes(s.bytes_in)))
      : h('tr', null,
      withName ? nameCell(s) : null, h('td', null, viaTag(s)),
      h('td', { class: 'num' }, fmtDateTime(s.connected_at)),
      h('td', null, !open(s) ? fmtDur(s.disconnected_at - s.connected_at) : h('span', { class: 'ink2' }, h('span', { class: 'dot-live' }), fmtDur(Date.now() / 1000 - s.connected_at)),
        // a visit: several connections of one client from one address, merged
        s.connections > 1 ? h('span', { class: 'muted small', title: 'Reconnects from the same address, at most 15 minutes apart' }, ` · ${fmtNum(s.connections)} connections, ${fmtDur(s.online_seconds)} online`) : null,
        s.disconnected_at && s.end_reason ? h('span', { class: 'muted small' }, ' · ' + s.end_reason) : null),
      fromCell({ ...s, proto: null }), h('td', { class: 'mono small' }, s.vpn_ip || '—'), deviceCell(s),
      h('td', { class: 'r num' }, fmtBytes(s.bytes_out)), h('td', { class: 'r num' }, fmtBytes(s.bytes_in)))))));
}

/* ------------------------------------------------------------- sessions */
function sessionsView(el) {
  let offset = 0, total = 0, name = state.route.param || '', active = false, merge = !name, via = 'all';
  const LIMIT = 100;
  const table = h('div');
  const pager = h('div', { class: 'row', style: 'justify-content:flex-end;padding:10px 16px' });
  const nameIn = h('input', { class: 'input search', value: name, placeholder: 'Filter by client name', onChange: e => { name = e.target.value.trim(); offset = 0; load(); } });
  const activeIn = h('label', { class: 'check' }, h('input', { type: 'checkbox', onChange: e => { active = e.target.checked; offset = 0; load(); } }), 'Active only');
  const mergeIn = h('label', { class: 'check', title: 'Show the OpenVPN reconnects of one client from one address, at most 15 minutes apart, as one visit' }, h('input', { type: 'checkbox', checked: merge, onChange: e => { merge = e.target.checked; offset = 0; load(); } }), 'Merge reconnects');
  const viaSeg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Connection type' }, [['all', 'All'], ['vpn', 'OpenVPN'], ['relay', 'Apple relay']].map(([v, label]) =>
    h('button', { class: v === via ? 'active' : '', onClick: e => { via = v; offset = 0; viaSeg.querySelectorAll('button').forEach(b => b.classList.toggle('active', b === e.currentTarget)); load(); } }, label)));
  const count = h('span');
  const quality = h('div');
  const qualityTitle = h('h2', null, 'OpenVPN connection quality');
  el.append(topbar('Sessions', count, nameIn, viaSeg, activeIn, mergeIn, h('button', { class: 'btn', onClick: () => { load(); loadQuality(); } }, icon('refresh'), 'Refresh')),
    h('div', { class: 'stack' }, h('section', { class: 'card' }, table, pager), h('section', { class: 'card' }, h('div', { class: 'card-h' }, qualityTitle, rangeControl(loadQuality)), h('div', { class: 'card-b' }, quality))));
  async function loadQuality() {
    qualityTitle.textContent = 'OpenVPN connection quality · ' + rangeLabel(state.range);
    let rows;
    try { const r = await api(`/api/connections?${rangeQuery()}`); rows = r.clients; showPeriod(r); } catch (e) { toast(e.message, 'err'); return; }
    if (!rows.length) { quality.replaceChildren(h('div', { class: 'empty' }, 'No OpenVPN sessions in this period')); return; }
    const n = (v, of) => h('td', { class: 'r num' }, v ? fmtNum(v) : h('span', { class: 'muted' }, '0'), v && of ? h('span', { class: 'muted small' }, ` ${Math.round(v / of * 100)}%`) : null);
    quality.replaceChildren(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, 'Client'), h('th', null, 'Device'), h('th', { class: 'r' }, 'Sessions'), h('th', { class: 'r', title: 'Half of the sessions were shorter than this' }, 'Median'), h('th', { class: 'r' }, 'Under 1 min'),
        h('th', { class: 'r', title: 'The client said goodbye. A phone does this every time it goes to sleep.' }, 'Left'), h('th', { class: 'r', title: 'The client vanished: no keepalive arrived (lost signal, crashed, blocked)' }, 'Timed out'),
        h('th', { class: 'r', title: 'A TCP connection was closed' }, 'Closed'), h('th', { class: 'r', title: 'Server restart, disconnected by an admin, or no reason in the log' }, 'Other'), h('th', { class: 'r', title: 'Sessions over the TCP fallback: UDP did not get through' }, 'Over TCP'))),
      h('tbody', null, rows.map(r => h('tr', null,
        h('td', { class: 'name-cell' }, r.name.includes('#') ? h('span', { class: 'muted' }, clientLabel(r.name)) : h('a', { href: '#/clients/' + encodeURIComponent(r.name) }, r.name)),
        deviceCell(r), h('td', { class: 'r num' }, fmtNum(r.sessions)), h('td', { class: 'r num' }, r.median_seconds === null ? '—' : fmtDur(r.median_seconds)),
        n(r.short, r.sessions), n(r.left), n(r.timed_out), n(r.closed), n(r.other), n(r.tcp, r.sessions)))))),
      h('p', { class: 'small muted', style: 'margin:10px 0 0' }, 'Sessions that started in the period. Many short sessions that end with "left" are normal for phones: OpenVPN Connect drops the tunnel when the phone sleeps and reconnects when it wakes. Timeouts and sessions over TCP point at the network between the client and this server.'));
  }
  async function load() {
    table.classList.add('loading');
    try {
      const r = await api(`/api/sessions?limit=${LIMIT}&offset=${offset}&active=${active}&merge=${merge}&via=${via}${name ? '&name=' + encodeURIComponent(name) : ''}`);
      const what = via === 'relay' ? 'relay session' : merge && via === 'vpn' ? 'visit' : 'session';
      total = r.total; count.textContent = `${fmtNum(total)} ${what}${total === 1 ? '' : 's'}`;
      table.replaceChildren(sessionsTable(r.sessions, true));
      pager.replaceChildren(h('span', { class: 'muted small' }, total ? `${offset + 1}–${Math.min(offset + LIMIT, total)} of ${fmtNum(total)}` : ''),
        h('button', { class: 'btn sm', disabled: offset === 0, onClick: () => { offset = Math.max(0, offset - LIMIT); load(); } }, 'Previous'),
        h('button', { class: 'btn sm', disabled: offset + LIMIT >= total, onClick: () => { offset += LIMIT; load(); } }, 'Next'));
    } catch (e) { toast(e.message, 'err'); }
    table.classList.remove('loading');
  }
  load(); loadQuality();
  return null;
}

/* --------------------------------------------------------------- server */
// "1197/udp, 1196/tcp" for a list of {port, proto}.
function socks(list, sorted) { const s = list.map(x => `${x.port}/${x.proto}`); return (sorted ? s.sort() : s).join(', '); }
function serverView(el) {
  const body = h('div', { class: 'stack' });
  const sub = h('span');
  el.append(topbar('Server', sub, h('button', { class: 'btn danger', onClick: async () => { if (await confirmDialog('Restart OpenVPN', 'All connected clients will be disconnected and reconnect automatically. Configuration changes are applied on restart.', 'Restart', true)) await withToast(api('/api/server/restart', { method: 'POST' }), 'OpenVPN is restarting'); } }, icon('power'), 'Restart OpenVPN')), body);
  let info = null;
  const status = h('div', { class: 'grid two' });
  const tfaCard = h('div'), ccCard = h('div');
  body.append(status, h('div', { class: 'grid two' }, tfaCard, ccCard), configEditor(), logsCard(), eventsCard());
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
    status.replaceChildren(
        card('Status', kv([
          ['OpenVPN', live.version || '—'],
          ['Management', h('span', null, h('span', { class: 'status-dot' + (live.connected ? ' on' : ''), style: 'display:inline-block;margin-right:6px' }), live.connected ? `${info.management.host}:${info.management.port}${info.management.password ? ' (password protected)' : ''}` : (live.error || 'disconnected'))],
          ['Data channel offload', live.stats && live.stats.dco_enabled !== undefined ? (live.stats.dco_enabled === '1' ? 'enabled (kernel)' : 'not available on this kernel') : '—'],
          ['Connected clients', live.connected ? String(live.clients.length) : '—'],
          ['Since process start', live.load && live.load.bytesin !== undefined ? `↓ ${fmtBytes(live.load.bytesout)} · ↑ ${fmtBytes(live.load.bytesin)}` : '—'],
          ['Listening on', h('span', null, socks(info.listen), h('span', { class: 'muted small' }, ' · server.conf'))],
          ['Client profiles point to', h('span', { class: socks(info.remote.remotes, true) !== socks(info.listen, true) ? 'badge expiring' : '' },
            `${info.remote.host || '(not set)'} · ${socks(info.remote.remotes)}`)],
          ['UI version', info.ui_version],
          ['Backups', !info.backup.enabled ? 'off (OVPN_BACKUP_KEEP=0)' : info.backup.last ? h('span', null, `${fmtAgo(info.backup.last)} · ${fmtBytes(info.backup.size)} · ${info.backup.count} kept in `, h('span', { class: 'mono small' }, info.backup.dir), info.backup.encrypted ? ' · encrypted' : h('span', { class: 'muted', title: 'The archives hold the CA key. Set OVPN_BACKUP_RECIPIENT to an age public key to encrypt them.' }, ' · not encrypted')) : 'none yet - the first one is written a minute after the start'],
        ]), h('button', { class: 'btn sm', onClick: () => withToast(api('/api/server/backup', { method: 'POST' }), 'Backup written').then(load) }, 'Back up now')),
        card('PKI', kv([
          ['Certificate authority', h('span', null, p.ca ? p.ca.cn : '—', ' · expires ', expiry(p.ca, 90))],
          ['Server certificate', h('span', null, p.server ? p.server.cn : '—', ' · expires ', expiry(p.server, 30))],
          ['Key algorithm', p.algo === 'ec' ? `EC ${p.curve || ''}` : `RSA ${p.key_size || ''}`],
          ['Default client validity', `${p.cert_days} days`],
          ['tls-crypt key', p.tls_key ? 'present' : h('span', { class: 'badge revoked' }, 'missing')],
          ['Revocation list', crl.exists ? h('span', null, `${crl.revoked} revoked · next update `, expiry({ not_after: crl.next_update }, 30)) : h('span', { class: 'badge revoked' }, 'missing')],
        ]), h('button', { class: 'btn sm', onClick: () => withToast(api('/api/server/crl', { method: 'POST' }), 'CRL regenerated').then(load) }, 'Regenerate CRL')));
    tfaCard.replaceChildren(card('Two-factor authentication', h('div', { class: 'stack', style: 'gap:8px' },
        h('label', { class: 'check' }, tfaToggle, h('b', null, 'Require a TOTP code from every client')),
        h('p', { class: 'small muted', style: 'margin:0' }, 'Adds "auth-user-pass-verify" to server.conf. Enrol clients first (Clients → client → Enable 2FA), then enforce and restart. Clients without a secret cannot connect while enforced.'))));
    const v2 = info.control_channel === 'tls-crypt-v2';
    ccCard.replaceChildren(card('Control channel key', h('div', { class: 'stack', style: 'gap:8px' },
      h('div', null, h('b', null, v2 ? 'One key per client (tls-crypt-v2)' : info.control_channel === 'tls-crypt' ? 'One key shared by all clients (tls-crypt)' : info.control_channel)),
      h('p', { class: 'small muted', style: 'margin:0' }, 'With a key per client, a leaked profile does not expose a key every client shares, and the server drops packets from unknown clients before doing any TLS work. Switching changes every profile: after restarting OpenVPN, clients connect only with their new profile (hand them out with Share link).'),
      h('div', null, h('button', { class: 'btn' + (v2 ? '' : ' primary'), onClick: async () => {
        if (await confirmDialog(v2 ? 'Switch to one shared key' : 'Switch to a key per client', 'Every client profile changes. After restarting OpenVPN, clients can only connect with their new profile.', 'Switch', true)) {
          await withToast(api('/api/server/control-channel', { method: 'PUT', body: { per_client: !v2 } }), 'Saved - restart OpenVPN, then hand out the profiles again'); load();
        } } }, v2 ? 'Switch to one shared key' : 'Switch to a key per client')))));
  }
  function configEditor() {
    const tabs = h('div', { class: 'tabs' });
    const ta = h('textarea', { class: 'input code', spellcheck: 'false' });
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
