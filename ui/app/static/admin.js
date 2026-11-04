'use strict';
/* Administrator pages: dashboard, clients, client detail, sessions and server. */

/* ------------------------------------------------------ portal accounts */
async function portalAccessDialog(name) {
  try {
    const info = await api(`/api/clients/${encodeURIComponent(name)}/portal`);
    const username = h('input', { class: 'input', value: info.username, autocomplete: 'off', 'aria-label': 'Portal username' });
    const password = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', 'aria-label': 'Portal password' });
    const url = `/api/clients/${encodeURIComponent(name)}/portal`;
    dialog({ title: 'Portal access · ' + name, body: h('div', { class: 'form' },
      h('p', null, info.enabled ? 'This client can sign in to download their own profiles. Saving resets their password and signs out existing sessions.' : 'Create a login for this client to download their own OpenVPN and Apple relay profiles.'),
      field('Username', username), field('New password', password, 'At least 8 characters. This password is for the website; the OpenVPN profile password is separate.')),
      buttons: [
        { label: 'Cancel', value: null },
        ...(info.enabled ? [{ label: 'Disable access', cls: 'danger', onClick: async () => { try { await withToast(api(url, { method: 'DELETE' }), 'Portal access disabled'); return true; } catch (_) { return false; } } }] : []),
        { label: 'Save login', cls: 'primary', onClick: async () => {
          if (password.value.length < 8) { toast('Use at least 8 characters', 'err'); return false; }
          try { await withToast(api(url, { method: 'PUT', body: { username: username.value.trim(), password: password.value } }), 'Portal login saved'); return true; } catch (_) { return false; }
        } }] });
  } catch (e) { toast(e.message, 'err'); }
}



/* ------------------------------------------------------------ dashboard */
function dashboardView(el) {
  let data = null;
  const sub = h('span', null, 'loading…');
  const body = h('div', { class: 'stack' });
  el.append(topbar('Dashboard', sub, rangeControl(load)), body);
  const liveTable = h('div');
  const throughputTile = h('div', { style: 'display:grid' });
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
        fromCell(c),
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
        card('Connected clients', liveTable),
        h('div', { id: 'rej' }));
      hourChart = lineChart(hourEl, hourOpts); rangeChart = lineChart(rangeEl, rangeOpts);
    } else { hourChart.update(hourOpts); rangeChart.update(rangeOpts); body.querySelectorAll('.card-h h2').forEach(x => { if (x.textContent.startsWith('Top clients')) x.textContent = 'Top clients · ' + rl; if (x.textContent.startsWith('Traffic ·')) x.textContent = 'Traffic · ' + rl; }); }
    $('#warnings', body).replaceChildren(warnings(data.warnings) || '');
    $('#kpi', body).replaceChildren(
      tile('Online now', [live.connected ? live.clients.length : '—', h('small', null, `of ${data.counts.valid}`)], data.counts.expiring ? `${data.counts.expiring} expiring soon` : `${data.counts.revoked} revoked`),
      tile('Download · ' + rl, fmtBytes(t.bytes_out), `${fmtNum(t.sessions)} session${t.sessions === 1 ? '' : 's'} · ${t.clients} client${t.clients === 1 ? '' : 's'}`, sparkline(dl.slice(-24))),
      tile('Upload · ' + rl, fmtBytes(t.bytes_in), 'from clients to the server', sparkline(ul.slice(-24))),
      throughputTile);
    $('#top', body).replaceChildren(bars(data.top.map(c => ({ label: clientLabel(c.name), value: c.bytes_in + c.bytes_out, href: c.name.includes('#') ? null : '#/clients/' + encodeURIComponent(c.name), title: `↓ ${fmtBytes(c.bytes_out)} · ↑ ${fmtBytes(c.bytes_in)}` }))));
    renderLiveTable(live);
    $('#rej', body).replaceChildren(data.rejections.length ? card('Rejected connection attempts · last 24 h', rejectionsTable(data.rejections, true)) : '');
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
        h('td', null, h('div', { class: 'row', style: 'gap:6px' }, stateBadge(c), c.tfa ? h('span', { class: 'badge plain', title: 'Two-factor authentication enabled' }, '2FA') : null, c.guest ? h('span', { class: 'subnet', title: 'Guest: only the personal portal' }, 'guest') : c.static_ip ? h('span', { class: 'subnet', title: 'Static IP' }, c.static_ip) : null, c.previous ? h('span', { class: 'badge plain expiring', title: 'Previous certificate still valid' }, 'renewed') : null)),
        h('td', { class: 'num' }, c.expires ? [fmtDate(c.expires), h('span', { class: 'muted small' }, ' · ' + fmtDays(c.days_left))] : '—'),
        h('td', null, c.online ? h('span', { class: 'ink2' }, 'now') : fmtAgo(c.total.last_seen)),
        h('td', { class: 'r num' }, fmtBytes(c.traffic.bytes_out)), h('td', { class: 'r num' }, fmtBytes(c.traffic.bytes_in)),
        h('td', { class: 'r num' }, fmtNum(c.total.sessions)),
        h('td', { class: 'actions' }, c.state === 'valid' ? h('a', { class: 'btn sm', href: `/api/clients/${encodeURIComponent(c.name)}/ovpn`, download: c.name + '.ovpn', title: 'Download OpenVPN config' }, icon('download'), 'OpenVPN') : null,
          c.state === 'valid' ? relayButton(c, true) : null)))))));
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
  const ip = h('input', { class: 'input' });
  let guest = false;
  const accessHelp = h('div', { class: 'help' });
  const access = h('div', { class: 'seg', role: 'group', 'aria-label': 'Access', style: 'align-self:flex-start' });
  const setAccess = g => {
    guest = g;
    access.querySelectorAll('button').forEach((b, i) => b.classList.toggle('active', (i === 1) === g));
    accessHelp.textContent = g ? 'Only the personal portal (password, profile downloads): no internet, no LAN, not this server or other VPN clients.' : 'Internet, your LAN and this server.';
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

  async function load() {
    body.classList.add('loading');
    try { c = await api(`/api/clients/${enc}?tz=${TZ}`); } catch (e) { toast(e.message, 'err'); body.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
    setChildren(badges, stateBadge(c), c.tfa ? h('span', { class: 'badge plain' }, '2FA') : null, c.guest ? h('span', { class: 'subnet' }, 'guest') : c.static_ip ? h('span', { class: 'subnet' }, 'static ' + c.static_ip) : null, c.previous ? h('span', { class: 'badge plain expiring' }, 'renewed · previous cert still valid') : null);
    setChildren(actions, 
      c.state === 'valid' ? h('a', { class: 'btn primary', href: `/api/clients/${enc}/ovpn`, download: name + '.ovpn' }, icon('download'), 'OpenVPN config') : null,
      c.state === 'valid' ? relayButton(c) : null,
      c.state === 'valid' ? act('Portal access', () => portalAccessDialog(name)) : null,
      c.relay_available ? act('Revoke relay access', async () => { if (await confirmDialog('Revoke relay access', 'Installed Apple relay profiles will stop working. Download a new profile to enable access again.', 'Revoke', true)) { await withToast(api(`/api/clients/${enc}/relay`, { method: 'DELETE' }), 'Relay access revoked'); load(); } }, 'danger') : null,
      c.online ? act('Disconnect', async () => { if (await confirmDialog('Disconnect', `Disconnect all sessions of ${name}?`, 'Disconnect', true)) { await withToast(api(`/api/clients/${enc}/disconnect`, { method: 'POST', body: {} }), 'Disconnected'); } }) : null,
      c.state === 'valid' ? act(c.tfa ? 'Show 2FA code' : 'Enable 2FA', async () => {
        if (c.tfa) { tfaDialog(name, c.tfa_uri); return; }
        if (await confirmDialog('Enable two-factor authentication', 'A new TOTP secret will be generated and "auth-user-pass" added to the profile. Re-deliver the profile afterwards. Note: 2FA is only checked when it is enforced on the Server page.', 'Enable')) {
          const r = await withToast(api(`/api/clients/${enc}/tfa`, { method: 'POST', body: { enabled: true } }), '2FA enabled'); tfaDialog(name, r.tfa_uri); load();
        } }) : null,
      c.state === 'valid' && c.tfa ? act('Disable 2FA', async () => { if (await confirmDialog('Disable 2FA', `Remove the TOTP secret of ${name}?`, 'Disable', true)) { await withToast(api(`/api/clients/${enc}/tfa`, { method: 'POST', body: { enabled: false } }), '2FA disabled'); load(); } }) : null,
      c.state === 'valid' ? act('Share link', () => shareDialog(name)) : null,
      c.state === 'valid' && !c.guest ? act('Static IP', () => staticIpDialog(c, load)) : null,
      c.state !== 'revoked' && !c.previous ? act('Renew', async () => { if (await confirmDialog('Renew certificate', 'A new certificate is issued for the same key. The previous certificate stays valid until you revoke it, so the client keeps working while you deliver the new profile.', 'Renew')) { await withToast(api(`/api/clients/${enc}/renew`, { method: 'POST', body: {} }), 'Certificate renewed'); load(); } }) : null,
      c.previous ? act('Revoke previous cert', async () => { if (await confirmDialog('Revoke previous certificate', 'The old certificate will be added to the CRL. Make sure the client already uses the new profile.', 'Revoke', true)) { await withToast(api(`/api/clients/${enc}/revoke-previous`, { method: 'POST' }), 'Previous certificate revoked'); load(); } }, 'danger') : null,
      c.state !== 'revoked' ? act('Revoke', async () => { if (await confirmDialog('Revoke certificate', `${name} will be disconnected and can no longer connect. This cannot be undone.`, 'Revoke', true)) { await withToast(api(`/api/clients/${enc}/revoke`, { method: 'POST', body: {} }), 'Certificate revoked'); load(); } }, 'danger') : null,
      c.state === 'revoked' ? act('Delete', async () => { if (await confirmDialog('Delete client', `Remove the profile, static IP and 2FA data of ${name}? Traffic history is kept.`, 'Delete', true)) { await withToast(api(`/api/clients/${enc}`, { method: 'DELETE' }), 'Client deleted'); go('#/clients'); } }, 'danger') : null);

    const cert = c.cert, t = c.total;
    const accessSeg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Access' }, [['Full access', false], ['Guest', true]].map(([label, g]) =>
      h('button', { class: c.guest === g ? 'active' : '', disabled: c.state !== 'valid', onClick: async () => {
        if (c.guest === g) return;
        const text = g ? `${name} will reach only the personal portal: no internet, no LAN, not this server or other VPN clients.` : `${name} will reach the internet, your LAN and this server.`;
        if (await confirmDialog(g ? 'Make guest' : 'Give full access', text + ' OpenVPN changes apply on reconnect. The relay applies them within seconds; download the Apple relay profile again, because guest and full-access profiles route different traffic.', g ? 'Make guest' : 'Give full access')) {
          await withToast(api(`/api/clients/${enc}/access`, { method: 'PUT', body: { guest: g } }), 'Access changed'); load();
        } } }, label)));
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
            ['Access', accessSeg],
            ['Address', c.guest ? 'a free guest address per device' : c.static_ip ? `static ${c.static_ip} (first device; others get a dynamic one)` : 'dynamic'],
            ['2FA', c.tfa ? 'enabled' : 'off'],
          ].filter(Boolean))),
          card('Note', h('div', { class: 'stack', style: 'gap:8px' }, noteIn, h('div', null, h('button', { class: 'btn sm', onClick: () => withToast(api(`/api/clients/${enc}/note`, { method: 'PUT', body: { note: noteIn.value } }), 'Note saved') }, 'Save note')))))),
      c.rejections.length ? card('Rejected connection attempts · last 30 days', rejectionsTable(c.rejections, false)) : '',
      card('Visits · last 100', sessionsTable(c.sessions, false), h('a', { class: 'btn sm', href: '#/sessions/' + enc }, 'Every session')));
    lineChart(dailyEl, { ts: c.daily.map(p => p.ts), series: [{ label: 'Download', cls: 's1', values: c.daily.map(p => p.bytes_out) }, { label: 'Upload', cls: 's2', values: c.daily.map(p => p.bytes_in) }], fmtY: v => fmtBytes(v, 0), fmtX: fmtDate, fmtXFull: fmtDate, height: 220, aria: 'Daily traffic' });
    body.classList.remove('loading');
  }
  load();
  return { onLive: live => { if (!c) return; const on = live.clients.some(x => x.cn === name); if (on !== c.online) load(); } };
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
function shareDialog(name) {
  const hours = h('select', { class: 'input' }, [['1', '1 hour'], ['24', '24 hours'], ['168', '7 days']].map(([v, l]) => h('option', { value: v, selected: v === '24' }, l)));
  const out = h('div', { class: 'stack', style: 'gap:10px' });
  const copy = (text, what) => navigator.clipboard.writeText(text).then(() => toast(what + ' copied', 'ok'), () => toast('Copying needs HTTPS - select the link instead', 'err'));
  const make = async () => {
    let r;
    try { r = await api(`/api/clients/${encodeURIComponent(name)}/share`, { method: 'POST', body: { hours: Number(hours.value) } }); } catch (e) { toast(e.message, 'err'); return; }
    out.replaceChildren(h('div', { class: 'qr' }, h('div', { class: 'code' }, h('img', { src: 'data:image/svg+xml;base64,' + btoa(r.qr_svg), alt: 'QR code of the import link' })),
      h('div', { class: 'stack', style: 'flex:1;min-width:220px;gap:8px' },
        h('p', { style: 'margin:0' }, `Scan it with the phone camera: OpenVPN Connect imports the profile. Or send the link: it opens a page that offers the profile, so a messenger's link preview does not use it up. The profile can be fetched once; the link expires ${fmtDateTime(r.expires_at)}.`),
        h('div', { class: 'uri mono muted' }, r.url),
        h('div', { class: 'row' }, h('button', { class: 'btn sm', onClick: () => copy(r.url, 'Link') }, 'Copy link'), h('button', { class: 'btn sm', onClick: () => copy(r.import_url, 'Import link') }, 'Copy import link')))),
      r.public ? '' : warnings(['OVPN_PROFILE_BASE_URL is not set, so the link uses this admin address and only works where that is reachable.']));
  };
  dialog({ title: `Share profile · ${name}`, wide: true, body: h('div', { class: 'stack' },
    h('div', { class: 'row', style: 'align-items:flex-end' }, field('Valid for', hours), h('button', { class: 'btn primary', onClick: make }, 'Create link')), out),
    buttons: [{ label: 'Done', cls: 'primary', value: true }] });
}
function staticIpDialog(c, after) {
  const ip = h('input', { class: 'input', value: c.static_ip || '', placeholder: 'leave empty for a dynamic address' });
  dialog({ title: 'Static IP · ' + c.name, body: h('div', { class: 'form' }, field('IPv4 address', ip, `An address of the VPN subnet outside the dynamic pool and outside the guest range ${state.user.guest_sub}. The first device of this client to connect gets it. Applies on the next connection.`)),
    buttons: [{ label: 'Cancel', value: null }, { label: 'Save', cls: 'primary', onClick: async () => { try { await api(`/api/clients/${encodeURIComponent(c.name)}/static-ip`, { method: 'PUT', body: { ip: ip.value.trim() || null } }); toast('Static IP saved', 'ok'); after(); return true; } catch (e) { toast(e.message, 'err'); return false; } } }] });
}
function sessionsTable(list, withName) {
  if (!list.length) return h('div', { class: 'empty' }, 'No sessions recorded');
  return h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
    h('thead', null, h('tr', null, withName ? h('th', null, 'Client') : null, h('th', null, 'Connected'), h('th', null, 'Duration'), h('th', null, 'From'), h('th', null, 'VPN IP'), h('th', null, 'Device'), h('th', { class: 'r' }, 'Download'), h('th', { class: 'r' }, 'Upload'), h('th', null, 'Cipher'))),
    h('tbody', null, list.map(s => h('tr', null,
      withName ? h('td', { class: 'name-cell' }, s.client_name.includes('#') ? h('span', { class: 'muted', title: 'An earlier certificate with this name' }, clientLabel(s.client_name)) : h('a', { href: '#/clients/' + encodeURIComponent(s.client_name) }, s.client_name)) : null,
      h('td', { class: 'num' }, fmtDateTime(s.connected_at)),
      h('td', null, s.disconnected_at ? fmtDur(s.disconnected_at - s.connected_at) : h('span', { class: 'ink2' }, h('span', { class: 'dot-live' }), fmtDur(Date.now() / 1000 - s.connected_at)),
        // a visit: several connections of one client from one address, merged
        s.connections > 1 ? h('span', { class: 'muted small', title: 'Reconnects from the same address, at most 15 minutes apart' }, ` · ${fmtNum(s.connections)} connections, ${fmtDur(s.online_seconds)} online`) : null,
        s.disconnected_at && s.end_reason ? h('span', { class: 'muted small' }, ' · ' + s.end_reason) : null),
      fromCell(s), h('td', { class: 'mono small' }, s.vpn_ip || '—'), deviceCell(s),
      h('td', { class: 'r num' }, fmtBytes(s.bytes_out)), h('td', { class: 'r num' }, fmtBytes(s.bytes_in)),
      h('td', { class: 'small muted' }, s.cipher || ''))))));
}

/* ------------------------------------------------------------- sessions */
function sessionsView(el) {
  let offset = 0, total = 0, name = state.route.param || '', active = false, merge = !name;
  const LIMIT = 100;
  const table = h('div');
  const pager = h('div', { class: 'row', style: 'justify-content:flex-end;padding:10px 16px' });
  const nameIn = h('input', { class: 'input search', value: name, placeholder: 'Filter by client name', onChange: e => { name = e.target.value.trim(); offset = 0; load(); } });
  const activeIn = h('label', { class: 'check' }, h('input', { type: 'checkbox', onChange: e => { active = e.target.checked; offset = 0; load(); } }), 'Active only');
  const mergeIn = h('label', { class: 'check', title: 'Show the reconnects of one client from one address, at most 15 minutes apart, as one visit' }, h('input', { type: 'checkbox', checked: merge, onChange: e => { merge = e.target.checked; offset = 0; load(); } }), 'Merge reconnects');
  const count = h('span');
  const quality = h('div');
  const qualityTitle = h('h2', null, 'Connection quality');
  el.append(topbar('Sessions', count, nameIn, activeIn, mergeIn, h('button', { class: 'btn', onClick: () => { load(); loadQuality(); } }, icon('refresh'), 'Refresh')),
    h('div', { class: 'stack' }, h('section', { class: 'card' }, h('div', { class: 'card-h' }, qualityTitle, rangeControl(loadQuality)), h('div', { class: 'card-b' }, quality)), h('section', { class: 'card' }, table, pager)));
  async function loadQuality() {
    qualityTitle.textContent = 'Connection quality · ' + rangeLabel(state.range);
    let rows;
    try { rows = (await api(`/api/connections?range=${state.range}&tz=${TZ}`)).clients; } catch (e) { toast(e.message, 'err'); return; }
    if (!rows.length) { quality.replaceChildren(h('div', { class: 'empty' }, 'No sessions in this period')); return; }
    const n = (v, of) => h('td', { class: 'r num' }, v ? fmtNum(v) : h('span', { class: 'muted' }, '0'), v && of ? h('span', { class: 'muted small' }, ` ${Math.round(v / of * 100)}%`) : null);
    quality.replaceChildren(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, h('th', null, 'Client'), h('th', null, 'Device'), h('th', { class: 'r' }, 'Sessions'), h('th', { class: 'r', title: 'Half of the sessions were shorter than this' }, 'Median'), h('th', { class: 'r' }, 'Under 1 min'),
        h('th', { class: 'r', title: 'The client said goodbye. A phone does this every time it goes to sleep.' }, 'Left'), h('th', { class: 'r', title: 'The client vanished: no keepalive arrived (lost signal, crashed, blocked)' }, 'Timed out'),
        h('th', { class: 'r', title: 'A TCP connection was closed' }, 'Closed'), h('th', { class: 'r', title: 'Server restart, disconnected by an admin, or no reason in the log' }, 'Other'), h('th', { class: 'r', title: 'Sessions over the TCP fallback: UDP did not get through' }, 'Over TCP'))),
      h('tbody', null, rows.map(r => h('tr', null,
        h('td', { class: 'name-cell' }, r.name.includes('#') ? h('span', { class: 'muted' }, clientLabel(r.name)) : h('a', { href: '#/clients/' + encodeURIComponent(r.name) }, r.name)),
        deviceCell(r), h('td', { class: 'r num' }, fmtNum(r.sessions)), h('td', { class: 'r num' }, r.median_seconds === null ? '—' : fmtDur(r.median_seconds)),
        n(r.short, r.sessions), n(r.left), n(r.timed_out), n(r.closed), n(r.other), n(r.tcp, r.sessions)))))),
      h('p', { class: 'small muted', style: 'margin:10px 0 0' }, 'Many short sessions that end with "left" are normal for phones: OpenVPN Connect drops the tunnel when the phone sleeps and reconnects when it wakes. Timeouts and sessions over TCP point at the network between the client and this server.'));
  }
  async function load() {
    table.classList.add('loading');
    try {
      const r = await api(`/api/sessions?limit=${LIMIT}&offset=${offset}&active=${active}&merge=${merge}${name ? '&name=' + encodeURIComponent(name) : ''}`);
      const what = merge ? 'visit' : 'session';
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
