'use strict';
/* Apple Network Relay: sessions, activity, profile signing and profile downloads. */

function relaySessionList(rows, detail = null, expanded = new Set()) {
  if (!rows.length) return h('p', { class: 'small muted' }, 'No relay sessions recorded yet. Activity appears after you connect with your profile.');
  return h('div', { class: 'stack' }, rows.map(row => {
    const summary = h('div', { class: 'stack', style: 'gap:6px' },
      h('div', { class: 'row' }, h('strong', null, row.client), h('span', { class: 'pill' }, row.state === 'active' ? 'Connected' : row.state === 'idle' ? 'Idle · waiting for reconnect' : 'Ended')),
      h('span', { class: 'small' }, `${fmtDateTime(row.started_at)} · ${fmtDur((row.ended_at || row.last_seen) - row.started_at)} · ${fmtNum(row.accepted)} connections${row.active ? ` · ${fmtNum(row.active)} open` : ''}`),
      h('span', { class: 'small' }, `↓ ${fmtBytes(row.bytes_down)} · ↑ ${fmtBytes(row.bytes_up)}`),
      row.denied || row.failed ? h('span', { class: 'small muted' }, `${fmtNum(row.denied)} blocked · ${fmtNum(row.failed)} failed`) : null,
      row.uncounted_flows ? h('span', { class: 'small muted' }, `${fmtNum(row.uncounted_flows)} flows have uncounted payload traffic`) : null);
    if (!detail) return h('div', { class: 'relay-session' }, summary);
    const panel = h('details', { class: 'relay-session', onToggle: event => {
      if (!event.currentTarget.isConnected) return;
      if (event.currentTarget.open) expanded.add(row.id); else expanded.delete(row.id);
    } }, h('summary', null, summary), detail(row));
    panel.open = expanded.has(row.id);
    return panel;
  }));
}

function relayView(el) {
  const summary = h('div', { class: 'grid two' });
  const active = h('div'), events = h('div'), sessions = h('div');
  const sessionExpanded = new Set();
  const activeExpanded = new Set(), historyExpanded = new Set();
  const filter = h('input', { class: 'input', placeholder: 'Filter by client or destination', 'aria-label': 'Filter relay activity', onInput: () => draw() });
  let info = null, loading = false;
  const signingSetup = relaySigningCard();
  el.append(topbar('Apple Network Relay', 'Access follows each client’s OpenVPN guest or full-access role',
    h('button', { class: 'btn', onClick: () => { load(); loadSigning(); } }, icon('refresh'), 'Refresh')),
    h('div', { class: 'stack' }, summary, card('Relay sessions', h('div', { class: 'stack' }, filter, sessions,
      h('p', { class: 'small muted' }, 'Short connections from the same profile form one session. A new session starts after five minutes without an open connection. The latest 200 sessions are shown; history is kept for one year across restarts. Devices sharing a profile share its session. Expand a session for recent connection details.'))),
      h('details', { class: 'settings-details' }, h('summary', null, 'Individual connections and diagnostics'), card('Active connections', active), card('Recent activity', events),
        h('p', { class: 'small muted' }, 'Individual details cover the latest 500 events and reset when the relay restarts. Session totals are saved every five seconds.')), signingSetup.card));
  const reason = value => (value || '').replace(/_/g, ' ');
  function table(rows, current) {
    const text = filter.value.toLowerCase();
    rows = rows.filter(r => `${r.client} ${r.target} ${r.reason}`.toLowerCase().includes(text));
    if (!rows.length) return h('div', { class: 'empty' }, current ? 'No active relay connections' : 'No matching relay activity');
    return h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, ['Time', 'Client', 'Access', 'Protocol', 'Destination', 'Result', 'Duration', 'Download', 'Upload'].map(t => h('th', null, t)))),
      h('tbody', null, rows.map(r => h('tr', null,
        h('td', { class: 'nowrap' }, fmtDateTime(r.ts)),
        h('td', null, r.client ? h('a', { href: '#/clients/' + encodeURIComponent(r.client) }, r.client) : 'unknown'),
        h('td', null, r.client ? (r.guest ? 'Guest' : 'Full access') : '—'), h('td', null, r.protocol || '—'),
        h('td', { class: 'mono small' }, r.target || '—'), h('td', null, r.status ? `${r.status} · ${r.kind}` : r.kind, h('div', { class: 'small muted' }, reason(r.reason)), r.upstream_error ? h('div', { class: 'small muted' }, reason(r.upstream_error)) : null),
        h('td', null, fmtDur(r.duration_ms / 1000)), h('td', { class: 'r num' }, r.bytes_counted ? fmtBytes(r.bytes_down) : '—'),
        h('td', { class: 'r num' }, r.bytes_counted ? fmtBytes(r.bytes_up) : '—'))))));
  }
  function groups(current) {
    const rows = current ? info.active : [...info.events].reverse();
    const expanded = current ? activeExpanded : historyExpanded;
    const needle = filter.value.toLowerCase();
    const clients = (info.clients || []).filter(c => (!current || c.active > 0) &&
      ((c.client || '').toLowerCase().includes(needle) || rows.some(r => r.client === c.client && `${r.target} ${r.reason} ${r.upstream_error || ''}`.toLowerCase().includes(needle))));
    if (!clients.length) return h('div', { class: 'empty' }, current ? 'No active relay connections' : 'No matching relay activity');
    return h('div', { class: 'stack', style: 'gap:12px' }, clients.map(c => {
      const details = h('details', { class: 'relay-user', onToggle: e => {
        if (!e.currentTarget.isConnected) return;
        if (e.currentTarget.open) expanded.add(c.client); else expanded.delete(c.client);
      } }, h('summary', { class: 'row', style: 'cursor:pointer;padding:8px 0;flex-wrap:wrap' },
        h('span', { class: 'relay-toggle', 'aria-hidden': 'true' }, '›'), h('strong', null, c.client || 'Unauthenticated requests'),
        c.client ? h('span', { class: 'pill' }, c.guest ? 'Guest' : 'Full access') : null,
        h('span', { class: 'small' }, current ? `${fmtNum(c.active)} connections · ${c.tcp} TCP / ${c.udp} UDP · ${c.destinations} destinations` : `${fmtNum(c.accepted)} accepted · ${fmtNum(c.failed)} failed · ${fmtNum(c.denied)} denied`),
        h('span', { class: 'small muted' }, `↓ ${fmtBytes(c.bytes_down)} · ↑ ${fmtBytes(c.bytes_up)}`)),
        h('div', { class: 'stack', style: 'gap:8px' }, c.uncounted_flows ? h('span', { class: 'small muted' }, `${c.uncounted_flows} HTTP/3 UDP flows have uncounted payload bytes`) : null, c.last_error ? h('div', { class: 'small muted' }, `Last issue: ${reason(c.last_error)} · ${fmtDateTime(c.last_error_at)}`) : null,
          table(rows.filter(r => r.client === c.client), current)));
      details.open = expanded.has(c.client);
      return details;
    }));
  }
  function draw() {
    if (!info) return;
    summary.replaceChildren(tile('Relay backend', !info.ready ? 'Unavailable' : info.policy_ready === false ? 'Policy unavailable' : 'Running', info.ready ? `${info.transport.toUpperCase()} · started ${fmtDateTime(info.started_at)}` : info.message),
      tile('Connections', info.active.length, `${fmtNum(info.total || 0)} accepted · ${fmtNum(info.failed || 0)} failed · ${fmtNum(info.denied || 0)} denied since startup${info.limits ? ` · limit ${info.limits.flows} total / ${info.limits.per_client} per client` : ''}`));
    active.replaceChildren(groups(true));
    events.replaceChildren(groups(false));
    const needle = filter.value.toLowerCase();
    const flowRows = [...info.active, ...[...info.events].reverse().filter(row => row.kind !== 'connected')];
    const members = row => new Set(row.member_ids || [row.id]);
    sessions.replaceChildren(relaySessionList((info.sessions || []).filter(row => row.client.toLowerCase().includes(needle) || flowRows.some(flow => members(row).has(flow.session_id) && `${flow.target} ${flow.reason}`.toLowerCase().includes(needle))),
      row => table(flowRows.filter(flow => members(row).has(flow.session_id)), false), sessionExpanded));
  }
  async function load() {
    if (loading) return;
    loading = true;
    try { info = await api('/api/relay/status'); draw(); } catch (e) { events.textContent = e.message; }
    finally { loading = false; }
  }
  const loadSigning = signingSetup.load;
  load(); loadSigning(); every(5000, load); every(60000, loadSigning);
  return null;
}

function relaySigningCard() {
  const status = h('div', { class: 'stack', style: 'gap:6px' });
  const url = h('input', { class: 'input', type: 'url', placeholder: 'https://openvpn.example.com/internal/relay-sign', 'aria-label': 'Profile signer URL' });
  const token = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', 'aria-label': 'Shared signing token' });
  const required = h('input', { type: 'checkbox', checked: true, 'aria-label': 'Require signed relay profiles' });
  let initialized = false;
  function show(s) {
    if (!initialized) {
      url.value = s.url || (location.protocol === 'https:' ? location.origin + '/internal/relay-sign' : '');
      required.checked = s.required; initialized = true;
    }
    token.placeholder = s.token_configured ? 'Token saved · leave blank to keep it' : 'Enter the shared Traefik signing token';
    status.replaceChildren(h('strong', null, s.ready ? 'Signed downloads enabled' : s.configured ? 'Signer unavailable — downloads blocked' : s.required ? 'Signed downloads blocked — complete signing setup' : 'Unsigned downloads explicitly allowed'),
      h('span', { class: 'small muted' }, s.ready ? `${s.subject} · certificate expires ${fmtDateTime(s.expires_at)}` : s.message));
  }
  async function load() { try { show(await api('/api/relay/signing')); } catch(e) { status.textContent = e.message; } }
  const result = card('Profile signing', h('div', { class: 'form' }, status,
    field('Profile signer URL', url, 'HTTPS endpoint on your Traefik host.'),
    field('Shared signing token', token, 'Use the existing RELAY_PROFILE_SIGNING_TOKEN from the Traefik .env. The token is never returned to this page.'),
    h('label', { class: 'check' }, required, 'Require signed relay profiles'),
    h('p', { class: 'small muted' }, 'After signing is ready, download the profile again and replace the old unsigned profile on the iPhone. Signing does not change relay connectivity.'),
    h('div', { class: 'row' }, h('button', { class: 'btn primary', onClick: async () => {
      try {
        const s = await withToast(api('/api/relay/signing', { method: 'PUT', body: { url: url.value.trim(), token: token.value.trim() || null, required: required.checked } }), 'Signing settings saved');
        token.value = ''; show(s);
      } catch (_) {}
    } }, 'Save signing settings'), h('button', { class: 'btn', onClick: load }, 'Check signing'),
    h('button', { class: 'btn', onClick: async () => {
      try {
        const s = await withToast(api('/api/relay/signing', { method: 'PUT', body: { use_environment: true } }), 'Using environment signing settings');
        initialized = false; token.value = ''; show(s);
      } catch (_) {}
    } }, 'Use environment settings'))));
  return { card: result, load };
}

function relayButton(c, small = false, portal = false, onError = null) {
  return h('button', { class: 'btn' + (small ? ' sm' : ''), disabled: !c.relay_available,
    title: c.relay_available ? 'Download a profile to install on your Apple device' : 'Ask your administrator to enable Apple relay',
    onClick: async event => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        const download = portal ? c.relay_download : await api(`/api/clients/${encodeURIComponent(c.name)}/relay-download`);
        if (!download?.url || !download?.csrf) throw new Error('Refresh this page before downloading your profile.');
        // A real HTTP download lets Safari hand .mobileconfig to Settings.
        const form = h('form', { method: 'POST', action: download.url, hidden: true }, h('input', { type: 'hidden', name: 'csrf', value: download.csrf }));
        document.body.append(form);
        form.submit();
        setTimeout(() => form.remove(), 1000);
      } catch (error) { if (onError) onError(error); else toast(error.message, 'err'); }
      finally { button.disabled = false; }
    } }, icon('download'), portal ? 'Download Apple relay' : 'Apple relay');
}
