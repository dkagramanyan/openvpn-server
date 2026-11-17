'use strict';
/* Traffic by podkop section: the dashboard, a client's page and the personal portal. */

function sectionName(s) {
  return s === '' ? 'Direct' : s === '?' ? 'Through podkop, section unknown' : s;
}

// sectionsCard(url, { clients, period }): url answers /api/sections or a client's view;
// clients = show each section's top clients (dashboard); period = add a period control.
function sectionsCard(url, opts) {
  opts = opts || {};
  const body = h('div', { class: 'stack', style: 'gap:10px' });
  const note = h('p', { class: 'small muted', style: 'margin:0' });
  const title = h('h2');
  const expanded = new Set();
  const control = opts.period ? rangeControl(() => load()) : null;
  const el = h('section', { class: 'card' }, h('div', { class: 'card-h' }, title, control), h('div', { class: 'card-b' }, body, note));
  function draw(data) {
    title.textContent = 'Traffic by section · ' + rangeLabel(state.range);
    const rows = data.sections || [];
    if (!rows.length) {
      body.replaceChildren(h('div', { class: 'empty' }, data.router && !data.router.address
        ? 'Counting by podkop section is off. Set the router under Settings → Router.' : 'No traffic counted by section in this period'));
    } else {
      const total = Math.max(1, data.bytes);
      body.replaceChildren(h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
        h('thead', null, h('tr', null, h('th', null, 'Section'), h('th', { class: 'r' }, 'Download'), h('th', { class: 'r' }, 'Upload'),
          h('th', { class: 'r' }, 'Share'), h('th', null, opts.clients ? 'Top clients' : 'Top domains'))),
        h('tbody', null, rows.map(s => {
          const bytes = s.bytes_in + s.bytes_out;
          const via = `OpenVPN ↓ ${fmtBytes(s.vpn.bytes_out)} ↑ ${fmtBytes(s.vpn.bytes_in)} · relay ↓ ${fmtBytes(s.relay.bytes_out)} ↑ ${fmtBytes(s.relay.bytes_in)}`;
          let extra;
          if (opts.clients) {
            extra = h('span', { class: 'small' }, (s.clients || []).map((c, i) => [i ? ', ' : '',
              h('a', { href: '#/clients/' + encodeURIComponent(c.name) }, clientLabel(c.name)), h('span', { class: 'muted' }, ' ' + fmtBytes(c.bytes))]));
          } else if (s.domains && s.domains.length) {
            const list = h('details', { onToggle: e => { if (e.currentTarget.open) expanded.add(s.section); else expanded.delete(s.section); } },
              h('summary', { class: 'small' }, s.domains.slice(0, 2).map(d => d.domain).join(', ') + (s.domains.length > 2 ? ` +${s.domains.length - 2}` : '')),
              h('div', { class: 'small' }, s.domains.map(d => h('div', null, h('span', { class: 'mono' }, d.domain),
                h('span', { class: 'muted' }, ` ↓ ${fmtBytes(d.bytes_out)} ↑ ${fmtBytes(d.bytes_in)} · ${fmtNum(d.flows)} conn.`)))));
            list.open = expanded.has(s.section);
            extra = list;
          } else {
            extra = h('span', { class: 'small muted' }, data.domains_available ? '—' : 'kept 7 days');
          }
          return h('tr', null,
            h('td', { class: s.section === '' || s.section === '?' ? 'muted' : '' }, h('strong', null, sectionName(s.section))),
            h('td', { class: 'r num', title: via }, fmtBytes(s.bytes_out)), h('td', { class: 'r num', title: via }, fmtBytes(s.bytes_in)),
            h('td', { class: 'r num' }, Math.round(bytes / total * 100) + '%'), h('td', null, extra));
        })))));
    }
    const parts = [];
    if (data.router && data.router.address && data.router.error) parts.push(`The router is not answering (${data.router.error}): new traffic waits up to an hour, then counts as section unknown.`);
    if (data.unknown_share > 0.005) parts.push(`${Math.round(data.unknown_share * 100)}% of the traffic through podkop has an unknown section (the router had not seen the name, or it restarted).`);
    parts.push('Direct = not through podkop. Hover a number for the OpenVPN and relay split.');
    if (!opts.clients) parts.push(`Domains are kept for ${data.detail_days} days; section totals for good.`);
    note.textContent = parts.join(' ');
  }
  async function load() {
    try {
      const data = await api(`${url}?${rangeQuery()}`);
      showPeriod(data);
      draw(data);
    } catch (e) { body.replaceChildren(h('div', { class: 'empty' }, e.message)); }
  }
  return { card: el, load };
}

function routerCard() {
  const address = h('input', { class: 'input', placeholder: 'root@192.168.1.1', autocomplete: 'off', 'aria-label': 'Router SSH address' });
  const status = h('div', { class: 'stack', style: 'gap:6px' });
  const line = h('div', { class: 'uri mono small', style: 'word-break:break-all' });
  const copy = () => navigator.clipboard.writeText(line.textContent).then(() => toast('Command copied', 'ok'), () => toast('Copying needs HTTPS - select the command instead', 'err'));
  const lineBox = h('div', { class: 'stack', style: 'gap:6px', hidden: true },
    h('span', { class: 'small' }, 'Paste this command into the router\'s terminal (SSH as root), once. It adds this server\'s key, which can run nothing but the section lookup, and replaces an older key of this server:'),
    line, h('div', null, h('button', { class: 'btn sm', onClick: copy }, 'Copy command')));
  const keyButton = h('button', { class: 'btn' });
  let initialized = false, info = null;
  function show(r) {
    info = r;
    if (!initialized) { address.value = r.address || ''; initialized = true; }
    keyButton.textContent = r.key ? 'Replace key' : 'Create key';
    lineBox.hidden = !r.command;
    line.textContent = r.command || '';
    const parts = [];
    if (!r.address) parts.push(h('strong', null, 'Off: no router address'));
    else if (r.error) parts.push(h('strong', null, 'Router not answering: '), h('span', null, r.error));
    else if (r.last_ok) parts.push(h('strong', null, `Router answers · checked ${fmtAgo(r.last_ok)}`), h('span', { class: 'muted' }, (r.agent ? ` · podkop-agent ${r.agent}` : '') + ` · ${r.sections.length} sections · ` + (r.subnets === null ? 'address lists not loaded yet' : `${fmtNum(r.subnets)} address ranges`)));
    else parts.push(h('strong', null, 'Not asked yet (the first check comes within a minute)'));
    status.replaceChildren(h('div', null, ...parts),
      h('span', { class: 'small muted' }, `${fmtNum(r.pending)} connections waiting for an answer` + (r.unmapped ? ` · ${fmtNum(r.unmapped)} OpenVPN connections without a known client since the UI started` : '')));
  }
  async function load() { try { show(await api('/api/router')); } catch (e) { status.textContent = e.message; } }
  keyButton.addEventListener('click', async () => {
    if (info && info.key && !await confirmDialog('Replace the key', 'The router refuses the old key from then on: paste the new command into its terminal.', 'Replace', true)) return;
    try { show(await withToast(api('/api/router/key', { method: 'POST', body: { replace: !!(info && info.key) } }), 'Key created')); } catch (_) {}
  });
  const result = card('Router · traffic by podkop section', h('div', { class: 'form' },
    h('p', { class: 'small muted', style: 'margin:0' }, 'The LAN router running podkop tells this server which section each destination belongs to; this server counts the bytes per client and checks the router every 5 minutes. Leave the address empty to switch it off.'),
    status,
    field('Router SSH address', address, 'user@host of the router with podkop-agent 0.27 or newer, e.g. root@192.168.1.1'),
    lineBox,
    h('div', { class: 'row' },
      h('button', { class: 'btn primary', onClick: async () => { try { show(await withToast(api('/api/router', { method: 'PUT', body: { address: address.value.trim() } }), 'Router saved')); } catch (_) {} } }, 'Save'),
      keyButton,
      h('button', { class: 'btn', onClick: async () => {
        try {
          const r = await api('/api/router/test', { method: 'POST' });
          if (r.ok) toast(`Router answers: ${r.sections.length} sections, ${r.subnets} address ranges`, 'ok'); else toast(r.error, 'err');
          load();
        } catch (e) { toast(e.message, 'err'); }
      } }, 'Test'))));
  load();
  return result;
}
