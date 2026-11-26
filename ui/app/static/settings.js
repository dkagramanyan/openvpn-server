'use strict';
/* Settings page: one pane per subject (deep link #/settings/<pane>), the network form's
   action bar with what is unsaved and what applying it takes, password, appearance. */

/* --------------------------------------------------------------- network */
// One form behind five panes (addresses, relay, guests, VPN network, gateway): everything the
// clients and the Traefik gateway need to know, saved with one request. `saved` is
// GET /api/network/settings, `relay` GET /api/relay/settings and `general` GET /api/settings.
// The form keeps what was last saved, so it can tell which panes have unsaved changes and
// what applying them takes: a VPN restart, the gateway file, or nothing more.
function networkForm(saved, relay, general) {
  const gw = saved.gateway;
  const listText = list => (list || []).join(', ');
  const parseList = value => value.split(/[\s,]+/).filter(Boolean);
  const text = (value, attrs = {}) => h('input', { class: 'input', value: value || '', autocomplete: 'off', spellcheck: 'false', ...attrs });
  const hostOf = url => { try { return new URL(url).hostname; } catch (_) { return ''; } };
  const group = (title, help, ...children) =>
    h('section', { class: 'settings-section' }, title ? h('h3', null, title) : null, help ? h('p', { class: 'small muted' }, help) : null, ...children);
  const more = (summary, ...children) => h('details', { class: 'settings-details' }, h('summary', null, summary), h('div', { class: 'form' }, ...children));

  /* -- inputs ------------------------------------------------------------ */
  const domain = text(gw.domain, { placeholder: 'example.com' });
  const website = text(gw.openvpn_host);
  const vpnHost = text(general.remote.host);
  const vpnPorts = general.listen.map(listener => {
    const remote = general.remote.remotes.find(r => r.proto === listener.proto) || listener;
    return { proto: listener.proto, input: text(remote.port, { type: 'number', min: 1, max: 65535 }) };
  });
  const relayEnabled = h('input', { type: 'checkbox', checked: relay.enabled });
  const relayDevices = h('input', { type: 'checkbox', checked: !!relay.devices });
  const relayLimit = text(relay.device_limit || 2, { type: 'number', min: 1, max: 100 });
  const relayURL = text(relay.url || gw.relay_public_url);
  const backend = text(gw.openvpn_backend, { placeholder: 'http://192.0.2.20:8080' });
  const relayBackend = text(gw.relay_backend);
  const proxies = text(listText(saved.proxy_cidrs));
  const portal = text(gw.portal_listener, { placeholder: '192.0.2.10:9443' });
  const trusted = text(listText(gw.trusted_cidrs), { placeholder: 'Keep the gateway’s current list' });
  const vpn = {
    vpn_subnet: text(saved.vpn_subnet), guest_subnet: text(saved.guest_subnet),
    pool_first: text(saved.pool_first), pool_last: text(saved.pool_last),
    dns_servers: text(listText(saved.dns_servers)), routes: text(listText(saved.routes)),
  };
  const services = serviceEditor(gw);
  const links = guestLinkEditor(gw.guest_links || [], () => showGuestBlock());

  // An empty field means "the usual value", shown as its placeholder.
  const defaults = () => {
    const d = domain.value.trim(), backendHost = hostOf(backend.value.trim());
    return {
      website: d ? 'openvpn.' + d : '', vpnHost: d, relayURL: d ? `https://${d}:8443` : '',
      relayBackend: backendHost ? `${backendHost.includes(':') ? `[${backendHost}]` : backendHost}:8444` : '',
    };
  };
  const value = (input, fallback) => input.value.trim() || fallback || '';
  const portalPage = h('code');
  const refresh = () => {
    const d = defaults();
    website.placeholder = d.website || 'openvpn.example.com';
    vpnHost.placeholder = d.vpnHost || 'vpn.example.com';
    relayURL.placeholder = d.relayURL || 'https://example.com:8443';
    relayBackend.placeholder = d.relayBackend || '192.0.2.20:8444';
    portalPage.textContent = `https://${value(website, d.website) || 'openvpn.example.com'}/portal`;
  };
  [domain, website, backend].forEach(input => input.addEventListener('input', refresh));

  /* -- the relay's listeners and certificate --------------------------------- */
  const relayStatus = h('div', { class: 'status-list', role: 'status' }, h('div', { class: 'small muted' }, 'Asking the relay…'));
  const statusRow = (ok, label, detail) => h('div', { class: 'status-row ' + (ok === null ? 'unknown' : ok ? 'ok' : 'bad') },
    h('span', { class: 'status-dot' + (ok ? ' on' : '') }), h('strong', null, label), detail ? h('span', { class: 'small muted' }, detail) : null);
  api('/api/relay/status').then(status => {
    // Older relays report one "transport" and no "transports".
    const open = status.transports || { http2: status.transport === 'http2', http3: status.transport === 'http3' };
    const rows = [];
    if (!status.ready) rows.push(statusRow(false, 'Relay not reachable', 'its listeners cannot be checked now'));
    else {
      rows.push(statusRow(!!open.http3, 'HTTP/3 (UDP)', open.http3 ? 'open: devices use it first' : 'closed: devices use HTTP/2'));
      rows.push(statusRow(!!open.http2, 'HTTP/2 (TCP)', !open.http2 ? 'closed' : open.http2_direct ? 'open on this server (TLS here): the fallback' : 'open through the gateway: the fallback'));
    }
    const tls = status.tls;
    if (tls && tls.not_after) {
      const days = Math.floor((tls.not_after - Date.now() / 1000) / 86400);
      const good = tls.ok !== false && days >= 21;
      rows.push(statusRow(good, 'Certificate', `${(tls.names || []).join(', ') || 'relay'} · expires ${fmtDate(tls.not_after)} (${fmtDays(days)})`
        + (tls.issuer ? ` · ${tls.issuer}` : '') + (days < 21 && days >= 0 ? ' · renew soon' : '')));
    } else if (tls === null) {
      rows.push(statusRow(false, 'Certificate', 'none on this server yet'));
    }
    relayStatus.replaceChildren(...rows);
  }, () => { relayStatus.replaceChildren(statusRow(null, 'Relay status unavailable')); });

  /* -- guests: the gateway file's guest entries, and a check of what guests reach -- */
  // The same entries as network.export_gateway() writes (link_rule: host, and path "/" for the whole site).
  const guestBlock = h('pre', { class: 'log mono' });
  const guestText = () => {
    const rules = links.collect().map(link => {
      try { const url = new URL(link.url); return { host: url.hostname, path: link.whole_site ? '/' : url.pathname || '/' }; } catch (_) { return null; }
    }).filter(Boolean);
    return `"portal_listener": ${JSON.stringify(portal.value.trim())},\n"guest_links": ` +
      (rules.length ? '[\n' + rules.map(rule => '  ' + JSON.stringify(rule)).join(',\n') + '\n]' : '[]');
  };
  const showGuestBlock = () => { guestBlock.textContent = guestText(); };
  portal.addEventListener('input', showGuestBlock);
  const copyGuestBlock = () => navigator.clipboard.writeText(guestBlock.textContent)
    .then(() => toast('Copied', 'ok'), () => toast('Copying needs HTTPS - select the text instead', 'err'));

  let savedGuests = guestText();   // the check uses the saved settings
  const guestCheck = h('div', { class: 'detection-status', role: 'status', hidden: true });
  const checkGuests = async event => {
    const button = event.currentTarget;
    guestCheck.hidden = false;
    if (guestText() !== savedGuests) { guestCheck.textContent = 'Save first: the check uses the saved guest settings.'; return; }
    button.disabled = true;
    guestCheck.textContent = 'Checking from this server, the way guest connections go…';
    try {
      const result = await api('/api/network/guest-check', { method: 'POST' });
      guestCheck.replaceChildren(h('ul', { class: 'guest-check' }, result.targets.map(target =>
        h('li', { class: target.ok ? 'ok' : 'fail' },
          h('strong', null, (target.ok ? 'Guests can open ' : 'Guests cannot open ') + target.url + (target.portal ? ' (personal portal)' : '')),
          h('div', { class: 'small' }, 'Gateway: ' + target.http.message),
          h('div', { class: 'small' }, 'DNS: ' + target.dns.message)))));
    } catch (error) {
      guestCheck.textContent = error.message;
    } finally { button.disabled = false; }
  };

  /* -- the request body ---------------------------------------------------- */
  const collect = () => {
    const d = defaults();
    const websiteHost = value(website, d.website), relayOrigin = value(relayURL, d.relayURL), profileHost = value(vpnHost, d.vpnHost);
    return {
      vpn_subnet: vpn.vpn_subnet.value.trim(), guest_subnet: vpn.guest_subnet.value.trim(),
      pool_first: vpn.pool_first.value.trim(), pool_last: vpn.pool_last.value.trim(),
      dns_servers: parseList(vpn.dns_servers.value), routes: parseList(vpn.routes.value),
      proxy_cidrs: parseList(proxies.value),
      gateway: {
        domain: domain.value.trim(), openvpn_host: websiteHost, openvpn_backend: backend.value.trim(),
        relay_host: hostOf(relayOrigin), relay_backend: value(relayBackend, d.relayBackend), relay_public_url: relayOrigin,
        portal_listener: portal.value.trim(), trusted_cidrs: parseList(trusted.value), guest_links: links.collect(),
        ...services.collect(),
      },
      relay: { enabled: relayEnabled.checked, url: relayOrigin, devices: relayDevices.checked, device_limit: Number(relayLimit.value) || 2 },
      remote: profileHost ? { host: profileHost, ports: Object.fromEntries(vpnPorts.map(p => [p.proto, Number(p.input.value)])) } : null,
    };
  };

  /* -- what is unsaved, and what it takes ------------------------------------ */
  // Each pane's share of the request body, and the parts the gateway file and the VPN restart carry.
  const PARTS = {
    addresses: b => [b.gateway.domain, b.gateway.openvpn_host, b.remote],
    relay: b => [b.relay, b.gateway.relay_public_url],
    guests: b => [b.gateway.portal_listener, b.gateway.guest_links],
    vpn: b => [b.vpn_subnet, b.guest_subnet, b.pool_first, b.pool_last, b.dns_servers, b.routes],
    gateway: b => [b.gateway.openvpn_backend, b.gateway.relay_backend, b.proxy_cidrs, b.gateway.trusted_cidrs,
                   b.gateway.replace_services, b.gateway.services],
  };
  const GATEWAY_FILE = b => ['domain', 'openvpn_host', 'openvpn_backend', 'relay_host', 'relay_backend', 'relay_public_url',
    'portal_listener', 'trusted_cidrs', 'guest_links', 'replace_services', 'services'].map(k => b.gateway[k]);
  const snapshot = () => {
    const b = collect();
    return { parts: Object.fromEntries(Object.entries(PARTS).map(([k, f]) => [k, JSON.stringify(f(b))])),
             gateway: JSON.stringify(GATEWAY_FILE(b)), restart: JSON.stringify(PARTS.vpn(b)) };
  };
  let baseline = null;
  const changes = () => {
    const now = snapshot();
    return { panes: Object.keys(PARTS).filter(k => now.parts[k] !== baseline.parts[k]),
             gateway: now.gateway !== baseline.gateway, restart: now.restart !== baseline.restart };
  };
  const listeners = [];
  let pending = false;
  const changed = () => {
    if (pending || !baseline) return;
    pending = true;
    queueMicrotask(() => { pending = false; const c = changes(); listeners.forEach(fn => fn(c)); });
  };
  const markSaved = () => { baseline = snapshot(); savedGuests = guestText(); changed(); };

  /* -- address detection ---------------------------------------------------- */
  const detection = h('div', { class: 'detection-status', role: 'status' }, 'Looking up this server’s and the gateway’s addresses…');
  const suggestionTargets = { 'gateway.openvpn_backend': backend, 'gateway.portal_listener': portal, proxy_cidrs: proxies };
  const loopbackOnly = input => parseList(input.value).every(v => ['127.0.0.1/32', '::1/128', '127.0.0.1'].includes(v));
  const detect = async () => {
    try {
      const found = await api('/api/network/discovery', { method: 'POST', body: collect() });
      const filled = [];
      for (const [key, suggestion] of Object.entries(found.suggestions)) {
        const input = suggestionTargets[key];
        if (!input || (input.value.trim() && !(input === proxies && loopbackOnly(input)))) continue;
        input.value = Array.isArray(suggestion.value) ? listText(suggestion.value) : suggestion.value;
        input.title = suggestion.source;
        filled.push(input.closest('.field').querySelector('label').textContent);
      }
      refresh();
      showGuestBlock();
      changed();
      detection.replaceChildren(
        h('strong', null, `Gateway: ${found.gateway_ipv4 || 'not found'} · This server: ${found.server_ipv4 || 'not found'}`),
        h('p', { class: 'small muted' }, filled.length
          ? `Filled in: ${filled.join(', ')}. Check them, then save.`
          : 'Nothing was changed; fields that already have a value are kept.'));
    } catch (error) {
      detection.textContent = 'Addresses could not be detected; enter them by hand. ' + error.message;
    }
  };

  /* -- actions -------------------------------------------------------------- */
  const save = async () => {
    await api('/api/network/settings', { method: 'PUT', body: collect() });
    markSaved();
  };
  const restartVPN = async () => {
    await save();
    await api('/api/server/restart', { method: 'POST' });
    return 'Saved. The VPN is restarting; connected clients reconnect by themselves.';
  };
  const downloadGatewayFile = async () => {
    await save();
    const response = await fetch('/api/network/traefik.json');
    if (!response.ok) throw await responseError(response, 'Could not download the gateway file.');
    const url = URL.createObjectURL(await response.blob());
    const link = h('a', { href: url, download: 'network.private.json' });
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    return 'Saved. Copy network.private.json to the gateway and apply it there (Gateway → Applying the gateway file).';
  };

  /* -- panes ---------------------------------------------------------------- */
  const portField = p => field(`Public ${p.proto.toUpperCase()} port`, p.input);
  const panes = {
    addresses: h('div', { class: 'stack' },
      group(null, 'Empty fields use the value shown in grey.',
        h('div', { class: 'form cols' },
          field('Domain', domain),
          field('Website and personal portal', website),
          field('VPN address in profiles', vpnHost, 'The server name OpenVPN profiles connect to.'),
          h('div', { class: 'form cols' }, ...vpnPorts.map(portField))))),
    relay: h('div', { class: 'stack' },
      group('Listeners', null, relayStatus,
        more('How devices use HTTP/3 and HTTP/2',
          h('p', { class: 'small', style: 'margin:0' }, 'Every relay profile carries the relay address twice: HTTP/3 (UDP, straight to this server) first and HTTP/2 (TCP) as the fallback, with one credential. HTTP/3 needs the relay’s UDP port forwarded from the router to this server and the relay hostname’s certificate here. Profiles installed before 2.4.1 keep working over HTTP/2; download them again for HTTP/3.'))),
      group('Profiles', null,
        h('div', { class: 'form' },
          field('Apple relay URL', relayURL, 'The HTTPS address in relay profiles, e.g. https://example.com:8443.'),
          h('label', { class: 'check' }, relayEnabled, 'Offer Apple relay profiles'),
          h('label', { class: 'check' }, relayDevices, 'Each new profile works on one device only'),
          field('Configs per client', relayLimit, 'Device-bound relay profiles and Xray keys a client can have, together. A client can get its own number on its page.')),
        more('How one-device profiles work',
          h('p', { class: 'small', style: 'margin:0' }, 'The device makes its own key while the profile installs and gets a certificate from this server at /acme/ on the website hostname; a copy of the file installs nowhere else. Switching this on checks that the gateway signs such profiles and routes /acme/ here (Traefik 1.4.0 or later). Profiles installed earlier keep working until you revoke them on the client’s page. Installing a new profile on the same phone takes a new device slot: remove the old device there.')))),
    guests: h('div', { class: 'stack' },
      group(null, null,
        h('p', { class: 'small', style: 'margin:0' }, 'Guests get the internet through your network but no LAN. Of your websites they open only their portal, ',
          portalPage, ', and the guest links below.'),
        field('Guest portal listener on the gateway', portal, 'The gateway’s LAN address and portal port, e.g. 192.0.2.10:9443. Empty: no portal for guests.')),
      group(null, null, links.element),
      group('Check', null,
        h('div', { class: 'row' }, h('button', { class: 'btn', type: 'button', onClick: checkGuests }, 'Check guest access'),
          h('span', { class: 'small muted' }, 'Opens the saved portal and links from here, the way a guest’s connection goes.')),
        guestCheck,
        more('Only these entries, for network.private.json',
          h('p', { class: 'small muted', style: 'margin:0' }, 'Replace these two entries in the gateway’s network.private.json and keep the rest, then run ',
            h('code', null, './manage setup --network-file ./network.private.json'), ' and ', h('code', null, 'sudo docker compose up -d'),
            '. Each link’s hostname must already be a website on the gateway.'),
          guestBlock,
          h('div', null, h('button', { class: 'btn', type: 'button', onClick: copyGuestBlock }, 'Copy'))))),
    vpn: h('div', { class: 'stack' },
      group(null, 'Static client addresses must stay inside the subnet.',
        h('div', { class: 'form cols' },
          field('VPN subnet', vpn.vpn_subnet), field('Guest subnet', vpn.guest_subnet, 'Part of the VPN subnet; one address per guest device.'),
          field('First pool address', vpn.pool_first), field('Last pool address', vpn.pool_last),
          field('DNS servers', vpn.dns_servers, 'Guests can reach these for name lookups.'),
          field('Pushed routes', vpn.routes, 'Networks full-access clients reach through the VPN.')))),
    gateway: h('div', { class: 'stack' },
      group('This server, as the gateway sees it', null,
        h('div', { class: 'form cols' },
          field('This server’s web address', backend, 'How the gateway reaches the web UI, with the port.'),
          field('This server’s relay address', relayBackend, 'Where the gateway forwards Apple relay connections.'),
          field('Gateway addresses', proxies, 'Its source addresses here. Only they may set a request’s client address.')),
        detection,
        h('div', null, h('button', { class: 'btn', type: 'button', onClick: detect }, 'Detect addresses'))),
      more('Advanced: trusted networks and additional websites',
        field('Networks allowed into private websites', trusted,
          'Replaces the gateway’s list of networks trusted with its private websites. Empty keeps its current list.'),
        services.element),
      more('Applying the gateway file',
        h('ol', { class: 'setup-steps' },
          h('li', null, 'Save and download the gateway file (the button below).'),
          h('li', null, 'Copy network.private.json into the Traefik folder on the gateway and run ',
            h('code', null, './manage setup --network-file ./network.private.json'), ', then ',
            h('code', null, 'sudo docker compose up -d'), '.'),
          h('li', null, 'If the VPN network changed too, use Save and restart VPN here.')))),
  };
  Object.values(panes).forEach(pane => ['input', 'change', 'click'].forEach(type => pane.addEventListener(type, changed)));
  refresh();
  showGuestBlock();
  baseline = snapshot();      // before detection: what it fills in counts as unsaved
  detect();
  return { panes, save, restartVPN, downloadGatewayFile, changes: () => changes(), onChange: fn => listeners.push(fn), markSaved };
}

// Extra pages guests may open: websites under your domain, served by the gateway.
// Each link allows its own path and below, or its whole website.
function guestLinkEditor(saved, onChange) {
  const list = h('div', { class: 'stack' });
  const rows = [];
  const add = (link = { url: '', whole_site: false }) => {
    const row = {
      url: h('input', { class: 'input', type: 'url', value: link.url, placeholder: 'https://files.example.com/share/abc', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Guest link' }),
      scope: h('select', { class: 'input', 'aria-label': 'What the link allows' },
        h('option', { value: 'path' }, 'This page and below'), h('option', { value: 'site' }, 'The whole website')),
    };
    row.scope.value = link.whole_site ? 'site' : 'path';
    row.element = h('div', { class: 'guest-link' }, row.url, row.scope,
      h('button', { class: 'btn', type: 'button', onClick: () => { rows.splice(rows.indexOf(row), 1); row.element.remove(); onChange(); } }, 'Remove'));
    row.url.addEventListener('input', onChange);
    row.scope.addEventListener('change', onChange);
    rows.push(row);
    list.append(row.element);
  };
  saved.forEach(add);
  return {
    element: h('div', { class: 'form' },
      h('strong', null, 'Guest links'),
      h('p', { class: 'small muted', style: 'margin:0' }, 'Pages under your domain that guests may open as well. They appear on the guests’ portal page. ' +
        'After a change, apply the gateway file on the gateway. A page that loads files from elsewhere on its website may need the whole website.'),
      list, h('div', null, h('button', { class: 'btn', type: 'button', onClick: () => add() }, 'Add link'))),
    collect: () => rows.filter(row => row.url.value.trim())
      .map(row => ({ url: row.url.value.trim(), whole_site: row.scope.value === 'site' })),
  };
}

// Additional websites on the gateway. Off: the gateway keeps its own list.
function serviceEditor(gw) {
  const manage = h('input', { type: 'checkbox', checked: gw.replace_services || gw.services.length > 0 });
  const list = h('div', { class: 'stack' });
  const rows = [];
  const add = (service = {}) => {
    const input = key => h('input', { class: 'input', autocomplete: 'off', spellcheck: 'false',
      value: Array.isArray(service[key]) ? service[key].join(', ') : service[key] || '' });
    const row = { name: input('name'), host: input('host'), url: input('url'), paths: input('paths'),
                  public: h('input', { type: 'checkbox', checked: !!service.public }),
                  insecure_tls: h('input', { type: 'checkbox', checked: !!service.insecure_tls }) };
    row.element = h('div', { class: 'service-editor' },
      h('div', { class: 'form cols' }, field('Name', row.name), field('Hostname', row.host),
        field('Backend URL', row.url), field('Paths', row.paths, 'Optional; a trailing / includes everything below it.')),
      h('label', { class: 'check' }, row.public, 'Open to the internet (otherwise trusted networks only)'),
      h('label', { class: 'check' }, row.insecure_tls, 'Accept an unverified backend certificate'),
      h('div', null, h('button', { class: 'btn', onClick: () => { rows.splice(rows.indexOf(row), 1); row.element.remove(); } }, 'Remove')));
    rows.push(row);
    list.append(row.element);
  };
  gw.services.forEach(add);
  const editor = h('div', { class: 'form', hidden: !manage.checked },
    h('p', { class: 'notice' }, 'This list replaces the gateway’s additional websites. Include every website to keep.'),
    list, h('div', null, h('button', { class: 'btn', onClick: () => add() }, 'Add website')));
  manage.addEventListener('change', () => { editor.hidden = !manage.checked; });
  return {
    element: h('div', { class: 'form' }, h('label', { class: 'check' }, manage, 'Manage the gateway’s additional websites here'), editor),
    collect: () => ({
      replace_services: manage.checked,
      services: manage.checked ? rows.map(row => ({
        name: row.name.value.trim(), host: row.host.value.trim(), url: row.url.value.trim(),
        paths: row.paths.value.split(/[\s,]+/).filter(Boolean), public: row.public.checked, insecure_tls: row.insecure_tls.checked,
      })) : [],
    }),
  };
}

/* ------------------------------------------------------------------ page */
// What each pane is for, and what saving it takes ("needs"): shown in the sub-navigation and the pane header.
const SETTINGS_PANES = [
  { id: 'addresses', title: 'Public addresses', hint: 'Domain and what profiles connect to', form: true, needs: ['gateway', 'profiles'] },
  { id: 'relay', title: 'Apple relay', hint: 'Listeners, certificate, relay URL', form: true, needs: ['gateway', 'profiles'] },
  { id: 'guests', title: 'Guests', hint: 'Portal and guest links', form: true, needs: ['gateway'] },
  { id: 'vpn', title: 'VPN network', hint: 'Subnets, pool, DNS, routes', form: true, needs: ['restart'] },
  { id: 'gateway', title: 'Gateway', hint: 'How Traefik reaches this server', form: true, needs: ['gateway'] },
  { id: 'telegram', title: 'Telegram', hint: 'Bot token and your chat', needs: ['own'] },
  { id: 'xray', title: 'Xray', hint: '3x-ui inbound for client keys', needs: ['own'] },
  { id: 'router', title: 'Router', hint: 'Traffic by podkop section', needs: ['own'] },
  { id: 'account', title: 'Account', hint: 'Password, appearance, version', needs: ['own'] },
];
const SETTINGS_NEEDS = {
  restart: ['Applies after a VPN restart', 'restart'],
  gateway: ['Apply the gateway file on the gateway', 'gateway'],
  profiles: ['New downloads of profiles carry it', 'profiles'],
  own: ['Saved by its own buttons', 'own'],
};

function settingsView(el) {
  const body = h('div', { class: 'settings-layout' }, h('div', { class: 'small muted' }, 'Loading…'));
  el.append(topbar('Settings', 'Network, relay, guests, gateway, router and your account'), body);
  (async () => {
    let general, relay, network;
    try {
      [general, relay, network] = await Promise.all([api('/api/settings'), api('/api/relay/settings'), api('/api/network/settings')]);
    } catch (e) { body.replaceChildren(h('div', { class: 'empty' }, e.message)); toast(e.message, 'err'); return; }
    const form = networkForm(network, relay, general);
    const panes = {
      ...form.panes,
      telegram: telegramCard(),
      xray: xrayCard(),
      router: routerCard(),
      account: h('div', { class: 'stack' }, h('div', { class: 'grid two' }, passwordCard(), appearanceCard()),
        card('About', h('dl', { class: 'kv' },
          h('dt', null, 'UI version'), h('dd', null, general.version),
          h('dt', null, 'Signed in as'), h('dd', null, state.user.username),
          h('dt', null, 'Poll interval'), h('dd', null, `${general.poll_interval} s`),
          h('dt', null, '2FA issuer'), h('dd', null, general.tfa_issuer)))),
    };

    /* -- navigation: a list on wide screens, a menu on narrow ones -- */
    const stored = (() => { try { return localStorage.getItem('settings-pane'); } catch (_) { return null; } })();
    const known = id => SETTINGS_PANES.some(p => p.id === id);
    let current = known(state.route.param) ? state.route.param : known(stored) ? stored : 'addresses';
    const navButtons = {};
    const nav = h('nav', { class: 'settings-nav', 'aria-label': 'Settings sections' }, SETTINGS_PANES.map(p => {
      navButtons[p.id] = h('button', { type: 'button', class: 'settings-nav-item', onClick: () => show(p.id) },
        h('span', { class: 'settings-nav-title' }, p.title, h('span', { class: 'dirty-dot', title: 'Unsaved changes', hidden: true })),
        h('span', { class: 'settings-nav-hint' }, p.hint));
      return navButtons[p.id];
    }));
    const picker = h('select', { class: 'input settings-picker', 'aria-label': 'Settings section', onChange: e => show(e.target.value) },
      SETTINGS_PANES.map(p => h('option', { value: p.id }, p.title)));
    const header = h('div', { class: 'settings-pane-head' });
    const content = h('div', { class: 'settings-pane-body network-settings' });

    /* -- the action bar of the network form -- */
    const status = h('div', { class: 'settings-bar-status', role: 'status', 'aria-live': 'polite' });
    const busy = fn => async event => {
      const buttons = bar.querySelectorAll('button');
      buttons.forEach(b => { b.disabled = true; });
      try { const said = await fn(event); if (said) { toast(said, 'ok'); lastSaid = said; } }
      catch (error) { toast(error.message, 'err'); lastSaid = error.message; }
      finally { buttons.forEach(b => { b.disabled = false; }); update(form.changes()); }
    };
    let lastSaid = '';
    const saveBtn = h('button', { class: 'btn', type: 'button', onClick: busy(async () => { await form.save(); return 'Saved.'; }) }, 'Save');
    const restartBtn = h('button', { class: 'btn', type: 'button', onClick: busy(form.restartVPN) }, 'Save and restart VPN');
    const gatewayBtn = h('button', { class: 'btn', type: 'button', onClick: busy(form.downloadGatewayFile) }, 'Save and download gateway file');
    const discardBtn = h('button', { class: 'btn ghost', type: 'button', onClick: async () => {
      if (!await confirmDialog('Discard changes', 'Unsaved changes in ' + paneTitles(form.changes().panes) + ' are dropped and the saved settings shown again.', 'Discard', true)) return;
      form.markSaved(); renderView();
    } }, 'Discard');
    const bar = h('div', { class: 'settings-bar' }, status, h('div', { class: 'settings-bar-actions' }, discardBtn, saveBtn, restartBtn, gatewayBtn));
    const paneTitles = ids => ids.map(id => SETTINGS_PANES.find(p => p.id === id).title).join(', ');
    const update = c => {
      const dirty = c.panes.length > 0;
      SETTINGS_PANES.forEach(p => { navButtons[p.id].querySelector('.dirty-dot').hidden = !c.panes.includes(p.id); });
      [...picker.options].forEach(o => { const p = SETTINGS_PANES.find(q => q.id === o.value); o.textContent = p.title + (c.panes.includes(p.id) ? ' •' : ''); });
      bar.classList.toggle('dirty', dirty);
      discardBtn.hidden = !dirty;
      saveBtn.disabled = !dirty;
      // The button that does what the changes need is the primary one.
      saveBtn.classList.toggle('primary', dirty && !c.restart && !c.gateway);
      restartBtn.classList.toggle('primary', c.restart);
      gatewayBtn.classList.toggle('primary', c.gateway && !c.restart);
      if (!dirty) {
        status.replaceChildren(h('strong', null, 'All changes saved'), lastSaid ? h('span', { class: 'small muted' }, lastSaid) : null);
        return;
      }
      lastSaid = '';
      const needs = [];
      if (c.restart) needs.push(h('span', { class: 'need-chip restart' }, 'Needs a VPN restart'));
      if (c.gateway) needs.push(h('span', { class: 'need-chip gateway' }, 'Needs the gateway file'));
      if (!needs.length) needs.push(h('span', { class: 'need-chip' }, 'Saving is enough'));
      status.replaceChildren(h('strong', null, 'Unsaved: ' + paneTitles(c.panes)), h('div', { class: 'row needs' }, needs));
    };
    form.onChange(update);

    const show = id => {
      current = id;
      state.route.param = id;     // a re-render (Discard) opens the same pane
      const p = SETTINGS_PANES.find(q => q.id === id);
      Object.entries(navButtons).forEach(([key, b]) => { b.classList.toggle('active', key === id); b.setAttribute('aria-current', key === id ? 'page' : 'false'); });
      picker.value = id;
      header.replaceChildren(h('h2', null, p.title), h('p', { class: 'small muted' }, p.hint),
        h('div', { class: 'row needs' }, p.needs.map(n => h('span', { class: 'need-chip ' + SETTINGS_NEEDS[n][1] }, SETTINGS_NEEDS[n][0]))));
      content.replaceChildren(panes[id]);
      bar.hidden = !p.form;
      try { localStorage.setItem('settings-pane', id); } catch (_) { /* private mode */ }
      history.replaceState(null, '', '#/settings/' + id);
    };
    body.replaceChildren(nav, h('div', { class: 'settings-main' }, picker, h('div', { class: 'card settings-pane' }, header, content, bar)));
    show(current);
    update(form.changes());

    /* -- unsaved changes: ask before leaving the page -- */
    const dirtyNow = () => body.isConnected && form.changes().panes.length > 0;
    const guardClick = async event => {
      if (!body.isConnected) { cleanup(); return; }
      const a = event.target.closest('a[href^="#/"]');
      if (!a || !dirtyNow()) return;
      const href = a.getAttribute('href');
      event.preventDefault(); event.stopPropagation();
      const sub = href.match(/^#\/settings(?:\/([\w-]+))?$/);
      if (sub) { if (sub[1] && known(sub[1])) show(sub[1]); return; }   // staying on this page keeps the changes
      if (await confirmDialog('Leave without saving?', 'Unsaved changes in ' + paneTitles(form.changes().panes) + ' will be lost.', 'Leave', true)) {
        cleanup(); go(href);
      }
    };
    const guardUnload = event => { if (dirtyNow()) { event.preventDefault(); event.returnValue = ''; } else if (!body.isConnected) cleanup(); };
    const cleanup = () => { document.removeEventListener('click', guardClick, true); window.removeEventListener('beforeunload', guardUnload); };
    document.addEventListener('click', guardClick, true);
    window.addEventListener('beforeunload', guardUnload);
  })();
  return null;
}

function passwordCard() {
  const current = h('input', { class: 'input', type: 'password', autocomplete: 'current-password' });
  const password = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', minlength: 8 });
  const repeat = h('input', { class: 'input', type: 'password', autocomplete: 'new-password' });
  const change = async () => {
    if (password.value !== repeat.value) { toast('Passwords do not match', 'err'); return; }
    await withToast(api('/api/me/password', { method: 'POST', body: { current: current.value, new: password.value } }), 'Password changed');
    current.value = password.value = repeat.value = '';
  };
  return card('Change password', h('div', { class: 'form' },
    field('Current password', current), field('New password', password, 'At least 8 characters'), field('Repeat new password', repeat),
    h('div', null, h('button', { class: 'btn primary', onClick: () => change().catch(() => {}) }, 'Change password'))));
}

function appearanceCard() {
  const theme = h('div', { class: 'seg' });
  const current = localStorage.getItem('theme') || 'system';
  for (const t of ['system', 'light', 'dark']) {
    theme.append(h('button', { class: t === current ? 'active' : '', onClick: e => {
      localStorage.setItem('theme', t); applyTheme();
      theme.querySelectorAll('button').forEach(b => b.classList.toggle('active', b === e.currentTarget));
    } }, t));
  }
  return card('Appearance', h('div', { class: 'row' }, theme));
}

// Xray through 3x-ui: the inbound whose clients this UI keeps, one per client.
function xrayCard() {
  const body = h('div', { class: 'stack' }, h('div', { class: 'small muted' }, 'Loading…'));
  (async () => {
    let info;
    try { info = await api('/api/xray/settings'); } catch (e) { setChildren(body, h('div', { class: 'notice', role: 'alert' }, e.message)); return; }
    const on = h('input', { type: 'checkbox', checked: info.enabled });
    const inbound = h('select', { class: 'input', 'aria-label': 'Xray inbound' },
      h('option', { value: '' }, info.inbounds.length ? 'Choose an inbound' : 'No inbounds in 3x-ui yet'),
      info.inbounds.map(i => h('option', { value: String(i.id), selected: i.id === info.inbound_id }, `${i.remark || i.tag} · ${i.protocol}${i.security ? ' + ' + i.security : ''} · port ${i.port}`)));
    setChildren(body,
      info.error ? h('div', { class: 'notice', role: 'alert' }, info.error) : null,
      info.panel_url ? h('p', { style: 'margin:0' }, h('a', { href: info.panel_url, target: '_blank', rel: 'noopener' }, 'Open the 3x-ui panel ↗'),
        h('span', { class: 'small muted' }, ' — through the gateway, from trusted networks (download the gateway file and apply it once).')) : null,
      h('p', { class: 'small muted', style: 'margin:0' }, 'Create the inbound in the 3x-ui panel (VLESS + REALITY over TCP works best), forward its port on the router, then choose it here. ',
        'Clients get a key from Share link or the Telegram bot; it stops working when their certificate ends. Xray gives internet only: private ranges and this server’s networks are blocked for everyone.'),
      h('label', { class: 'check' }, on, 'Offer Xray keys to clients'),
      field('Inbound', inbound),
      h('div', { class: 'row' }, h('button', { class: 'btn primary', onClick: async () => {
        try {
          await withToast(api('/api/xray/settings', { method: 'PUT', body: { enabled: on.checked, inbound_id: inbound.value ? Number(inbound.value) : null } }), 'Xray settings saved');
        } catch (_) {}
      } }, 'Save')),
      h('p', { class: 'small muted', style: 'margin:0' }, 'The panel login is printed once in docker compose logs xui. The panel listens on XUI_LISTEN, port XUI_PORT.'));
  })();
  return body;
}

// The Telegram bot: its token (never shown again) and the admin chat that gets access requests.
function telegramCard() {
  const body = h('div', { class: 'stack' }, h('div', { class: 'small muted' }, 'Loading…'));
  const render = info => {
    const token = h('input', { class: 'input', type: 'password', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Bot token',
      placeholder: info.configured ? (info.token_from_env ? 'From .env · paste one to replace it' : 'Saved · leave blank to keep it') : 'Paste the token from @BotFather' });
    const chat = h('input', { class: 'input', inputmode: 'numeric', value: info.admin_chat_id ?? '', placeholder: 'e.g. 123456789', 'aria-label': 'Your chat ID' });
    const save = async tokenValue => {
      const id = chat.value.trim();
      if (id && !/^-?\d+$/.test(id)) { toast('The chat ID is a number', 'err'); return; }
      try {
        render(await withToast(api('/api/telegram/settings', { method: 'PUT', body: { token: tokenValue, admin_chat_id: id ? Number(id) : null } }), 'Telegram settings saved'));
      } catch (_) {}
    };
    setChildren(body,
      h('p', { class: 'small muted', style: 'margin:0' }, info.configured
        ? ['The bot ', info.bot_username ? h('a', { href: `https://t.me/${info.bot_username}`, target: '_blank', rel: 'noopener' }, '@' + info.bot_username) : '(connecting…)', ' is on. Clients write to it; you enter their username on the client page under Telegram & portal.']
        : 'Create a bot with @BotFather (/newbot) and paste its token here. The server needs outgoing HTTPS to api.telegram.org.'),
      field('Bot token', token),
      field('Your chat ID', chat, 'Access requests and newly linked accounts go here. To find it, send /start to the bot from your own account: it answers with your Telegram ID. Press Start in the bot before testing.'),
      h('div', { class: 'row' },
        h('button', { class: 'btn primary', onClick: () => save(token.value.trim() ? token.value.trim() : null) }, 'Save'),
        h('button', { class: 'btn', onClick: async () => { try { await withToast(api('/api/telegram/test', { method: 'POST', body: {} }), 'Test message sent'); } catch (_) {} } }, 'Send test message'),
        info.configured && !info.token_from_env ? h('button', { class: 'btn danger', onClick: async () => {
          if (await confirmDialog('Remove the bot token', 'The bot stops answering until a token is saved again.', 'Remove', true)) save('');
        } }, 'Remove token') : null));
  };
  api('/api/telegram/settings').then(render, e => setChildren(body, h('div', { class: 'notice', role: 'alert' }, e.message)));
  return body;
}
