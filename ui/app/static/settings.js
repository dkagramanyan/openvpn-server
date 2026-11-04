'use strict';
/* Settings page: network and gateway settings, password, appearance. */

/* --------------------------------------------------------------- network */
// One form for everything the clients and the Traefik gateway need to know.
// `saved` is GET /api/network/settings, `relay` GET /api/relay/settings and
// `general` GET /api/settings (the profile address and OpenVPN's sockets).
function networkSettingsCard(saved, relay, general) {
  const gw = saved.gateway;
  const listText = list => (list || []).join(', ');
  const parseList = value => value.split(/[\s,]+/).filter(Boolean);
  const text = (value, attrs = {}) => h('input', { class: 'input', value: value || '', autocomplete: 'off', spellcheck: 'false', ...attrs });
  const hostOf = url => { try { return new URL(url).hostname; } catch (_) { return ''; } };
  const section = (title, help, ...children) =>
    h('section', { class: 'settings-section' }, h('h3', null, title), help ? h('p', { class: 'small muted' }, help) : null, ...children);

  /* -- inputs ------------------------------------------------------------ */
  const domain = text(gw.domain, { placeholder: 'example.com' });
  const website = text(gw.openvpn_host);
  const vpnHost = text(general.remote.host);
  const vpnPorts = general.listen.map(listener => {
    const remote = general.remote.remotes.find(r => r.proto === listener.proto) || listener;
    return { proto: listener.proto, input: text(remote.port, { type: 'number', min: 1, max: 65535 }) };
  });
  const relayEnabled = h('input', { type: 'checkbox', checked: relay.enabled });
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
  const links = guestLinkEditor(gw.guest_links || []);

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
      relay: { enabled: relayEnabled.checked, url: relayOrigin },
      remote: profileHost ? { host: profileHost, ports: Object.fromEntries(vpnPorts.map(p => [p.proto, Number(p.input.value)])) } : null,
    };
  };

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
      detection.replaceChildren(
        h('strong', null, `Gateway: ${found.gateway_ipv4 || 'not found'} · This server: ${found.server_ipv4 || 'not found'}`),
        h('p', { class: 'small muted' }, filled.length
          ? `Filled in: ${filled.join(', ')}. Check them before saving.`
          : 'Nothing was changed; fields that already have a value are kept.'));
    } catch (error) {
      detection.textContent = 'Addresses could not be detected; enter them by hand. ' + error.message;
    }
  };

  /* -- actions -------------------------------------------------------------- */
  const message = h('div', { class: 'notice', role: 'status', hidden: true });
  const say = (text, kind = 'status') => { message.hidden = false; message.textContent = text; message.setAttribute('role', kind); };
  const save = () => api('/api/network/settings', { method: 'PUT', body: collect() });
  const action = (label, primary, run) => h('button', { class: 'btn' + (primary ? ' primary' : ''), onClick: async event => {
    const button = event.currentTarget;
    button.disabled = true; message.hidden = true;
    try { say(await run()); } catch (error) { say(error.message, 'alert'); } finally { button.disabled = false; }
  } }, label);
  const downloadGatewayFile = async () => {
    await save();
    const response = await fetch('/api/network/traefik.json');
    if (!response.ok) throw await responseError(response, 'Could not download the gateway file.');
    const url = URL.createObjectURL(await response.blob());
    const link = h('a', { href: url, download: 'network.private.json' });
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    return 'Saved. Copy network.private.json to the gateway and apply it there (see the steps below).';
  };

  /* -- layout ---------------------------------------------------------------- */
  const portField = p => field(`Public ${p.proto.toUpperCase()} port`, p.input);
  const root = h('div', { class: 'form network-settings' },
    section('Public addresses', 'What clients connect to. Empty fields use the value shown in grey.',
      h('div', { class: 'form cols' },
        field('Domain', domain),
        field('Website and personal portal', website),
        field('VPN address in profiles', vpnHost),
        h('div', { class: 'form cols' }, ...vpnPorts.map(portField)),
        field('Apple relay URL', relayURL, 'Clients connect here; the gateway forwards it to this server.'),
        h('label', { class: 'check' }, relayEnabled, 'Offer Apple relay profiles'))),
    section('Guests', null,
      h('p', null, 'Guests of OpenVPN and the Apple relay get the internet through your network (with its filtering) but no LAN access. Of your websites they can open only their personal portal, ',
        portalPage, ', to change their password and download their profiles, and the guest links below.'),
      field('Guest portal listener on the gateway', portal,
        'The gateway’s LAN address and its portal port (9443). A guest’s HTTPS connections to the gateway go there. Empty: guests cannot open the portal.'),
      links.element),
    section('Gateway', 'How the Traefik gateway reaches this server, and which of its addresses this server trusts.',
      h('div', { class: 'form cols' },
        field('This server’s web address', backend, 'As the gateway reaches the web UI, including the port.'),
        field('This server’s relay address', relayBackend, 'Where the gateway forwards Apple relay connections.'),
        field('Gateway addresses', proxies, 'Its source addresses here. Only they may set the client address of a request.')),
      detection,
      h('div', null, h('button', { class: 'btn', onClick: detect }, 'Detect addresses'))),
    section('VPN network', 'Changes take effect when the VPN restarts. Static client addresses must stay inside the subnet.',
      h('div', { class: 'form cols' },
        field('VPN subnet', vpn.vpn_subnet), field('Guest subnet', vpn.guest_subnet, 'Part of the VPN subnet; one address per guest device.'),
        field('First pool address', vpn.pool_first), field('Last pool address', vpn.pool_last),
        field('DNS servers', vpn.dns_servers, 'Guests can reach these for name lookups.'),
        field('Pushed routes', vpn.routes, 'Networks full-access clients reach through the VPN.'))),
    h('details', { class: 'settings-details' }, h('summary', null, 'Advanced gateway settings'),
      h('div', { class: 'form' },
        field('Networks allowed into private websites', trusted,
          'Replaces the gateway’s list of networks trusted with its private websites. Empty keeps its current list.'),
        services.element)),
    message,
    h('div', { class: 'row settings-actions' },
      action('Save', false, async () => { await save(); return 'Saved. Restart the VPN to apply network changes.'; }),
      action('Save and restart VPN', false, async () => {
        await save();
        await api('/api/server/restart', { method: 'POST' });
        return 'Saved. The VPN is restarting; connected clients reconnect by themselves.';
      }),
      action('Save and download gateway file', true, downloadGatewayFile)),
    h('details', { class: 'settings-details' }, h('summary', null, 'Applying the gateway file'),
      h('ol', { class: 'setup-steps' },
        h('li', null, 'Save and download the gateway file.'),
        h('li', null, 'Copy network.private.json into the Traefik folder on the gateway and run ',
          h('code', null, './manage setup --network-file ./network.private.json'), ', then ',
          h('code', null, 'sudo docker compose up -d'), '.'),
        h('li', null, 'Back here, use Save and restart VPN.'))));
  refresh();
  detect();
  return card('Network', root);
}

// Extra pages guests may open: websites under your domain, served by the gateway.
// Each link allows its own path and below, or its whole website.
function guestLinkEditor(saved) {
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
      h('button', { class: 'btn', type: 'button', onClick: () => { rows.splice(rows.indexOf(row), 1); row.element.remove(); } }, 'Remove'));
    rows.push(row);
    list.append(row.element);
  };
  saved.forEach(add);
  return {
    element: h('div', { class: 'form' },
      h('strong', null, 'Guest links'),
      h('p', { class: 'small muted' }, 'Pages under your domain that guests may open as well. They appear on the guests’ portal page. ' +
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
function settingsView(el) {
  const body = h('div', { class: 'stack' });
  el.append(topbar('Settings'), body);
  (async () => {
    let general, relay, network;
    try {
      [general, relay, network] = await Promise.all([api('/api/settings'), api('/api/relay/settings'), api('/api/network/settings')]);
    } catch (e) { toast(e.message, 'err'); return; }
    body.append(networkSettingsCard(network, relay, general),
      h('div', { class: 'grid two' }, passwordCard(), appearanceCard()),
      card('About', h('dl', { class: 'kv' },
        h('dt', null, 'UI version'), h('dd', null, general.version),
        h('dt', null, 'Signed in as'), h('dd', null, state.user.username),
        h('dt', null, 'Poll interval'), h('dd', null, `${general.poll_interval} s`),
        h('dt', null, '2FA issuer'), h('dd', null, general.tfa_issuer))));
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
