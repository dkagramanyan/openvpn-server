'use strict';
/* Personal portal: a client account downloads its own profiles. Passwords come from the Telegram bot. */

function portalView(el) {
  const body = h('div', { class: 'stack portal-content' });
  const signOutButton = h('button', { class: 'btn', onClick: async () => {
    try { await api('/api/portal/logout', { method: 'POST' }); } finally { signOut(); }
  } }, icon('logout'), 'Sign out');
  el.append(topbar('My profiles', state.user.username, signOutButton), body);
  (async () => {
    try {
      const profile = await api('/api/portal');
      const own = sectionsCard('/api/portal/sections', { period: true });
      own.load();
      body.replaceChildren(connectCard(profile), relayActivityPanel(), own.card,
        h('p', { class: 'small muted' }, profile.telegram_bot ? ['For a new password, send /password to ', h('a', { href: `https://t.me/${profile.telegram_bot}`, rel: 'noopener' }, '@' + profile.telegram_bot), ' in Telegram.'] : 'For a new password, ask the administrator.'));
    } catch (error) {
      body.replaceChildren(h('div', { class: 'notice', role: 'alert' }, error.message),
        h('button', { class: 'btn', onClick: () => renderView() }, 'Try again'));
    }
  })();
  return null;
}

const setupSteps = items => h('ol', { class: 'setup-steps' }, items.map(item => h('li', null, item)));

// The two ways to connect; the one that fits this device is open.
function connectCard(profile) {
  const apple = /iPhone|iPad|Macintosh/.test(navigator.userAgent);
  const downloadError = h('div', { class: 'notice', role: 'alert', hidden: true });
  const showError = error => { downloadError.hidden = false; downloadError.textContent = error.message; };
  const access = profile.guest
    ? ['Guest access', 'Internet through this server, without local network access.']
    : ['Full access', 'Internet and local network access through this server.'];

  const appleMethod = h('details', { class: 'connection-method', open: apple },
    h('summary', null, 'Apple relay · iPhone, iPad and Mac'),
    h('div', { class: 'stack' },
      h('p', null, 'Uses the relay built into your Apple device. Open this page in Safari to install the profile.'),
      setupSteps([
        h('div', { class: 'stack' },
          h('span', null, 'Download your personal Apple relay profile. Tap Allow when Safari asks.'),
          relayButton(profile, false, true, showError), downloadError),
        'Open Settings → General → VPN & Device Management, select the downloaded profile, then tap Install.',
        'Follow the prompts on the screen.',
      ]),
      profile.relay_available ? null
        : h('p', { class: 'small muted' }, 'Apple relay is not enabled on this server yet. Ask your administrator, or use OpenVPN below.'),
      h('a', { href: 'https://support.apple.com/102400', target: '_blank', rel: 'noopener' }, 'Apple’s profile installation guide')));

  const openvpnMethod = h('details', { class: 'connection-method', open: !apple },
    h('summary', null, 'OpenVPN · all devices'),
    h('div', { class: 'stack' },
      setupSteps([
        'Install the OpenVPN Connect app.',
        'Download your personal OpenVPN profile.',
        'Open the file in OpenVPN Connect, import it and tap Connect. Enter the profile password or verification code if you were given one.',
      ]),
      h('a', { class: 'btn primary', href: '/api/portal/ovpn', download: profile.name + '.ovpn' }, icon('download'), 'Download OpenVPN profile')));

  const links = profile.links && profile.links.length ? h('div', { class: 'stack' },
    h('strong', null, 'Pages you can open'),
    h('ul', { class: 'guest-links' }, profile.links.map(url => h('li', null, h('a', { href: url, target: '_blank', rel: 'noopener' }, url))))) : null;
  return card('Connect your device', h('div', { class: 'stack' },
    h('div', { class: 'access-summary' }, h('strong', null, access[0]), h('span', { class: 'small muted' }, access[1])),
    links,
    h('p', null, 'Choose one method. An installed profile keeps working; you only need to download it again if your administrator asks you to.'),
    appleMethod, openvpnMethod,
    h('span', { class: 'small muted' }, `Personal profile ${profile.name} · valid until ${fmtDate(profile.expires_at)}`)));
}

// The account's own relay sessions, loaded while the panel is open.
function relayActivityPanel() {
  const activity = h('div', { class: 'stack' });
  const load = async () => {
    try {
      const status = await api('/api/portal/relay/status');
      const own = status.clients[0] || {};
      const running = status.ready && status.policy_ready !== false;
      activity.replaceChildren(
        h('strong', null, running ? `${fmtNum(own.active || 0)} open connections` : 'The relay is temporarily unavailable'),
        relaySessionList(status.sessions || []),
        (status.flows || []).length ? h('div', { class: 'stack' }, h('strong', null, 'My recent connections'),
          h('div', { class: 'table-wrap' }, h('table', { class: 'tbl' },
            h('thead', null, h('tr', null, ['Ended', 'Destination', 'Result'].map(t => h('th', null, t)), h('th', { class: 'r' }, 'Download'), h('th', { class: 'r' }, 'Upload'))),
            h('tbody', null, status.flows.slice(0, 30).map(f => h('tr', null, h('td', { class: 'nowrap' }, fmtDateTime(f.ts)), h('td', { class: 'mono small' }, f.target || '—'),
              h('td', { class: 'small' }, f.kind === 'closed' ? 'ok' : `${f.kind} · ${(f.reason || '').replace(/_/g, ' ')}`),
              h('td', { class: 'r num' }, fmtBytes(f.bytes_down)), h('td', { class: 'r num' }, fmtBytes(f.bytes_up)))))))) : null,
        h('p', { class: 'small muted' }, 'An idle device may show no connections. There is no need to download the profile again after a server restart.'));
    } catch (error) {
      activity.replaceChildren(h('p', null, 'Your connection activity cannot be loaded right now. Try again in a moment.'),
        h('button', { class: 'btn', onClick: load }, 'Try again'));
    }
  };
  const panel = h('details', { class: 'portal-panel' }, h('summary', null, 'My relay activity'), activity);
  let polling = false;
  panel.addEventListener('toggle', () => {
    if (!panel.open) return;
    load();
    if (!polling) { polling = true; every(10000, () => { if (panel.open) load(); }); }
  });
  return panel;
}
