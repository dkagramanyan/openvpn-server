'use strict';
/* Personal portal: a client account downloads its own profiles and changes its password. */

function portalView(el) {
  const body = h('div', { class: 'stack portal-content' });
  const signOutButton = h('button', { class: 'btn', onClick: async () => {
    try { await api('/api/portal/logout', { method: 'POST' }); } finally { signOut(); }
  } }, icon('logout'), 'Sign out');
  el.append(topbar('My profiles', state.user.username, signOutButton), body);
  (async () => {
    try {
      const profile = await api('/api/portal');
      body.replaceChildren(connectCard(profile), relayActivityPanel(), h('details', { class: 'portal-panel' },
        h('summary', null, 'Change my password'), portalPasswordForm()));
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
    ? ['Guest access', (profile.links || []).length ? 'Your profiles open only this page and the pages listed below. They do not give internet or local network access.' : 'Your profiles open only this page. They do not give internet or local network access.']
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

function portalPasswordForm() {
  const input = (autocomplete, extra = {}) => h('input', { class: 'input', type: 'password', autocomplete, required: true, ...extra });
  const current = input('current-password');
  const password = input('new-password', { minlength: 8 }), repeat = input('new-password', { minlength: 8 });
  const message = h('p', { class: 'form-message', role: 'status', hidden: true });
  const button = h('button', { class: 'btn primary', type: 'submit' }, 'Change password');
  const say = text => { message.hidden = false; message.textContent = text; };
  return h('form', { class: 'form', onSubmit: async event => {
    event.preventDefault();
    if (password.value !== repeat.value) { say('The new passwords do not match. Enter them again.'); return; }
    button.disabled = true;
    try {
      await api('/api/portal/password', { method: 'POST', body: { current: current.value, new: password.value } });
      current.value = password.value = repeat.value = '';
      say('Your password has been changed.');
    } catch (error) { say(error.message); } finally { button.disabled = false; }
  } }, field('Current password', current), field('New password', password, 'At least 8 characters.'),
    field('Repeat new password', repeat), message, button);
}
