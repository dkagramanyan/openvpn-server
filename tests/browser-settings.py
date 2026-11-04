#!/usr/bin/env python3
"""Browser regressions with synthetic API responses; no production/network probes.

Run with Playwright installed: python tests/browser-settings.py
Uses system Chrome by default. Set CHROME_BIN to another Chromium binary.
"""
import copy
import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import sync_playwright

STATIC = Path(__file__).resolve().parents[1] / 'ui/app/static'
SHOTS = os.environ.get('SCREENSHOT_DIR', '/tmp')
BASE_NETWORK = dict(vpn_subnet='10.8.0.0/24', pool_first='10.8.0.2', pool_last='10.8.0.99', guest_subnet='10.8.0.128/25',
    dns_servers=['1.1.1.1'], routes=[], proxy_cidrs=['127.0.0.1/32'],
    gateway=dict(domain='example.test', openvpn_host='openvpn.example.test', openvpn_backend='', relay_host='example.test',
        relay_backend='', relay_public_url='https://example.test:9444', portal_listener='', trusted_cidrs=['192.0.2.0/24'], guest_links=[],
        services=[], replace_services=False))


def scenario(browser, portal=False):
    context = browser.new_context(viewport={'width': 390 if portal else 1440, 'height': 844 if portal else 1000}, accept_downloads=True,
        user_agent='Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1')
    page = context.new_page()
    errors, saved, calls, native = [], [], [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    network = copy.deepcopy(BASE_NETWORK)
    relay = dict(enabled=True, url='https://example.test:9444', transport='http2')
    block_save = [False]
    def handle(route):
        path = urlsplit(route.request.url).path
        method = route.request.method
        if path.startswith('/api/'):
            calls.append((method, path))
            if path == '/api/portal/relay.mobileconfig':
                native.append((method, parse_qs(route.request.post_data)))
                route.fulfill(content_type='application/x-apple-aspen-config', headers={'Content-Disposition': 'attachment; filename="alice-relay.mobileconfig"'}, body=b'<?xml version="1.0"?><plist><dict/></plist>')
                return
            if path in ('/api/portal/relay/status', '/api/portal/password', '/api/clients/alice/relay-download'):
                route.fulfill(status=403, content_type='text/plain', body='Forbidden')
                return
            if path == '/api/network/discovery':
                result = dict(server_ipv4='192.0.2.20', gateway_ipv4='192.0.2.10', website_ipv4s=['192.0.2.10'],
                    interfaces=[dict(name='eth0', address='192.0.2.20', network='192.0.2.0/24')], suggestions={
                        'gateway.openvpn_backend':dict(value='http://192.0.2.20:8080', source='detected server route'),
                        'gateway.portal_listener':dict(value='192.0.2.10:9443', source='actual proxy connection'),
                        'proxy_cidrs':dict(value=['192.0.2.10/32'], source='actual proxy'),
                    })
            elif path == '/api/network/settings' and method == 'PUT':
                if block_save[0]:
                    route.fulfill(status=403, content_type='text/plain', body='Forbidden'); return
                body = route.request.post_data_json
                saved.append(body)
                network.update({key:value for key,value in body.items() if key not in ('relay','remote')})
                relay.update(body['relay'])
                result = {'settings':network, 'relay':relay, 'restart_required':True}
            elif path == '/api/network/traefik.json':
                result = dict(version=2, **copy.deepcopy(network['gateway']))
            else:
                data = {
                    '/api/me':dict(username='alice-login' if portal else 'admin', role='client' if portal else 'admin', client_name='alice' if portal else None, guest_sub='10.8.0.128/25'),
                    '/api/portal/me':dict(username='alice-login',role='client',client_name='alice'),
                    '/api/settings':dict(remote=dict(host='example.test',remotes=[dict(proto='udp',port=21197),dict(proto='tcp',port=21196)]),listen=[dict(proto='udp',port=1197),dict(proto='tcp',port=1196)],tfa_issuer='OpenVPN',poll_interval=5,version='test'),
                    '/api/relay/settings':relay, '/api/network/settings':network,
                    '/api/portal':dict(name='alice',guest=True,links=['https://files.example.test/share/abc'],expires_at=1900000000,relay_available=True,signed_profiles=True,relay_download=dict(url='/api/portal/relay.mobileconfig',csrf='session-bound-test-token')),
                }
                result = data.get(path,{})
            route.fulfill(content_type='application/json',body=json.dumps(result))
        else:
            file = STATIC / (path.rsplit('/',1)[-1] if path.startswith('/static/') else 'index.html')
            route.fulfill(content_type='text/javascript' if file.suffix=='.js' else 'text/css' if file.suffix=='.css' else 'text/html',body=file.read_text())
    page.route('http://example.test/**',handle)
    page.goto('http://example.test/portal' if portal else 'http://example.test/#/settings')
    if portal:
        page.get_by_role('heading',name='Connect your device',exact=True).wait_for()
        assert page.get_by_role('link',name='Clients',exact=True).count()==0
        assert page.get_by_role('link',name='Settings',exact=True).count()==0
        # A native POST must work even when Blob URLs are unavailable on a device.
        page.evaluate("() => { URL.createObjectURL = () => { throw new SyntaxError('The string did not match the expected pattern.'); }; }")
        with page.expect_download() as download:
            page.get_by_role('button',name='Download Apple relay',exact=True).click()
        assert download.value.suggested_filename=='alice-relay.mobileconfig'
        assert native==[('POST', {'csrf':['session-bound-test-token']})]
        page.get_by_text('Guest access',exact=True).wait_for()
        assert page.get_by_role('link',name='https://files.example.test/share/abc',exact=True).count()==1
        page.get_by_text('My relay activity',exact=True).click()
        page.get_by_text('Your connection activity cannot be loaded right now.',exact=False).wait_for()
        assert page.get_by_text('Forbidden',exact=True).count()==0
        page.get_by_text('Change my password',exact=True).click()
        page.get_by_label('Current password',exact=True).fill('current-password')
        page.get_by_label('New password',exact=True).fill('another-password')
        page.get_by_label('Repeat new password',exact=True).fill('another-password')
        page.get_by_role('button',name='Change password',exact=True).click()
        page.get_by_text('The gateway blocked this request.',exact=False).wait_for()
        assert page.get_by_text('The string did not match the expected pattern.',exact=True).count()==0
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=os.path.join(SHOTS,'portal-mobile.png'),full_page=True)
    else:
        page.get_by_role('heading',name='Network',exact=True).wait_for()
        page.get_by_text('Gateway: 192.0.2.10',exact=False).wait_for()
        web = page.get_by_label('This server’s web address',exact=True)
        assert web.input_value()=='http://192.0.2.20:8080'
        assert page.get_by_label('Guest portal listener on the gateway',exact=True).input_value()=='192.0.2.10:9443'
        assert '192.0.2.10/32' in page.get_by_label('Gateway addresses',exact=True).input_value()
        page.get_by_text('https://openvpn.example.test/portal',exact=True).wait_for()
        # Detection never overwrites a value that is already there.
        web.fill('http://192.0.2.99:8088')
        page.get_by_role('button',name='Detect addresses',exact=True).click()
        page.get_by_text('Nothing was changed',exact=False).wait_for()
        assert web.input_value()=='http://192.0.2.99:8088'
        page.get_by_role('button',name='Add link',exact=True).click()
        page.get_by_label('Guest link',exact=True).fill('https://wiki.example.test/start')
        page.get_by_label('What the link allows',exact=True).select_option('site')
        # An empty field uses the value shown as its placeholder.
        page.get_by_label('This server’s relay address',exact=True).fill('')
        assert page.get_by_label('This server’s relay address',exact=True).get_attribute('placeholder')=='192.0.2.99:8444'
        with page.expect_download() as download:
            page.get_by_role('button',name='Save and download gateway file',exact=True).click()
        assert download.value.suggested_filename=='network.private.json'
        data=json.loads(Path(download.value.path()).read_text())
        assert calls[-2:]==[('PUT','/api/network/settings'),('GET','/api/network/traefik.json')]
        body=saved[-1]
        assert body['remote']=={'host':'example.test','ports':{'udp':21197,'tcp':21196}}
        assert body['relay']=={'enabled':True,'url':'https://example.test:9444'}
        assert body['gateway']['relay_public_url']=='https://example.test:9444'
        assert body['gateway']['relay_backend']=='192.0.2.99:8444'
        assert body['gateway']['portal_listener']=='192.0.2.10:9443'
        assert body['gateway']['openvpn_backend']=='http://192.0.2.99:8088'
        assert body['gateway']['replace_services'] is False and body['gateway']['services']==[]
        assert body['gateway']['guest_links']==[{'url':'https://wiki.example.test/start','whole_site':True}]
        assert data['version']==2 and data['portal_listener']=='192.0.2.10:9443'
        page.screenshot(path=os.path.join(SHOTS,'settings-desktop.png'),full_page=True)
        page.set_viewport_size({'width':390,'height':844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=os.path.join(SHOTS,'settings-mobile.png'),full_page=True)
        page.get_by_text('Advanced gateway settings',exact=True).click()
        page.get_by_label('Networks allowed into private websites',exact=True).fill('')
        page.get_by_role('button',name='Save',exact=True).click()
        page.get_by_text('Saved. Restart the VPN',exact=False).wait_for()
        assert saved[-1]['gateway']['trusted_cidrs']==[]
        # A refused save shows a readable message and downloads nothing.
        block_save[0]=True
        exports=sum(path=='/api/network/traefik.json' for _,path in calls)
        page.get_by_role('button',name='Save and download gateway file',exact=True).click()
        page.get_by_text('The gateway blocked this request.',exact=False).wait_for()
        assert sum(path=='/api/network/traefik.json' for _,path in calls)==exports
    assert not errors,errors
    context.close()


with sync_playwright() as playwright:
    browser=playwright.chromium.launch(executable_path=os.environ.get('CHROME_BIN','/usr/bin/google-chrome'),headless=True)
    scenario(browser)
    scenario(browser,portal=True)
    browser.close()
print('PASS: detected suggestions, kept values, placeholder defaults, gateway file, readable 403 errors, guest portal page and mobile layouts')
