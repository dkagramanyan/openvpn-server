import pytest

from app import network, network_discovery as discovery


@pytest.fixture
def discovered(monkeypatch):
    monkeypatch.setattr(discovery, 'interfaces', lambda: [{'name': 'eth0', 'address': '192.0.2.20', 'network': '192.0.2.0/24'}])
    monkeypatch.setattr(discovery, 'dns_ipv4', lambda host: ['198.51.100.10'])
    monkeypatch.setattr(discovery, 'source_ipv4', lambda target: '192.0.2.20')
    return network.NetworkSettings(vpn_subnet='10.8.0.0/24', pool_first='10.8.0.2', pool_last='10.8.0.99',
        guest_subnet='10.8.0.128/25', gateway=network.Gateway(domain='example.test', openvpn_host='vpn.example.test')).model_dump()


def test_detects_this_server_and_the_actual_proxy(discovered):
    result = discovery.discover(discovered, peer='192.0.2.10', proxied=True)
    suggestions = result['suggestions']
    assert suggestions['gateway.openvpn_backend']['value'] == 'http://192.0.2.20:8080'
    assert suggestions['gateway.portal_listener']['value'] == '192.0.2.10:9443'
    assert suggestions['proxy_cidrs']['value'] == ['192.0.2.10/32']
    assert set(suggestions) == {'gateway.openvpn_backend', 'gateway.portal_listener', 'proxy_cidrs'}
    assert discovered['gateway']['openvpn_backend'] == ''  # Detection does not save or mutate settings.


def test_does_not_guess_gateway_from_remote_browser_or_public_dns(discovered):
    result = discovery.discover(discovered, peer='203.0.113.40', proxied=False)
    assert result['gateway_ipv4'] is None
    assert 'gateway.portal_listener' not in result['suggestions']
    assert 'proxy_cidrs' not in result['suggestions']


def test_same_lan_dns_can_suggest_gateway_when_peer_is_loopback(discovered, monkeypatch):
    monkeypatch.setattr(discovery, 'dns_ipv4', lambda host: ['192.0.2.10'])
    assert discovery.discover(discovered, peer='127.0.0.1', proxied=True)['gateway_ipv4'] == '192.0.2.10'


def test_does_not_choose_between_ambiguous_gateway_dns_answers(discovered, monkeypatch):
    monkeypatch.setattr(discovery, 'dns_ipv4', lambda host: ['192.0.2.10', '192.0.2.11'])
    assert discovery.discover(discovered)['gateway_ipv4'] is None


@pytest.mark.parametrize('address', ['127.0.0.1', '0.0.0.0', '169.254.1.2', '224.0.0.1', '::1', 'not-an-ip'])
def test_unusable_addresses_are_not_suggested(address):
    assert discovery.usable_ipv4(address) is None
