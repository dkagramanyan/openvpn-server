import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from app import network, pki
from app.settings import settings


@pytest.fixture
def config(tmp_path, monkeypatch):
    path = tmp_path / "server.conf"
    path.write_text('management 127.0.0.1 2080\nserver 10.8.0.0 255.255.255.0 nopool\nifconfig-pool 10.8.0.2 10.8.0.99\npush "dhcp-option DNS 1.1.1.1"\n')
    monkeypatch.setattr(settings, "server_conf", path)
    monkeypatch.setattr(settings, "openvpn_dir", tmp_path)
    monkeypatch.setattr(settings, "network_file", tmp_path / "config/network/settings.conf")
    monkeypatch.setattr(settings, "_guest_sub", "")
    monkeypatch.setattr(pki, "static_ips", lambda: {})
    body = network.get_settings()
    body["proxy_cidrs"] = ["192.0.2.10/32"]
    body["gateway"] = {"domain": "example.test", "openvpn_host": "vpn.example.test", "openvpn_backend": "http://192.0.2.20:8080",
        "relay_host": "relay.example.test", "relay_backend": "192.0.2.20:8444", "portal_listener": "192.0.2.10:9443",
        "trusted_cidrs": ["192.0.2.0/24"], "services": [{"name": "example", "host": "app.example.test", "url": "http://192.0.2.30:8000"}]}
    return body


class SavedSettings:
    def __init__(self, **values):
        self.values = {key: json.dumps(value) for key, value in values.items()}

    def get_setting(self, key, default=None):
        return self.values.get(key, default)


def test_network_saved_privately_and_exported(config):
    result = network.save_settings(network.NetworkSettings(**config))
    assert result["restart_required"]
    assert stat.S_IMODE(settings.network_file.stat().st_mode) == 0o600
    assert network.get_settings()["gateway"]["portal_listener"] == "192.0.2.10:9443"
    assert settings.guest_sub == "10.8.0.128/25"
    assert "GUEST_PORTAL_TARGET=192.0.2.10:9443\n" in settings.network_file.read_text()
    exported = network.export_gateway()
    assert exported["version"] == 2
    assert exported["portal_listener"] == "192.0.2.10:9443"
    assert exported["services"][0]["name"] == "example"
    assert "password" not in json.dumps(exported).lower()
    config["gateway"]["portal_listener"] = ""
    network.save_settings(network.NetworkSettings(**config))
    assert "GUEST_PORTAL_TARGET=\n" in settings.network_file.read_text()
    assert network.guest_portal() is None


def test_export_keeps_gateway_services_unless_managed_here(config):
    config["gateway"]["services"] = []
    network.save_settings(network.NetworkSettings(**config))
    assert network.export_gateway()["services"] is None


@pytest.mark.parametrize("change", [
    {"guest_subnet": "10.9.0.128/25"}, {"pool_last": "10.8.0.150"}, {"proxy_cidrs": ["::/0"]},
    {"gateway": {"portal_listener": "192.0.2.10:443"}}, {"gateway": {"portal_listener": "127.0.0.1:9443"}},
    {"gateway": {"trusted_cidrs": ["0.0.0.0/0"]}},
])
def test_invalid_network_changes_write_nothing(config, change):
    before = settings.server_conf.read_bytes()
    for key, value in change.items():
        if key == "gateway":
            config["gateway"].update(value)
        else:
            config[key] = value
    with pytest.raises(pki.PkiError):
        network.save_settings(network.NetworkSettings(**config))
    assert not settings.network_file.exists()
    assert settings.server_conf.read_bytes() == before


def test_saved_settings_reach_firewall_and_unprivileged_relay(config):
    network.save_settings(network.NetworkSettings(**config))
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(["bash", "-euc", '''
        source "$SOURCE_ROOT/bin/guest-portal.sh"
        source "$SOURCE_ROOT/bin/network-settings.sh"
        load_network_settings
        printf '%s\\n' "$TRUST_SUB" "$GUEST_SUB" "$GUEST_PORTAL_TARGET"
    '''], env={**os.environ, "SOURCE_ROOT": str(root),
               "OPENVPN_DIR": str(settings.openvpn_dir), "SERVER_CONF": str(settings.server_conf)},
        check=True, capture_output=True, text=True)
    assert result.stdout.splitlines() == ["10.8.0.0/24", "10.8.0.128/25", "192.0.2.10:9443"]
    proxy_file = settings.network_file.with_name("proxies.conf")
    assert stat.S_IMODE(proxy_file.stat().st_mode) == 0o600
    assert "NETWORK_JSON" not in proxy_file.read_text()
    if os.geteuid() == 0:
        # The relay's real container UID can read proxy trust, but not the
        # full network/service inventory. Make only the pytest parents traversable.
        for parent in settings.network_file.parents:
            if parent == Path("/tmp"):
                break
            parent.chmod(parent.stat().st_mode | 0o111)
        result = subprocess.run(["sh", "-c", 'test -r "$1" && test ! -r "$2"', "sh",
                                 str(proxy_file), str(settings.network_file)],
                                user=65532, group=65532, extra_groups=[], check=False)
        assert result.returncode == 0


def test_custom_services_cannot_take_the_website_hostname(config):
    config["gateway"]["services"][0].update(host="vpn.example.test", public=True)
    with pytest.raises(pki.PkiError, match="cannot use the OpenVPN website"):
        network.save_settings(network.NetworkSettings(**config))


def test_guest_relay_policy_is_the_portal_only(config, monkeypatch):
    from app import relay
    network.save_settings(network.NetworkSettings(**config))
    monkeypatch.setattr(relay, "eligible", lambda name: {"serial": "01"})
    guest = {"value": True}
    monkeypatch.setattr(relay, "is_guest", lambda name: guest["value"])
    db = SavedSettings(apple_relay={"enabled": True, "url": "https://relay.example.test"}, **{"relay_client:alice": {"secret": "token", "serial": "01"}})
    policy = relay.authorize(db, "Bearer alice:token")
    assert policy["guest"] and policy["allowed_cidrs"] == []
    assert policy["portal"] == {"host": "vpn.example.test", "target": "192.0.2.10:9443", "hosts": []}
    guest["value"] = False
    policy = relay.authorize(db, "Bearer alice:token")
    assert policy["allowed_cidrs"] == ["0.0.0.0/0", "::/0"] and policy["portal"] is None
    guest["value"] = True
    config["gateway"]["portal_listener"] = ""
    network.save_settings(network.NetworkSettings(**config))
    assert relay.authorize(db, "Bearer alice:token")["portal"] is None


def test_unreadable_network_settings_fail_closed_for_guests(config, monkeypatch):
    from app import relay
    settings.network_file.parent.mkdir(parents=True)
    settings.network_file.write_text("TRUST_SUB=10.8.0.0/24\n")   # no NETWORK_JSON
    monkeypatch.setattr(relay, "eligible", lambda name: {"serial": "01"})
    monkeypatch.setattr(relay, "is_guest", lambda name: True)
    db = SavedSettings(apple_relay={"enabled": True, "url": "https://relay.example.test"}, **{"relay_client:alice": {"secret": "token", "serial": "01"}})
    assert relay.authorize(db, "Bearer alice:token") is None
    with pytest.raises(ValueError):
        relay.authorize(db, "Bearer alice:token", strict_state=True)


def test_settings_from_development_builds_are_upgraded(config):
    old = {k: v for k, v in config.items() if k != "gateway"}
    old.update(lan_cidrs=["192.0.2.0/24"], blocked_cidrs=[], portal={"enabled": True, "host": "vpn.example.test",
               "target": "192.0.2.10:9443", "destinations": ["192.0.2.10"]},
               gateway={"domain": "example.test", "openvpn_host": "vpn.example.test", "portal_cidrs": ["10.8.0.0/24"]})
    upgraded = network.NetworkSettings(**old).model_dump()
    assert upgraded["gateway"]["portal_listener"] == "192.0.2.10:9443"
    assert "lan_cidrs" not in upgraded and "portal" not in upgraded
    old["portal"]["enabled"] = False
    assert network.NetworkSettings(**old).gateway.portal_listener == ""


def test_existing_urls_prefill_gateway_without_exposing_signing_token(config, monkeypatch):
    monkeypatch.setattr(settings, "profile_base_url", "")
    monkeypatch.setattr(settings, "relay_signer_url", "")
    config["gateway"] = network.Gateway(openvpn_backend="http://192.0.2.20:8080").model_dump()
    network.save_settings(network.NetworkSettings(**config))
    db = SavedSettings(apple_relay={"url": "https://example.test:8443"},
                       relay_signing={"url": "https://vpn.example.test/internal/relay-sign", "token": "private-token"})
    saved = network.get_settings(db)
    assert saved["gateway"]["domain"] == "example.test"
    assert saved["gateway"]["openvpn_host"] == "vpn.example.test"
    assert saved["gateway"]["relay_host"] == "example.test"
    assert saved["gateway"]["relay_backend"] == "192.0.2.20:8444"
    assert saved["gateway"]["trusted_cidrs"] == []
    assert "private-token" not in json.dumps(saved)


def test_defaults_keep_custom_gateway_addresses(config, monkeypatch):
    network.save_settings(network.NetworkSettings(**config))
    monkeypatch.setattr(settings, "profile_base_url", "https://other.example.test")
    db = SavedSettings(apple_relay={"url": "https://another.example.test:8443"})
    expected = config["gateway"] | {"replace_services": True, "relay_public_url": "https://another.example.test:8443"}
    assert network.get_settings(db)["gateway"] == network.Gateway(**expected).model_dump()


def test_portal_listener_needs_the_website_hostname(config):
    config["gateway"].update(openvpn_host="", domain="")
    with pytest.raises(pki.PkiError, match="website hostname"):
        network.save_settings(network.NetworkSettings(**config))


def test_relay_needs_only_its_url():
    from app import relay
    assert relay.validate_settings(relay.RelaySettings(enabled=True, url="https://relay.example.test:8443/"))["url"] == "https://relay.example.test:8443"
    with pytest.raises(pki.PkiError, match="public HTTPS URL"):
        relay.validate_settings(relay.RelaySettings(enabled=True, url=""))
    assert relay.validate_settings(relay.RelaySettings(enabled=False, url=""))["enabled"] is False


def test_export_names_missing_fields(config):
    config["gateway"]["openvpn_backend"] = ""
    network.save_settings(network.NetworkSettings(**config))
    with pytest.raises(pki.PkiError, match="VPN server web address"):
        network.export_gateway()


@pytest.mark.parametrize("key,value,label", [
    ("portal_listener", "https://192.0.2.10:9443", "Guest portal listener"),
    ("openvpn_backend", "ftp://192.0.2.20", "VPN server web address"),
    ("relay_backend", "192.0.2.20", "Relay backend"),
])
def test_errors_name_the_input(config, key, value, label):
    config["gateway"][key] = value
    with pytest.raises(pki.PkiError, match=label):
        network.save_settings(network.NetworkSettings(**config))


@pytest.mark.parametrize("host,domain", [("vpn.example.test", "example.test"), ("example.test", "example.test"), ("192.0.2.20", "")])
def test_existing_vpn_endpoint_can_prefill_domain_without_using_ip_as_domain(config, monkeypatch, host, domain):
    monkeypatch.setattr(settings, "profile_base_url", "")
    monkeypatch.setattr(settings, "relay_signer_url", "")
    monkeypatch.setattr(pki, "get_remote", lambda: {"host": host})
    config["gateway"] = network.Gateway().model_dump()
    network.save_settings(network.NetworkSettings(**config))
    assert network.get_settings(SavedSettings())["gateway"]["domain"] == domain


def test_guest_links_reach_the_gateway_file_relay_and_portal_page(config):
    config["gateway"]["guest_links"] = [
        {"url": "https://Files.Example.test/share/abc?x=1", "whole_site": False},
        {"url": "https://wiki.example.test/start", "whole_site": True},
        {"url": "https://files.example.test/", "whole_site": False},
    ]
    network.save_settings(network.NetworkSettings(**config))
    assert network.export_gateway()["guest_links"] == [
        {"host": "files.example.test", "path": "/share/abc"}, {"host": "wiki.example.test", "path": "/"},
        {"host": "files.example.test", "path": "/"}]
    assert network.guest_portal()["hosts"] == ["files.example.test", "wiki.example.test"]
    assert network.guest_links()[0] == "https://files.example.test/share/abc?x=1"


@pytest.mark.parametrize("url", [
    "http://files.example.test/", "https://files.example.test:8443/", "https://user:pw@files.example.test/",
    "https://other.test/", "https://example.test/", "https://vpn.example.test/portal", "https://dashboard.example.test/",
    "https://relay.example.test/", "https://files.example.test/{{x}}", "not a url",
])
def test_invalid_guest_links_are_refused(config, url):
    config["gateway"]["guest_links"] = [{"url": url}]
    with pytest.raises(pki.PkiError, match="Guest link"):
        network.save_settings(network.NetworkSettings(**config))
