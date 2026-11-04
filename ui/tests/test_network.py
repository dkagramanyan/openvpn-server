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
    body["lan_cidrs"] = ["192.0.2.0/24"]
    body["proxy_cidrs"] = ["192.0.2.10/32"]
    body["portal"] = {"enabled": True, "host": "vpn.example.test", "target": "192.0.2.10:9443", "destinations": ["192.0.2.10", "198.51.100.10"]}
    body["gateway"] = {"domain": "example.test", "openvpn_host": "vpn.example.test", "openvpn_backend": "http://192.0.2.20:8080",
        "relay_host": "relay.example.test", "relay_backend": "192.0.2.20:8444", "trusted_cidrs": ["192.0.2.0/24"],
        "portal_cidrs": ["192.0.2.0/24", "10.8.0.0/24"], "services": [{"name": "example", "host": "app.example.test", "url": "http://192.0.2.30:8000"}]}
    return body


def test_network_saved_privately_and_exported(config):
    result = network.save_settings(network.NetworkSettings(**config))
    assert result["restart_required"]
    assert stat.S_IMODE(settings.network_file.stat().st_mode) == 0o600
    saved = network.get_settings()
    assert saved["portal"] == config["portal"]
    assert settings.guest_sub == "10.8.0.128/25"
    text = settings.network_file.read_text()
    assert "GUEST_PORTAL_TARGET=192.0.2.10:9443\n" in text
    assert "LAN_CIDRS=192.0.2.0/24\n" in text
    exported = network.export_gateway()
    assert exported["gateway"]["services"][0]["name"] == "example"
    assert "password" not in json.dumps(exported).lower()
    config["portal"]["enabled"] = False
    network.save_settings(network.NetworkSettings(**config))
    assert "GUEST_PORTAL_TARGET=\n" in settings.network_file.read_text()


@pytest.mark.parametrize("change", [
    {"guest_subnet": "10.9.0.128/25"}, {"pool_last": "10.8.0.150"},
    {"lan_cidrs": ["0.0.0.0/0"]}, {"proxy_cidrs": ["::/0"]},
    {"portal": {"enabled": True, "host": "vpn.example.test", "target": "192.0.2.10:443", "destinations": ["198.51.100.10"]}},
])
def test_invalid_network_changes_write_nothing(config, change):
    before = settings.server_conf.read_bytes()
    config.update(change)
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
        printf '%s\\n' "$TRUST_SUB" "$GUEST_SUB" "$LAN_CIDRS" "$GUEST_PORTAL_TARGET"
    '''], env={**os.environ, "SOURCE_ROOT": str(root),
               "OPENVPN_DIR": str(settings.openvpn_dir), "SERVER_CONF": str(settings.server_conf)},
        check=True, capture_output=True, text=True)
    assert result.stdout.splitlines() == ["10.8.0.0/24", "10.8.0.128/25", "192.0.2.0/24", "192.0.2.10:9443"]
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


def test_custom_services_cannot_expose_portal(config):
    config["gateway"]["services"][0].update(host="vpn.example.test", public=True)
    with pytest.raises(pki.PkiError, match="cannot replace"):
        network.save_settings(network.NetworkSettings(**config))


def test_ui_policy_changes_reach_relay_authorization(config, monkeypatch):
    from app import relay
    network.save_settings(network.NetworkSettings(**config))
    blocks = relay.guest_blocks({"allowed_cidrs": []})
    assert "192.0.2.0/24" in blocks
    monkeypatch.setattr(relay, "eligible", lambda name: {"serial": "01"})
    monkeypatch.setattr(relay, "is_guest", lambda name: True)
    class DB:
        def get_setting(self, key, default=None):
            if key == "apple_relay": return json.dumps({"enabled": True, "url": "https://relay.example.test", "allowed_cidrs": ["192.0.2.0/24"]})
            return json.dumps({"secret": "token", "serial": "01"})
    assert relay.authorize(DB(), "Bearer guest:token")["portal"]["target"] == "192.0.2.10:9443"
    config["portal"]["enabled"] = False
    network.save_settings(network.NetworkSettings(**config))
    assert relay.authorize(DB(), "Bearer guest:token")["portal"] is None
    config["portal"].update(enabled=True, target="", destinations=[])
    network.save_settings(network.NetworkSettings(**config))
    assert relay.authorize(DB(), "Bearer guest:token")["portal"] is None


def test_guest_portal_allowlist_does_not_require_dedicated_routing_or_grant_admin_access(config):
    config["portal"].update(enabled=True, target="", destinations=[])
    config["gateway"]["portal_cidrs"] = []
    private_networks = config["gateway"]["trusted_cidrs"][:]
    network.save_settings(network.NetworkSettings(**config))
    exported = network.export_gateway()
    assert exported["portal"]["target"] == ""
    assert exported["gateway"]["portal_cidrs"] == [*private_networks, config["guest_subnet"]]
    assert exported["gateway"]["trusted_cidrs"] == private_networks
    assert exported["gateway"]["trusted_cidrs"] != exported["gateway"]["portal_cidrs"]
    text = settings.network_file.read_text()
    assert "GUEST_PORTAL_HOST=\n" in text
    assert "GUEST_PORTAL_TARGET=\n" in text
    assert network.get_settings()["lan_cidrs"] == config["lan_cidrs"]


class SavedSettings:
    def __init__(self, **values):
        self.values = {key: json.dumps(value) for key, value in values.items()}

    def get_setting(self, key, default=None):
        return self.values.get(key, default)


def test_existing_urls_prefill_gateway_without_exposing_signing_token(config, monkeypatch):
    monkeypatch.setattr(settings, "profile_base_url", "")
    monkeypatch.setattr(settings, "relay_signer_url", "")
    config["gateway"] = network.Gateway(openvpn_backend="http://192.0.2.20:8080").model_dump()
    config["portal"].update(enabled=False, host="")
    network.save_settings(network.NetworkSettings(**config))
    db = SavedSettings(apple_relay={"url": "https://example.test:8443"},
                       relay_signing={"url": "https://vpn.example.test/internal/relay-sign", "token": "private-token"})
    saved = network.get_settings(db)
    assert saved["gateway"]["domain"] == "example.test"
    assert saved["gateway"]["openvpn_host"] == "vpn.example.test"
    assert saved["portal"]["host"] == "vpn.example.test"
    assert saved["gateway"]["relay_host"] == "example.test"
    assert saved["gateway"]["relay_backend"] == "192.0.2.20:8444"
    assert saved["gateway"]["trusted_cidrs"] == []  # Guest blocks never grant admin access.
    assert "private-token" not in json.dumps(saved)


def test_shared_defaults_preserve_custom_gateway_addresses(config, monkeypatch):
    network.save_settings(network.NetworkSettings(**config))
    monkeypatch.setattr(settings, "profile_base_url", "https://other.example.test")
    db = SavedSettings(apple_relay={"url": "https://another.example.test:8443"})
    expected = config["gateway"] | {"replace_services": True, "relay_public_url": "https://another.example.test:8443"}
    assert network.get_settings(db)["gateway"] == network.Gateway(**expected).model_dump()


def test_legacy_relay_lan_blocks_are_carried_into_shared_form(config):
    network.save_settings(network.NetworkSettings(**config))
    db = SavedSettings(apple_relay={"allowed_cidrs": ["192.0.2.0/24", "198.51.100.0/24", "fd00::/64"]})
    saved = network.get_settings(db)
    assert saved["lan_cidrs"] == ["192.0.2.0/24", "198.51.100.0/24"]
    assert network.validate(network.NetworkSettings(**saved))["lan_cidrs"] == saved["lan_cidrs"]


def test_portal_reuses_website_hostname_and_rejects_conflicts(config):
    config["portal"]["host"] = ""
    saved = network.save_settings(network.NetworkSettings(**config))
    assert saved["settings"]["portal"]["host"] == "vpn.example.test"
    config["portal"]["host"] = "different.example.test"
    before = settings.network_file.read_bytes()
    with pytest.raises(pki.PkiError, match="same hostname"):
        network.save_settings(network.NetworkSettings(**config))
    assert settings.network_file.read_bytes() == before


def test_relay_uses_shared_lan_blocks_without_duplicate_input(config):
    from app import relay
    network.save_settings(network.NetworkSettings(**config))
    body = relay.RelaySettings(enabled=True, url="https://relay.example.test:8443", allowed_cidrs=[])
    assert relay.validate_settings(body)["enabled"]
    with pytest.raises(pki.PkiError, match="LAN networks"):
        relay.validate_settings(body, lan_cidrs=[])


def test_export_names_missing_fields(config):
    config["gateway"]["openvpn_backend"] = ""
    network.save_settings(network.NetworkSettings(**config))
    with pytest.raises(pki.PkiError, match="OpenVPN UI backend URL"):
        network.export_gateway()


@pytest.mark.parametrize("field,value,label", [
    ("target", "https://192.0.2.10:9443", "Dedicated portal listener"),
    ("destinations", ["127.0.0.1"], "Portal DNS IPv4 addresses"),
])
def test_portal_errors_identify_the_actual_input(config, field, value, label):
    config["portal"][field] = value
    with pytest.raises(pki.PkiError, match=label):
        network.save_settings(network.NetworkSettings(**config))


@pytest.mark.parametrize("host,domain", [("vpn.example.test", "example.test"), ("example.test", "example.test"), ("192.0.2.20", "")])
def test_existing_vpn_endpoint_can_prefill_domain_without_using_ip_as_domain(config, monkeypatch, host, domain):
    monkeypatch.setattr(settings, "profile_base_url", "")
    monkeypatch.setattr(settings, "relay_signer_url", "")
    monkeypatch.setattr(pki, "get_remote", lambda: {"host": host})
    config["gateway"] = network.Gateway().model_dump()
    config["portal"].update(host="", enabled=False)
    network.save_settings(network.NetworkSettings(**config))
    assert network.get_settings(SavedSettings())["gateway"]["domain"] == domain


def test_website_export_needs_no_duplicate_gateway_admin_networks(config):
    config['gateway'].update(trusted_cidrs=[], portal_cidrs=['192.0.2.20/32'])
    network.save_settings(network.NetworkSettings(**config))
    exported = network.export_gateway()
    assert exported['gateway']['trusted_cidrs'] == []
    assert exported['gateway']['portal_cidrs'] == ['192.0.2.20/32', config['guest_subnet']]
    assert exported['portal']['target'] == config['portal']['target']
