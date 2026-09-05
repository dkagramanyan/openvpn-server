"""Runtime configuration, taken from the environment and server.conf."""
from __future__ import annotations

import os
import re
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


class Settings:
    def __init__(self) -> None:
        self.openvpn_dir = Path(_env("OPENVPN_DIR", "/etc/openvpn"))
        self.easyrsa_dir = Path(_env("EASYRSA_DIR", "/usr/share/easy-rsa"))
        self.bin_dir = Path(_env("OVPN_BIN_DIR", "/opt/app/bin"))
        self.log_dir = Path(_env("OVPN_LOG_DIR", "/var/log/openvpn"))
        self.pki_dir = Path(_env("EASYRSA_PKI", str(self.openvpn_dir / "pki")))
        self.db_path = Path(_env("OVPN_UI_DB", str(self.openvpn_dir / "db" / "openvpn-ui.db")))

        self.server_conf = self.openvpn_dir / "server.conf"
        self.client_conf = self.openvpn_dir / "config" / "client.conf"
        self.vars_template = self.openvpn_dir / "config" / "easy-rsa.vars"
        self.clients_dir = self.openvpn_dir / "clients"
        self.static_dir = self.openvpn_dir / "staticclients"
        self.oath_secrets = self.clients_dir / "oath.secrets"

        self.poll_interval = max(2.0, float(_env("OVPN_UI_POLL_INTERVAL", "5")))
        self.session_ttl = int(_env("OVPN_UI_SESSION_TTL", str(12 * 3600)))
        self.admin_username = _env("OPENVPN_ADMIN_USERNAME", "admin").strip() or "admin"
        self.admin_password = _env("OPENVPN_ADMIN_PASSWORD", "")
        self.public_host = _env("OVPN_PUBLIC_HOST", "").strip()
        self.public_port = _env("OVPN_PUBLIC_PORT", "1195").strip() or "1195"
        self.public_proto = _env("OVPN_PUBLIC_PROTO", "tcp").strip().lower() or "tcp"
        self.secure_cookies = _env("OVPN_UI_SECURE_COOKIES", "auto").strip().lower()
        self.tfa_issuer = _env("OVPN_TFA_ISSUER", "OpenVPN").strip() or "OpenVPN"

    # -- management interface ---------------------------------------------
    def management_endpoint(self) -> tuple[str, int, Path | None]:
        """(host, port, password file) from server.conf, overridable by env."""
        host, port, pw_file = "127.0.0.1", 2080, None
        try:
            for line in self.server_conf.read_text().splitlines():
                m = re.match(r"^\s*management\s+(\S+)\s+(\d+)(?:\s+(\S+))?", line)
                if m:
                    host, port = m.group(1), int(m.group(2))
                    if m.group(3):
                        pw_file = Path(m.group(3))
                        if not pw_file.is_absolute():
                            pw_file = self.openvpn_dir / pw_file
                    break
        except OSError:
            pass
        host = _env("MGMT_HOST", host)
        port = int(_env("MGMT_PORT", str(port)))
        if host == "0.0.0.0":
            host = "127.0.0.1"
        return host, port, pw_file

    def management_password(self) -> str | None:
        _, _, pw_file = self.management_endpoint()
        if pw_file and pw_file.exists():
            try:
                return pw_file.read_text().strip() or None
            except OSError:
                return None
        return None


settings = Settings()
