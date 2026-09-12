"""PKI and configuration operations, delegated to easy-rsa and the scripts in bin/."""
from __future__ import annotations

import base64
import io
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import segno

from .settings import settings

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")
IP_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]{1,253}$")
RESERVED = {"server", "ca"}
REVOKE_REASONS = {"unspecified", "keyCompromise", "CACompromise", "affiliationChanged", "superseded",
                  "cessationOfOperation", "certificateHold"}

TFA_LINES = ("auth-user-pass-verify /opt/app/bin/oath.sh via-file", "auth-gen-token 43200")


class PkiError(Exception):
    pass


def validate_name(name: str) -> str:
    if not NAME_RE.match(name or ""):
        raise PkiError("Invalid client name: use 1-64 characters from letters, digits, _ . @ -")
    if name.lower() in RESERVED:
        raise PkiError(f"'{name}' is a reserved name")
    return name


# -- process helpers -----------------------------------------------------------
def _env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        "HOME": "/tmp",
        "OPENVPN_DIR": str(settings.openvpn_dir),
        "EASYRSA_DIR": str(settings.easyrsa_dir),
        "EASYRSA_PKI": str(settings.pki_dir),
        "EASYRSA_BATCH": "1",
    }
    if extra:
        env.update({k: v for k, v in extra.items() if v})
    return env


def _run(cmd: list[str], extra_env: dict[str, str] | None = None, timeout: int = 180) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=_env(extra_env), timeout=timeout,
                              cwd=str(settings.openvpn_dir))
    except subprocess.TimeoutExpired as exc:
        raise PkiError(f"{Path(cmd[0]).name} timed out") from exc
    except OSError as exc:
        raise PkiError(f"cannot run {cmd[0]}: {exc}") from exc
    if proc.returncode != 0:
        msg = (proc.stderr.strip() or proc.stdout.strip()).splitlines()
        raise PkiError(" ".join(msg[-3:]) if msg else f"{Path(cmd[0]).name} failed ({proc.returncode})")
    return proc.stdout


def script(name: str, *args: str, extra_env: dict[str, str] | None = None) -> str:
    return _run([str(settings.bin_dir / name), *args], extra_env)


def easyrsa(*args: str) -> str:
    return _run([str(settings.easyrsa_dir / "easyrsa"), *args])


def openssl(*args: str) -> str:
    return _run(["openssl", *args], timeout=30)


# -- parsing helpers -----------------------------------------------------------
def parse_asn1_time(value: str) -> int | None:
    value = value.strip()
    for fmt in ("%y%m%d%H%M%SZ", "%Y%m%d%H%M%SZ"):
        try:
            return int(datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue
    return None


def parse_openssl_time(value: str) -> int | None:
    try:
        return int(datetime.strptime(" ".join(value.split()), "%b %d %H:%M:%S %Y %Z")
                   .replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


def _cn_from_dn(dn: str) -> str:
    m = re.search(r"(?:^|[/,])CN=([^/,]+)", dn)
    return m.group(1).strip() if m else ""


def parse_index(text: str) -> dict[str, dict[str, Any]]:
    """pki/index.txt -> {serial: entry}. Tolerates the extra fields older tooling appended to the DN."""
    entries: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 6 or parts[0] not in ("V", "R", "E"):
            continue
        status, expiry, revocation, serial, _fname, dn = parts[:6]
        revoked_at, reason = None, None
        if revocation:
            date_part, _, reason = revocation.partition(",")
            revoked_at = parse_asn1_time(date_part)
            reason = reason or None
        entries[serial.upper()] = {
            "status": status,
            "expires": parse_asn1_time(expiry),
            "revoked_at": revoked_at,
            "reason": reason,
            "serial": serial.upper(),
            "cn": _cn_from_dn(dn),
        }
    return entries


def read_index() -> dict[str, dict[str, Any]]:
    path = settings.pki_dir / "index.txt"
    try:
        return parse_index(path.read_text())
    except OSError:
        return {}


_cert_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def cert_info(path: Path) -> dict[str, Any] | None:
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    cached = _cert_cache.get(str(path))
    if cached and cached[0] == mtime:
        return dict(cached[1])
    try:
        out = openssl("x509", "-in", str(path), "-noout", "-serial", "-startdate", "-enddate",
                      "-subject", "-nameopt", "RFC2253", "-fingerprint", "-sha256")
    except PkiError:
        return None
    info: dict[str, Any] = {"serial": "", "not_before": None, "not_after": None, "cn": "", "fingerprint": ""}
    for line in out.splitlines():
        key, _, val = line.partition("=")
        key = key.strip().lower()
        if key == "serial":
            info["serial"] = val.strip().upper()
        elif key == "notbefore":
            info["not_before"] = parse_openssl_time(val)
        elif key == "notafter":
            info["not_after"] = parse_openssl_time(val)
        elif key == "subject":
            info["cn"] = _cn_from_dn(val)
        elif "fingerprint" in key:
            info["fingerprint"] = val.strip()
    _cert_cache[str(path)] = (mtime, dict(info))
    return info


# -- static IPs / 2FA state ----------------------------------------------------
def static_ips() -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for f in settings.static_dir.iterdir():
            if not f.is_file() or f.name.startswith("."):
                continue
            try:
                for line in f.read_text().splitlines():
                    m = re.match(r"^\s*ifconfig-push\s+(\S+)", line)
                    if m:
                        result[f.name] = m.group(1)
                        break
            except OSError:
                continue
    except OSError:
        pass
    return result


def set_static_ip(name: str, ip: str | None) -> None:
    validate_name(name)
    path = settings.static_dir / name
    if not ip:
        path.unlink(missing_ok=True)
        return
    if not IP_RE.match(ip):
        raise PkiError("Invalid IPv4 address")
    mask = "255.255.255.0"
    m = re.search(r"^\s*server\s+[\d.]+\s+([\d.]+)", read_config("server"), re.M)
    if m:
        mask = m.group(1)
    settings.static_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(f"ifconfig-push {ip} {mask}\n")
    path.chmod(0o644)


def tfa_secrets() -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for line in settings.oath_secrets.read_text().splitlines():
            name, sep, secret = line.strip().partition(":")
            if sep and name and secret:
                result[name] = secret
    except OSError:
        pass
    return result


def tfa_uri(name: str) -> str | None:
    secret = tfa_secrets().get(name)
    if not secret:
        return None
    try:
        b32 = base64.b32encode(bytes.fromhex(secret)).decode().rstrip("=")
    except ValueError:
        return None
    issuer = settings.tfa_issuer.replace(" ", "%20")
    return f"otpauth://totp/{issuer}:{name}?secret={b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def tfa_qr_svg(uri: str) -> str:
    buf = io.BytesIO()
    segno.make(uri, error="m").save(buf, kind="svg", scale=5, dark="#0b0b0b", light=None, xmldecl=True, svgns=True)
    return buf.getvalue().decode()


def enable_tfa(name: str) -> str:
    validate_name(name)
    out = script("oath-sec-gen.sh", name, settings.tfa_issuer)
    uri = out.strip().splitlines()[0] if out.strip() else ""
    if (settings.pki_dir / "issued" / f"{name}.crt").exists():
        script("mkovpn.sh", name)
    return uri


def disable_tfa(name: str) -> None:
    validate_name(name)
    script("oath-sec-rm.sh", name)
    if (settings.pki_dir / "issued" / f"{name}.crt").exists():
        script("mkovpn.sh", name)


# -- client listing --------------------------------------------------------------
def list_clients(hidden_serials: set[str]) -> dict[str, dict[str, Any]]:
    """Every client known to the PKI, keyed by name, with certificate state."""
    now = int(time.time())
    index = read_index()
    clients: dict[str, dict[str, Any]] = {}
    issued_dir = settings.pki_dir / "issued"
    renewed_dir = settings.pki_dir / "renewed" / "issued"
    revoked_dir = settings.pki_dir / "revoked" / "certs_by_serial"

    def cert_state(info: dict[str, Any]) -> dict[str, Any]:
        entry = index.get(info["serial"], {})
        status = entry.get("status", "V")
        expires = info.get("not_after") or entry.get("expires")
        if status == "R":
            state = "revoked"
        elif expires is not None and expires <= now:
            state = "expired"
        else:
            state = "valid"
        return {
            "serial": info["serial"], "cn": info["cn"], "state": state,
            "not_before": info.get("not_before"), "not_after": expires,
            "revoked_at": entry.get("revoked_at"), "reason": entry.get("reason"),
            "fingerprint": info.get("fingerprint", ""),
        }

    try:
        issued = sorted(issued_dir.glob("*.crt"))
    except OSError:
        issued = []
    for path in issued:
        name = path.stem
        if name in RESERVED:
            continue
        info = cert_info(path)
        if not info:
            continue
        cert = cert_state(info)
        previous = None
        prev_path = renewed_dir / f"{name}.crt"
        if prev_path.exists():
            prev_info = cert_info(prev_path)
            if prev_info:
                previous = cert_state(prev_info)
        clients[name] = {"name": name, "cert": cert, "previous": previous, "history": []}

    try:
        revoked = sorted(revoked_dir.glob("*.crt"))
    except OSError:
        revoked = []
    for path in revoked:
        info = cert_info(path)
        if not info or info["serial"] in hidden_serials:
            continue
        name = info["cn"] or info["serial"]
        cert = cert_state(info)
        if name in clients:
            clients[name]["history"].append(cert)
        else:
            clients[name] = {"name": name, "cert": cert, "previous": None, "history": []}
    for c in clients.values():
        c["history"].sort(key=lambda x: x.get("not_before") or 0, reverse=True)
    return clients


# -- client operations -------------------------------------------------------------
def create_client(name: str, days: int | None = None, passphrase: str | None = None,
                  static_ip: str | None = None) -> None:
    validate_name(name)
    if days is not None and not (1 <= days <= 3650):
        raise PkiError("Validity must be between 1 and 3650 days")
    if static_ip and not IP_RE.match(static_ip):
        raise PkiError("Invalid static IPv4 address")
    if passphrase and len(passphrase) < 4:
        raise PkiError("Passphrase must be at least 4 characters")
    args = [name] + ([static_ip] if static_ip else [])
    script("genclient.sh", *args, extra_env={
        "OVPN_CERT_DAYS": str(days) if days else "",
        "OVPN_KEY_PASSPHRASE": passphrase or "",
    })


def revoke_client(name: str, reason: str | None = None) -> None:
    validate_name(name)
    if reason and reason not in REVOKE_REASONS:
        raise PkiError("Invalid revocation reason")
    script("revoke.sh", name, *([reason] if reason else []))


def revoke_previous(name: str) -> None:
    validate_name(name)
    script("revoke.sh", "--renewed", name)


def renew_client(name: str, days: int | None = None) -> None:
    validate_name(name)
    if days is not None and not (1 <= days <= 3650):
        raise PkiError("Validity must be between 1 and 3650 days")
    script("renew.sh", name, extra_env={"OVPN_CERT_DAYS": str(days) if days else ""})


def remove_client(name: str) -> None:
    validate_name(name)
    script("rmcert.sh", name)


def build_profile(name: str) -> str:
    validate_name(name)
    out = script("mkovpn.sh", name).strip()
    path = Path(out.splitlines()[-1]) if out else settings.clients_dir / f"{name}.ovpn"
    return path.read_text()


# -- configuration files ---------------------------------------------------------
CONFIG_FILES = {"server": "server.conf", "client": "config/client.conf", "vars": "pki/vars"}


def config_path(which: str) -> Path:
    if which not in CONFIG_FILES:
        raise PkiError("Unknown configuration file")
    path = settings.openvpn_dir / CONFIG_FILES[which]
    if which == "vars" and not path.exists():
        path = settings.vars_template
    return path


def read_config(which: str) -> str:
    try:
        return config_path(which).read_text()
    except OSError:
        return ""


def write_config(which: str, content: str) -> None:
    path = config_path(which)
    if len(content) > 200_000:
        raise PkiError("Configuration file too large")
    content = content.replace("\r\n", "\n")
    if not content.endswith("\n"):
        content += "\n"
    if which == "server":
        if not re.search(r"^\s*management\s+", content, re.M):
            raise PkiError("server.conf must keep the 'management' line - the UI needs it")
    try:
        if path.exists():
            backup = path.with_name(path.name + ".bak")
            backup.write_text(path.read_text())
        # Write in place so bind mounts keep pointing at the same inode.
        with open(path, "w") as fh:
            fh.write(content)
    except OSError as exc:
        raise PkiError(f"cannot write {path.name}: {exc}") from exc


def get_remote() -> dict[str, str]:
    text = read_config("client")
    host, port, proto = "", "1195", "tcp"
    m = re.search(r"^\s*remote\s+(\S+)\s+(\d+)(?:\s+(\S+))?", text, re.M)
    if m:
        host, port = m.group(1), m.group(2)
        if m.group(3):
            proto = m.group(3)
    m = re.search(r"^\s*proto\s+(\S+)", text, re.M)
    if m and m.group(1).startswith(("udp", "tcp")):
        proto = m.group(1)[:3]
    return {"host": host, "port": port, "proto": proto}


def server_listen() -> dict[str, str]:
    """What OpenVPN actually listens on, from server.conf."""
    text = read_config("server")
    port, proto = "1194", "udp"          # OpenVPN's own defaults
    m = re.search(r"^\s*port\s+(\d+)", text, re.M)
    if m:
        port = m.group(1)
    m = re.search(r"^\s*proto\s+(\S+)", text, re.M)
    if m and m.group(1).lower().startswith(("udp", "tcp")):
        proto = m.group(1).lower()[:3]
    return {"port": port, "proto": proto}


def set_remote(host: str, port: int | str) -> None:
    """Point client profiles at <host>:<port>. The protocol always follows server.conf:
    a port forward can remap the port, but it can never turn UDP into TCP."""
    host = host.strip()
    if not HOST_RE.match(host):
        raise PkiError("Invalid host name or IP address")
    try:
        port = int(port)
    except ValueError:
        raise PkiError("Invalid port") from None
    if not (1 <= port <= 65535):
        raise PkiError("Invalid port")
    proto = server_listen()["proto"]
    text = read_config("client")
    lines = [l for l in text.splitlines() if not re.match(r"^\s*(remote|proto)\s+", l)]
    # keep "client" first, then proto/remote
    out: list[str] = []
    inserted = False
    for line in lines:
        out.append(line)
        if not inserted and line.strip() == "client":
            out += [f"proto {proto}", f"remote {host} {port}"]
            inserted = True
    if not inserted:
        out = [f"proto {proto}", f"remote {host} {port}"] + out
    write_config("client", "\n".join(out) + "\n")
    regenerate_profiles()


def sync_remote_proto() -> bool:
    """Rewrite the profiles' protocol when server.conf changed it. True when it did."""
    remote = get_remote()
    if not remote["host"] or remote["proto"] == server_listen()["proto"]:
        return False
    set_remote(remote["host"], remote["port"])
    return True


def regenerate_profiles() -> list[str]:
    failed: list[str] = []
    try:
        names = [p.stem for p in (settings.pki_dir / "issued").glob("*.crt") if p.stem not in RESERVED]
    except OSError:
        return failed
    for name in names:
        try:
            script("mkovpn.sh", name)
        except PkiError:
            failed.append(name)
    return failed


def tfa_enforced() -> bool:
    return bool(re.search(r"^\s*auth-user-pass-verify\s+", read_config("server"), re.M))


def set_tfa_enforced(enabled: bool) -> None:
    text = read_config("server")
    lines = [l for l in text.splitlines()
             if not re.match(r"^\s*#?\s*(auth-user-pass-verify|auth-gen-token)\s+", l)]
    if enabled:
        lines += list(TFA_LINES)
    else:
        lines += ["#" + l for l in TFA_LINES]
    write_config("server", "\n".join(lines) + "\n")


# -- PKI status ------------------------------------------------------------------
def crl_info() -> dict[str, Any]:
    path = settings.pki_dir / "crl.pem"
    info: dict[str, Any] = {"exists": path.exists(), "last_update": None, "next_update": None, "revoked": 0}
    if not info["exists"]:
        return info
    try:
        out = openssl("crl", "-in", str(path), "-noout", "-lastupdate", "-nextupdate")
        for line in out.splitlines():
            key, _, val = line.partition("=")
            if key == "lastUpdate":
                info["last_update"] = parse_openssl_time(val)
            elif key == "nextUpdate":
                info["next_update"] = parse_openssl_time(val)
    except PkiError:
        pass
    info["revoked"] = sum(1 for e in read_index().values() if e["status"] == "R")
    return info


def gen_crl() -> None:
    easyrsa("gen-crl")
    try:
        (settings.pki_dir / "crl.pem").chmod(0o644)
    except OSError:
        pass


def ensure_crl_fresh(min_days: int = 30) -> bool:
    info = crl_info()
    if info["exists"] and info["next_update"] and info["next_update"] - time.time() > min_days * 86400:
        return False
    gen_crl()
    return True


def pki_status() -> dict[str, Any]:
    ca = cert_info(settings.pki_dir / "ca.crt")
    server = cert_info(settings.pki_dir / "issued" / "server.crt")
    vars_text = read_config("vars")
    algo = re.search(r'EASYRSA_ALGO\s+"?(\w+)"?', vars_text)
    curve = re.search(r'EASYRSA_CURVE\s+"?([\w-]+)"?', vars_text)
    keysize = re.search(r'EASYRSA_KEY_SIZE\s+"?(\d+)"?', vars_text)
    return {
        "ca": ca,
        "server": server,
        "crl": crl_info(),
        "tls_key": (settings.pki_dir / "ta.key").exists(),
        "algo": (algo.group(1) if algo else "rsa"),
        "curve": curve.group(1) if curve else None,
        "key_size": int(keysize.group(1)) if keysize else None,
        "cert_days": int(m.group(1)) if (m := re.search(r"EASYRSA_CERT_EXPIRE\s+(\d+)", vars_text)) else 825,
    }


def tail_file(path: Path, lines: int = 200, max_bytes: int = 512 * 1024) -> str:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            data = fh.read().decode("utf-8", "replace")
    except OSError:
        return ""
    return "\n".join(data.splitlines()[-lines:])
