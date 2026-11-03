"""Check the exact firewall exception without changing the host's firewall."""
import os
from pathlib import Path
import shlex
import subprocess

import pytest

HELPER = Path(__file__).resolve().parents[1] / "bin/guest-portal.sh"


def rules(target="192.0.2.13:9443", destinations="192.0.2.13 198.51.100.4"):
    return subprocess.run(["bash", "-ec", '''
source "$1"
guest_portal_validate
iptables() { printf '%q ' "$@"; printf '\n'; }
guest_portal_rules -A
''', "test", str(HELPER)], env=os.environ | {
        "GUEST_PORTAL_TARGET": target, "GUEST_PORTAL_DESTINATIONS": destinations,
        "GUEST_SUB": "10.8.0.128/25",
    }, text=True, capture_output=True)


def test_exception_only_for_guest_https_to_pinned_listener():
    result = rules()
    assert result.returncode == 0, result.stderr
    commands = [shlex.split(line) for line in result.stdout.splitlines()]
    assert len(commands) == 5
    for command in commands:
        assert command[command.index("-s") + 1] == "10.8.0.128/25"
        assert command[command.index("-p") + 1] == "tcp"
        if "--to-destination" in command:
            assert command[command.index("--dport") + 1] == "443"
            assert command[command.index("--to-destination") + 1] == "192.0.2.13:9443"
        else:
            assert command[command.index("-d") + 1] == "192.0.2.13"
            assert command[command.index("--dport") + 1] == "9443"
            assert command[command.index("--ctstate") + 1] == "DNAT"
        if "ACCEPT" in command:
            assert command[command.index("--ctorigdst") + 1] in ("192.0.2.13", "198.51.100.4")
            assert command[command.index("--ctorigdstport") + 1] == "443"
            assert command[command.index("-i") + 1] == "tun+"


@pytest.mark.parametrize("target,destinations", [
    ("", "192.0.2.13"), ("192.0.2.13:9443", ""),
    ("192.0.2.13:443", "192.0.2.13"), ("127.0.0.1:9443", "192.0.2.13"),
    ("192.0.2.999:9443", "192.0.2.13"), ("192.0.2.13:9443", "0.0.0.0/0"),
    ("192.0.2.13:9443", "--something"),
])
def test_invalid_exception_installs_no_rules(target, destinations):
    result = rules(target, destinations)
    assert result.returncode != 0
    assert not result.stdout


def test_disabled_exception_installs_no_rules():
    result = rules("", "")
    assert result.returncode == 0
    assert not result.stdout
