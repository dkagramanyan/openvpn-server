"""Check the guest portal rules without changing the host's firewall."""
import os
from pathlib import Path
import shlex
import subprocess

import pytest

HELPER = Path(__file__).resolve().parents[1] / "bin/guest-portal.sh"


def rules(target="192.0.2.13:9443"):
    return subprocess.run(["bash", "-ec", '''
source "$1"
guest_portal_validate
iptables() { printf '%q ' "$@"; printf '\\n'; }
guest_portal_rules -A
''', "test", str(HELPER)], env=os.environ | {"GUEST_PORTAL_TARGET": target, "GUEST_SUB": "10.8.0.128/25"},
        text=True, capture_output=True)


def test_guest_https_goes_only_to_the_portal_listener():
    result = rules()
    assert result.returncode == 0, result.stderr
    dnat, accept, masquerade = [shlex.split(line) for line in result.stdout.splitlines()]
    for command in (dnat, accept, masquerade):
        assert command[command.index("-s") + 1] == "10.8.0.128/25"
        assert command[command.index("-p") + 1] == "tcp"
    assert "-d" not in dnat   # whatever address the guest's DNS returned
    assert dnat[dnat.index("--dport") + 1] == "443"
    assert dnat[dnat.index("--to-destination") + 1] == "192.0.2.13:9443"
    assert accept[accept.index("-d") + 1] == "192.0.2.13"
    assert accept[accept.index("--dport") + 1] == "9443"
    assert accept[accept.index("--ctstate") + 1] == "DNAT"
    assert accept[accept.index("--ctorigdstport") + 1] == "443"
    assert accept[accept.index("-i") + 1] == "tun+"
    assert masquerade[-1] == "MASQUERADE"


@pytest.mark.parametrize("target", ["192.0.2.13:443", "127.0.0.1:9443", "192.0.2.999:9443", "0.0.0.0/0", "--something", "host:9443"])
def test_invalid_listener_installs_no_rules(target):
    result = rules(target)
    assert result.returncode != 0
    assert not result.stdout


def test_no_listener_installs_no_rules():
    result = rules("")
    assert result.returncode == 0
    assert not result.stdout
