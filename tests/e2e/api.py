"""The end-to-end test's hands on the web UI. Runs inside the openvpn-ui container (inside.sh)."""
import collections
import http.cookiejar
import json
import re
import sys
import urllib.request

BASE = "http://127.0.0.1:8080"
LOG = "/var/log/openvpn/openvpn.log"
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def call(path, body=None):
    req = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"X-Requested-With": "fetch", "Content-Type": "application/json"})
    with opener.open(req, timeout=30) as res:
        data = res.read().decode()
        return json.loads(data) if res.headers.get("content-type", "").startswith("application/json") else data


def check():
    sessions = call("/api/sessions?limit=500")["sessions"]
    by_name = collections.defaultdict(list)
    for s in sessions:
        by_name[s["client_name"]].append(s)
    for s in sessions:
        print(f"    {s['client_name']:6} {s['real_address']:28} {s['proto']} {s['platform']} {s['client_ver']} "
              f"{(s['disconnected_at'] or 0) - s['connected_at']:4d} s  {s['end_reason']}")

    # Every session ending in the log is a session in the UI, with the same ending.
    ends = re.findall(r"^\S+ \S+ ([^/\s]+)/\S+ SIG\w+\[\w+,([^\]]*)\] received, client-instance", open(LOG).read(), re.M)
    words = {"delayed-exit": "left", "remote-exit": "left", "ping-restart": "timed out",
             "ovpn-dco: ping expired": "timed out", "connection-reset": "closed",
             "ovpn-dco: transport disconnected": "closed"}
    in_log = collections.Counter((name, words.get(reason, reason)) for name, reason in ends)
    in_ui = collections.Counter((s["client_name"], s["end_reason"]) for s in sessions)
    assert in_log == in_ui, f"log {dict(in_log)} != UI {dict(in_ui)}"

    alice, bob = by_name["alice"], by_name["bob"]
    assert len(alice) == 5 and len(bob) == 1, (len(alice), len(bob))
    assert all(s["platform"] == "linux" and s["client_ver"].startswith("2.7") for s in sessions), "device missing"
    assert all(s["disconnected_at"] for s in sessions), "a session is still open"
    assert [s["proto"] for s in alice].count("tcp") == 1 and bob[0]["proto"] == "udp"
    assert [s["end_reason"] for s in alice if s["proto"] == "udp"] == ["left"] * 4
    assert next(s for s in alice if s["proto"] == "tcp")["end_reason"] in ("closed", "left")
    assert bob[0]["end_reason"] == "timed out"
    first = alice[-1]
    assert first["bytes_in"] > 0 and first["bytes_out"] > 0 and first["vpn_ip"].startswith("10.0.70.")

    # alice's five connections came from one address within minutes: one visit
    visits = call("/api/sessions?merge=true")
    assert visits["total"] == 2, visits["total"]
    v = next(v for v in visits["sessions"] if v["client_name"] == "alice")
    assert v["connections"] == 5 and v["tcp"] == 1 and v["bytes_in"] == sum(s["bytes_in"] for s in alice)
    assert call("/api/clients/alice")["sessions"][0]["connections"] == 5

    stats = {c["name"]: c for c in call("/api/connections?range=today")["clients"]}
    a, b = stats["alice"], stats["bob"]
    assert (a["sessions"], a["tcp"], a["left"] + a["closed"], a["timed_out"], a["platform"]) == (5, 1, 5, 0, "linux"), a
    assert (b["sessions"], b["timed_out"], b["left"]) == (1, 1, 0), b
    assert a["short"] >= 3 and a["median_seconds"] is not None

    kinds = {e["kind"] for e in call("/api/events?limit=1000")["events"]}
    assert {"client_created", "profile_downloaded"} <= kinds and not kinds & {"vpn_connect", "vpn_disconnect"}, kinds
    assert not call("/api/overview")["warnings"], call("/api/overview")["warnings"]
    print("    sessions, endings, devices, visits and statistics match the log")


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    call("/api/login", {"username": "admin", "password": "e2e-password"})
    if cmd == "create":
        call("/api/clients", {"name": args[0]})
    elif cmd == "profile":
        sys.stdout.write(call(f"/api/clients/{args[0]}/ovpn"))
    elif cmd == "backup":
        status = call("/api/server/backup", {})["backup"]
        assert status["count"] >= 1 and status["size"] > 1000, status
    elif cmd == "summary":      # what a restore has to bring back
        clients = [(c["name"], c["state"], c["cert"]["serial"], c["total"]["sessions"]) for c in call("/api/clients")["clients"]]
        json.dump({"clients": sorted(clients), "sessions": call("/api/sessions")["total"],
                   "visits": call("/api/sessions?merge=true")["total"]}, sys.stdout, sort_keys=True)
    elif cmd == "check":
        check()
    else:
        sys.exit(f"unknown command {cmd}")


if __name__ == "__main__":
    main()
