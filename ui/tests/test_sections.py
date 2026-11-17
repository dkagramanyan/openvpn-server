"""Traffic by podkop section: conntrack lines, the client at a VPN address, the router's answers."""
import json
import os

import pytest

from pg_fixture import Database
from app import sections
from app.db import SECTION_DOMAIN_RETENTION, HOUR_RETENTION

LINE = ("[1794948045.038197]\t[DESTROY] tcp      6 CLOSE src=10.0.70.135 dst=95.213.56.4 sport=54572 dport=443 "
        "packets=12 bytes=3760 src=95.213.56.4 dst=170.134.51.30 sport=443 dport=54572 packets=13 bytes=7852 [ASSURED]")
T = 1794948000          # an hour start


def flow_line(ts, src, dst, up, down, proto="tcp"):
    return (f"[{ts}.5]\t[DESTROY] {proto}      6 CLOSE src={src} dst={dst} sport=1000 dport=443 packets=1 bytes={up} "
            f"src={dst} dst=170.134.51.30 sport=443 dport=1000 packets=1 bytes={down} [ASSURED]\n")


def test_parse_flow_takes_both_directions_and_rejects_noise():
    f = sections.parse_flow(LINE)
    assert f == {"ts": 1794948045, "proto": "tcp", "src": "10.0.70.135", "dst": "95.213.56.4", "dport": 443,
                 "bytes_in": 3760, "bytes_out": 7852}
    # Without accounting the counters are missing: no bytes, not an error.
    bare = sections.parse_flow("[1794948045.1]\t[DESTROY] udp      17 src=10.0.70.2 dst=170.134.51.1 sport=1 dport=53 "
                               "src=170.134.51.1 dst=170.134.51.30 sport=53 dport=1")
    assert bare["bytes_in"] == bare["bytes_out"] == 0 and bare["proto"] == "udp"
    for noise in ("", "WARNING: We have hit ENOBUFS!", "[1] [NEW] tcp src=10.0.70.2 dst=1.1.1.1",
                  "[1794948045.1]\t[DESTROY] tcp src=fd00:70::2 dst=2001:db8::1 bytes=1 bytes=2"):
        assert sections.parse_flow(noise) is None


def test_ranges_match_cidrs_and_inclusive_ranges():
    r = sections.Ranges(["149.154.160.0/20", "91.108.4.0-91.108.7.255", "10.0.0.0/8", "bogus", "5.5.5.9-5.5.5.1"])
    value = sections.ip_int
    assert value("149.154.175.1") in r and value("91.108.7.255") in r and value("91.108.4.0") in r
    assert value("91.108.8.0") not in r and value("149.154.176.0") not in r and value("5.5.5.5") not in r
    assert len(r) == 3
    assert sections.is_fakeip("198.19.255.255") and sections.is_fakeip("198.18.0.40") and not sections.is_fakeip("198.20.0.1")


def test_validate_address_and_authorized_line(tmp_path, monkeypatch):
    assert sections.validate_address(" 171.134.51.1 ") == "root@171.134.51.1"
    assert sections.validate_address("admin@router.lan") == "admin@router.lan"
    assert sections.validate_address("") == ""
    for bad in ("root@", "root@host;rm", "-oProxyCommand=x", "a b@host", "root@host/x"):
        with pytest.raises(ValueError):
            sections.validate_address(bad)
    monkeypatch.setattr(sections, "router_dir", lambda: tmp_path / "router")
    assert sections.authorized_line() is None
    line = sections.create_key()
    assert line.startswith('restrict,command="/usr/bin/podkop-agent --sections-only" ssh-ed25519 ')
    assert line.endswith(" openvpn-server-sections") and "PRIVATE" not in line
    assert oct(os.stat(tmp_path / "router/id_ed25519").st_mode & 0o777) == "0o600"
    with pytest.raises(ValueError):
        sections.create_key()
    assert sections.create_key(replace=True) != line


class Router:
    """The agent as the contract describes it; records every request."""
    def __init__(self, domains=None, addresses=None, subnets=(), boot="b1"):
        self.domains, self.addresses, self.subnets, self.boot = domains or {}, addresses or {}, list(subnets), boot
        self.calls, self.down = [], False

    def __call__(self, address, request):
        assert address == "root@router" and len(request["domains"]) <= 500 and len(request["addresses"]) <= 500
        self.calls.append(request)
        if self.down:
            raise sections.SectionsUnavailable("router did not answer: TimeoutExpired")
        data = {"boot_id": self.boot, "sections": ["youtube", "telegram", "main"],
                "domains": {d: s for d, s in self.domains.items() if d in request["domains"]},
                "addresses": {a: v for a, v in self.addresses.items() if a in request["addresses"]}}
        if request["subnets"]:
            data["subnets"] = self.subnets
        return data


def setup(router, tmp_path):
    db = Database()
    db.set_setting("router_sections", json.dumps({"address": "root@router"}))
    with db.tx() as conn:
        conn.execute("INSERT INTO vpn_sessions (client_name, cid, real_address, vpn_ip, connected_at, last_seen, disconnected_at) "
                     "VALUES ('alice', 1, '203.0.113.5:1', '10.0.70.2', ?, ?, ?)", (T - 3600, T + 600, T + 600))
        conn.execute("INSERT INTO vpn_sessions (client_name, cid, real_address, vpn_ip, connected_at, last_seen) "
                     "VALUES ('bob', 2, '203.0.113.6:1', '10.0.70.2', ?, ?)", (T + 1200, T + 3000))
    return db, sections.SectionCollector(db, call=router, flows_log=tmp_path / "flows.log")


def totals(db, **where):
    sql = "SELECT client_name, source, section, SUM(bytes_in) AS i, SUM(bytes_out) AS o, SUM(flows) AS n FROM section_traffic"
    rows = db.query(sql + " GROUP BY client_name, source, section")
    return {(r["client_name"], r["source"], r["section"]): (int(r["i"]), int(r["o"]), int(r["n"])) for r in rows}


def test_vpn_flows_are_mapped_to_the_client_of_the_address_at_the_time_and_classified(tmp_path):
    router = Router(addresses={"198.18.0.40": {"section": "youtube", "host": "www.youtube.com"},
                               "149.154.167.50": {"section": "telegram", "host": ""}},
                    subnets=["149.154.160.0/20"])
    db, c = setup(router, tmp_path)
    (tmp_path / "flows.log").write_text(
        flow_line(T + 10, "10.0.70.2", "198.18.0.40", 100, 1000)        # alice, youtube
        + flow_line(T + 20, "10.0.70.2", "198.18.0.99", 5, 50)          # alice, a FakeIP the router never saw
        + flow_line(T + 30, "10.0.70.2", "149.154.167.50", 7, 70)      # alice, telegram by address
        + flow_line(T + 40, "10.0.70.2", "149.154.161.1", 1, 10)       # in the address set, not seen
        + flow_line(T + 50, "10.0.70.2", "95.213.56.4", 3, 30)         # direct
        + flow_line(T + 1500, "10.0.70.2", "95.213.56.4", 2, 20)       # the same address is bob's now
        + flow_line(T + 60, "10.0.70.9", "95.213.56.4", 9, 90)         # nobody had this address
        + flow_line(T + 70, "10.0.70.2", "1.1.1.1", 0, 0))             # no counters: skipped
    c.poll(now=T + 1600)
    assert totals(db) == {("alice", "vpn", "youtube"): (100, 1000, 1), ("alice", "vpn", "?"): (6, 60, 2),
                          ("alice", "vpn", "telegram"): (7, 70, 1), ("alice", "vpn", ""): (3, 30, 1),
                          ("bob", "vpn", ""): (2, 20, 1)}
    assert c.status["unmapped"] == 1
    assert db.query("SELECT COUNT(*) AS n FROM section_pending")[0]["n"] == 0
    # The address lists were missing, so they came with the first call; the addresses
    # inside them were asked at once in a second one.
    assert [r["subnets"] for r in router.calls] == [True, False]
    assert router.calls[1]["addresses"] == ["149.154.161.1", "149.154.167.50"]
    domains = {r["domain"]: r["section"] for r in db.query("SELECT domain, section FROM section_domains")}
    assert domains == {"www.youtube.com": "youtube"}
    # The log position is kept: reading again adds nothing.
    c.poll(now=T + 1700)
    assert totals(db)[("alice", "vpn", "youtube")] == (100, 1000, 1)


def test_log_rotation_is_read_from_the_start(tmp_path):
    router = Router()
    db, c = setup(router, tmp_path)
    log = tmp_path / "flows.log"
    log.write_text(flow_line(T + 10, "10.0.70.2", "95.213.56.4", 1, 10) * 3)
    c.poll(now=T + 100)
    log.write_text(flow_line(T + 20, "10.0.70.2", "95.213.56.4", 2, 20))      # truncated and written again
    c.poll(now=T + 200)
    os.replace(tmp_path / "flows.log", tmp_path / "flows.log.1")
    (tmp_path / "flows.log").write_text(flow_line(T + 30, "10.0.70.2", "95.213.56.4", 4, 40))   # a new file
    c.poll(now=T + 300)
    assert totals(db)[("alice", "vpn", "")] == (3 + 2 + 4, 30 + 20 + 40, 5)
    # A partial last line waits for its end.
    with open(log, "a") as fh:
        fh.write(flow_line(T + 40, "10.0.70.2", "95.213.56.4", 8, 80)[:30])
    c.poll(now=T + 400)
    assert totals(db)[("alice", "vpn", "")][2] == 5


def relay_row(db, ident, ts, target, address, up, down, client="carol"):
    with db.tx() as conn:
        conn.execute("INSERT INTO relay_flows (instance, id, client_name, ts, kind, target, address, bytes_up, bytes_down) "
                     "VALUES ('r1', ?, ?, ?, 'closed', ?, ?, ?, ?)", (ident, client, ts, target, address, up, down))


def test_relay_flows_use_the_routers_answer_then_the_asked_name(tmp_path):
    router = Router(domains={"rr3.googlevideo.com": "youtube"},
                    addresses={"198.18.0.7": {"section": "main", "host": "chatgpt.com"}})
    db, c = setup(router, tmp_path)
    relay_row(db, 1, T + 5, "chatgpt.com:443", "198.18.0.7:443", 10, 100)
    relay_row(db, 2, T + 6, "rr3.googlevideo.com:443", "198.18.0.8:443", 20, 200)    # address unknown, name known
    relay_row(db, 3, T + 7, "nowhere.example:443", "198.18.0.9:443", 30, 300)
    relay_row(db, 4, T + 8, "93.184.215.14:443", "93.184.215.14:443", 40, 400)     # a literal address: direct
    relay_row(db, 5, T + 9, "refused.example:443", None, 0, 0)                     # never connected
    c.poll(now=T + 60)
    assert totals(db) == {("carol", "relay", "main"): (10, 100, 1), ("carol", "relay", "youtube"): (20, 200, 1),
                          ("carol", "relay", "?"): (30, 300, 1), ("carol", "relay", ""): (40, 400, 1)}
    domains = {(r["domain"], r["section"]) for r in db.query("SELECT domain, section FROM section_domains")}
    assert domains == {("chatgpt.com", "main"), ("rr3.googlevideo.com", "youtube"), ("nowhere.example", "?")}
    assert router.calls[0]["domains"] == ["chatgpt.com", "nowhere.example", "rr3.googlevideo.com"]
    assert db.query("SELECT COUNT(*) AS n FROM relay_flows WHERE NOT sectioned")[0]["n"] == 0


def test_router_outage_keeps_flows_waiting_and_an_hour_makes_them_unknown(tmp_path):
    router = Router(addresses={"198.18.0.40": {"section": "youtube", "host": "www.youtube.com"}})
    db, c = setup(router, tmp_path)
    router.down = True
    (tmp_path / "flows.log").write_text(flow_line(T + 10, "10.0.70.2", "198.18.0.40", 1, 10)
                                        + flow_line(T + 11, "10.0.70.2", "95.213.56.4", 2, 20))
    c.poll(now=T + 100)
    assert totals(db) == {} and c.status["error"].startswith("router did not answer")
    # Without the address lists even a "direct" destination is not known to be direct.
    assert db.query("SELECT COUNT(*) AS n FROM section_pending")[0]["n"] == 2
    router.down = False
    c.poll(now=T + 200)
    assert totals(db) == {("alice", "vpn", "youtube"): (1, 10, 1), ("alice", "vpn", ""): (2, 20, 1)}
    router.down = True
    (tmp_path / "flows.log").write_text((tmp_path / "flows.log").read_text() + flow_line(T + 300, "10.0.70.2", "198.18.0.40", 4, 40))
    c.poll(now=T + 400)
    c.poll(now=T + 400 + sections.PENDING_MAX_AGE + 1)
    assert totals(db)[("alice", "vpn", "?")] == (4, 40, 1)


def test_waiting_flows_survive_a_restart(tmp_path):
    router = Router(addresses={"198.18.0.40": {"section": "youtube", "host": "www.youtube.com"}})
    db, c = setup(router, tmp_path)
    router.down = True
    (tmp_path / "flows.log").write_text(flow_line(T + 10, "10.0.70.2", "198.18.0.40", 1, 10))
    c.poll(now=T + 100)
    router.down = False
    again = sections.SectionCollector(db, call=router, flows_log=tmp_path / "flows.log")    # a new UI process
    again.poll(now=T + 200)
    assert totals(db) == {("alice", "vpn", "youtube"): (1, 10, 1)}


def test_router_reboot_makes_waiting_fakeip_flows_unknown(tmp_path):
    router = Router(addresses={"198.18.0.40": {"section": "youtube", "host": "www.youtube.com"}})
    db, c = setup(router, tmp_path)
    (tmp_path / "flows.log").write_text(flow_line(T + 10, "10.0.70.2", "198.18.0.40", 1, 10))
    c.poll(now=T + 100)
    router.down = True
    with open(tmp_path / "flows.log", "a") as fh:
        fh.write(flow_line(T + 120, "10.0.70.2", "198.18.0.40", 2, 20))
    c.poll(now=T + 150)
    router.down, router.boot = False, "b2"        # the router came back after a reboot
    c.poll(now=T + 300)
    assert totals(db) == {("alice", "vpn", "youtube"): (1, 10, 1), ("alice", "vpn", "?"): (2, 20, 1)}
    assert db.get_setting("sections:boot_id") == "b2"


def test_large_batches_are_split(tmp_path):
    router = Router()
    db, c = setup(router, tmp_path)
    (tmp_path / "flows.log").write_text("".join(flow_line(T + 10, "10.0.70.2", f"198.18.{i // 250}.{i % 250 + 1}", 1, 1)
                                                for i in range(1200)))
    c.poll(now=T + 100)
    assert len(router.calls) == 3 and sum(len(r["addresses"]) for r in router.calls) == 1200
    assert [r["subnets"] for r in router.calls] == [True, False, False]
    assert totals(db)[("alice", "vpn", "?")][2] == 1200


def test_switched_off_reads_nothing(tmp_path):
    router = Router()
    db, c = setup(router, tmp_path)
    db.set_setting("router_sections", json.dumps({"address": ""}))
    (tmp_path / "flows.log").write_text(flow_line(T + 10, "10.0.70.2", "95.213.56.4", 1, 10))
    c.poll(now=T + 100)
    assert router.calls == [] and db.query("SELECT COUNT(*) AS n FROM section_pending")[0]["n"] == 0


def test_retention_domains_seven_days_sections_folded_into_days_forever():
    db = Database()
    now = 2_000_000_000 - 2_000_000_000 % 86400
    old_hour = now - HOUR_RETENTION - 86400 + 5 * 3600
    with db.tx() as conn:
        for ts in (old_hour, old_hour + 3600, now - 3600):
            conn.execute("INSERT INTO section_traffic (ts, client_name, source, section, bytes_in, bytes_out, flows) "
                         "VALUES (?, 'alice', 'vpn', 'youtube', 1, 10, 1)", (ts,))
        for ts in (now - SECTION_DOMAIN_RETENTION - 3600, now - 3600):
            conn.execute("INSERT INTO section_domains (ts, client_name, source, section, domain, bytes_in, bytes_out, flows) "
                         "VALUES (?, 'alice', 'vpn', 'youtube', 'www.youtube.com', 1, 10, 1)", (ts,))
    db.rollup(now=now)
    db.rollup(now=now)           # twice changes nothing
    rows = db.query("SELECT ts, bytes_in, bytes_out, flows FROM section_traffic ORDER BY ts")
    assert [(r["ts"], r["bytes_in"], r["flows"]) for r in rows] == [(old_hour - old_hour % 86400, 2, 2), (now - 3600, 1, 1)]
    assert [r["ts"] for r in db.query("SELECT ts FROM section_domains")] == [now - 3600]


def test_history_follows_archive_and_purge():
    db = Database()
    with db.tx() as conn:
        conn.execute("INSERT INTO section_traffic (ts, client_name, source, section) VALUES (3600, 'erin', 'vpn', 'main')")
        conn.execute("INSERT INTO section_domains (ts, client_name, source, section, domain) VALUES (3600, 'erin', 'vpn', 'main', 'x.example')")
        conn.execute("INSERT INTO section_traffic (ts, client_name, source, section) VALUES (3600, 'UNDEF', 'vpn', 'main')")
    key = db.archive_client_history("erin")
    assert key and db.query("SELECT client_name FROM section_traffic WHERE client_name = ?", (key,))
    assert db.query("SELECT client_name FROM section_domains")[0]["client_name"] == key
    db.purge_client("UNDEF")
    assert not db.query("SELECT 1 FROM section_traffic WHERE client_name = 'UNDEF'")


def test_report_orders_sections_and_measures_the_unknown_share():
    db = Database()
    now = int(__import__("time").time())
    h = now - now % 3600
    with db.tx() as conn:
        for client, source, section, bi, bo in (("alice", "vpn", "youtube", 10, 990), ("bob", "relay", "youtube", 0, 1000),
                                                ("alice", "relay", "?", 0, 1000), ("alice", "vpn", "", 0, 5000)):
            conn.execute("INSERT INTO section_traffic (ts, client_name, source, section, bytes_in, bytes_out, flows) "
                         "VALUES (?, ?, ?, ?, ?, ?, 1)", (h, client, source, section, bi, bo))
        conn.execute("INSERT INTO section_domains (ts, client_name, source, section, domain, bytes_in, bytes_out, flows) "
                     "VALUES (?, 'alice', 'vpn', 'youtube', 'www.youtube.com', 10, 990, 1)", (h,))
    every = sections.report(db, h - 86400, now + 1)
    assert [s["section"] for s in every["sections"]] == ["youtube", "", "?"] or \
        [s["section"] for s in every["sections"]] == ["youtube", "?", ""]
    youtube = every["sections"][0]
    assert youtube["vpn"] == {"bytes_in": 10, "bytes_out": 990} and youtube["relay"] == {"bytes_in": 0, "bytes_out": 1000}
    assert [c["name"] for c in youtube["clients"]] == ["alice", "bob"] or [c["name"] for c in youtube["clients"]] == ["bob", "alice"]
    assert every["unknown_share"] == pytest.approx(1000 / 3000)
    alice = sections.report(db, h - 86400, now + 1, "alice", domains=True)
    assert alice["domains_available"] and alice["sections"][0]["domains"][0]["domain"] == "www.youtube.com"
    assert "clients" not in alice["sections"][0]
    assert not sections.report(db, h - 30 * 86400, now + 1, "alice", domains=True)["domains_available"]


def test_the_router_is_checked_without_traffic_and_its_silence_is_an_event(tmp_path):
    router = Router(subnets=["149.154.160.0/20"])
    db, c = setup(router, tmp_path)
    kinds = lambda: [r["kind"] for r in db.query("SELECT kind FROM events WHERE kind LIKE 'router_sections_%' ORDER BY id")]
    c.poll(now=T)                               # no traffic at all: the first check
    assert router.calls == [{"domains": [], "addresses": [], "subnets": True}]
    assert c.status["last_ok"] == T and c.status["error"] is None and len(c.ranges) == 1
    assert c.sections == ["youtube", "telegram", "main"]
    c.poll(now=T + 60)                          # not again within five minutes
    assert len(router.calls) == 1
    router.down = True
    c.poll(now=T + 300)
    c.poll(now=T + 600)
    assert len(router.calls) == 3 and c.status["error"] and kinds() == ["router_sections_down"]    # one event, not two
    router.down = False
    c.poll(now=T + 900)
    assert c.status["error"] is None and c.status["last_ok"] == T + 900
    assert kinds() == ["router_sections_down", "router_sections_up"]
