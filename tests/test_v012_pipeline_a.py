import pytest
from v012_helpers import make_env
from reconboard.models import Target, HostSnapshot, ScopeAuditLog, ChangeLog
from reconboard.pipeline import ReconPipeline
from reconboard.tools import HttpxProbe

def test_a1_outcomes(session, monkeypatch):
    resolve = {
        "blocked-dns.com": (False, ["10.0.0.1"], "prohibited_ip:10.0.0.1"),
        "nx.com": (False, [], "dns_nxdomain:x"),
        "err.com": (False, [], "dns_error:x")
    }
    probes = {
        "ok.com": HttpxProbe(hostname="ok.com", is_live=True, status_code=200),
        "failed-probe.com": HttpxProbe(hostname="failed-probe.com", is_live=False, failed=True),
        "blocked-httpx.com": HttpxProbe(hostname="blocked-httpx.com", is_live=True, status_code=200, http_ips=["127.0.0.1"])
    }
    for i in range(60):
        resolve[f"fill{i}.com"] = (True, ["93.184.216.34"], "safe")
        probes[f"fill{i}.com"] = HttpxProbe(hostname=f"fill{i}.com", is_live=True, status_code=200)

    make_env(monkeypatch, resolve=resolve, probes=probes, help_text="-probe")
    t = Target(name="a1", in_scope=["ok.com", "failed-probe.com", "missing-line.com", "blocked-dns.com", "blocked-httpx.com", "nx.com", "err.com"] + [f"fill{i}.com" for i in range(60)])
    session.add(t)
    session.commit()

    scan = ReconPipeline(session, t, "passive_probe").execute()
    snaps = {s.hostname: s for s in session.query(HostSnapshot).filter_by(scan_id=scan.id).all()}

    assert snaps["ok.com"].probe_status == "ok" and snaps["ok.com"].probed is True
    assert snaps["failed-probe.com"].probe_status == "no_response" and snaps["failed-probe.com"].probed is True
    assert snaps["missing-line.com"].probe_status == "no_result" and snaps["missing-line.com"].probed is False
    assert snaps["blocked-dns.com"].probe_status == "blocked_ip" and snaps["blocked-dns.com"].probed is False
    assert snaps["blocked-httpx.com"].probe_status == "blocked_ip" and snaps["blocked-httpx.com"].probed is False
    assert not snaps["blocked-httpx.com"].is_live
    assert snaps["nx.com"].probe_status == "nxdomain" and snaps["nx.com"].probed is True
    assert snaps["err.com"].probe_status == "dns_error" and snaps["err.com"].probed is False

    audits = {a.candidate_host: a.reason for a in session.query(ScopeAuditLog).filter_by(scan_id=scan.id).all()}
    assert audits["blocked-dns.com"] == "prohibited_ip"
    assert audits["blocked-httpx.com"] == "httpx_reported_prohibited_ip"

    probs = " ".join(scan.stats_json.get("problems", []))
    assert "missing-line.com" in probs and "err.com" in probs

def test_a2_nmap(session, monkeypatch):
    make_env(monkeypatch, nmap={"ok": False, "error": "broken", "hosts": {}})
    t1 = Target(name="a2_1", in_scope=["a.com"], allow_port_scan=True)
    session.add(t1)
    session.commit()
    s1 = ReconPipeline(session, t1, "full").execute()
    assert not s1.complete
    assert "broken" in " ".join(s1.stats_json.get("problems", []))
    assert session.query(HostSnapshot).filter_by(scan_id=s1.id, hostname="a.com").one().port_scan_status == "partial"

    resolve = {
        "a.com": (True, ["1.1.1.1"], "safe"),
        "cdn.com": (True, ["2.2.2.2"], "safe"),
        "shared1.com": (True, ["3.3.3.3"], "safe"),
        "shared2.com": (True, ["3.3.3.3"], "safe"),
        "v6.com": (True, ["2606:4700::1"], "safe")
    }
    probes = {
        "a.com": HttpxProbe(hostname="a.com", is_live=True),
        "cdn.com": HttpxProbe(hostname="cdn.com", is_live=True, cdn_waf="cloudflare"),
        "shared1.com": HttpxProbe(hostname="shared1.com", is_live=True),
        "shared2.com": HttpxProbe(hostname="shared2.com", is_live=True),
        "v6.com": HttpxProbe(hostname="v6.com", is_live=True)
    }
    make_env(monkeypatch, resolve=resolve, probes=probes, nmap={"ok": True, "hosts": {"1.1.1.1": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}]}})
    t2 = Target(name="a2_2", in_scope=["a.com", "cdn.com", "shared1.com", "shared2.com", "v6.com"], allow_port_scan=True)
    session.add(t2)
    session.commit()
    s2 = ReconPipeline(session, t2, "full").execute()

    assert s2.complete
    snaps = {s.hostname: s for s in session.query(HostSnapshot).filter_by(scan_id=s2.id).all()}
    assert snaps["a.com"].port_scan_status == "complete"

    skipped = s2.stats_json.get("nmap_skipped", {})
    assert skipped.get("cdn_waf_detected") == 1
    assert skipped.get("shared_ip") == 2
    assert skipped.get("ipv6_only") == 1

def test_a3_dns(session, monkeypatch):
    make_env(monkeypatch, resolve={"err1.com": (False, [], "dns_error:x"), "err2.com": (False, [], "dns_timeout:x")})
    t1 = Target(name="a3_1", in_scope=["err1.com", "err2.com"])
    session.add(t1)
    session.commit()
    s1 = ReconPipeline(session, t1, "passive_probe").execute()
    assert not s1.complete
    assert "All DNS lookups failed" in " ".join(s1.stats_json.get("problems", []))

    make_env(monkeypatch, resolve={"nx1.com": (False, [], "dns_nxdomain:x")})
    t2 = Target(name="a3_2", in_scope=["nx1.com"])
    session.add(t2)
    session.commit()
    s2 = ReconPipeline(session, t2, "passive_probe").execute()
    assert s2.complete

def test_a4_allowlist(session, monkeypatch):
    resolve = {"a.com": (True, ["1.1.1.1"], "safe"), "b.com": (True, ["2.2.2.2"], "safe"), "private.com": (False, ["10.0.0.1"], "prohibited_ip:10.0.0.1")}
    calls = make_env(monkeypatch, resolve=resolve)
    t = Target(name="a4", in_scope=["a.com", "b.com", "private.com"])
    session.add(t)
    session.commit()
    s = ReconPipeline(session, t, "passive_probe").execute()
    assert s.config_json["ip_allowlist"] == ["1.1.1.1", "2.2.2.2"]
    assert set(calls["httpx"][0]["vetted_ips"]) == {"1.1.1.1", "2.2.2.2"}

def test_b1_ips_diff(session, monkeypatch):
    t = Target(name="b1", in_scope=["a.com", "b.com", "c.com", "d.com"], allow_port_scan=True)
    session.add(t)
    session.commit()

    resolve = {"a.com": (True, ["1.1.1.1"], "safe"), "b.com": (True, ["3.3.3.3"], "safe"), "c.com": (True, ["5.5.5.5"], "safe"), "d.com": (True, ["7.7.7.7"], "safe")}
    probes = {h: HttpxProbe(hostname=h, is_live=True, http_ips=[resolve[h][1][0]]) for h in resolve}
    probes["c.com"].cdn_waf = "cloudflare"
    make_env(monkeypatch, resolve=resolve, probes=probes)

    s1 = ReconPipeline(session, t, "full").execute()
    assert s1.complete
    snap_a = session.query(HostSnapshot).filter_by(scan_id=s1.id, hostname="a.com").one()
    assert snap_a.dns_ips == ["1.1.1.1"] and snap_a.http_ips == ["1.1.1.1"] and snap_a.scan_ips == ["1.1.1.1"]

    resolve2 = {"a.com": (True, ["2.2.2.2"], "safe"), "b.com": (True, ["3.3.3.3", "4.4.4.4"], "safe"), "c.com": (True, ["6.6.6.6"], "safe"), "d.com": (True, ["8.8.8.8"], "safe")}
    probes2 = {
        "a.com": HttpxProbe(hostname="a.com", is_live=True, http_ips=["2.2.2.2"]),
        "b.com": HttpxProbe(hostname="b.com", is_live=True, http_ips=["4.4.4.4"]),
        "c.com": HttpxProbe(hostname="c.com", is_live=True, cdn_waf="cloudflare", http_ips=["6.6.6.6"])
    }
    make_env(monkeypatch, resolve=resolve2, probes=probes2, help_text="-probe")
    s2 = ReconPipeline(session, t, "full").execute()

    changes = [(c.hostname, c.change_type) for c in session.query(ChangeLog).filter_by(scan_id=s2.id).all()]
    assert ("a.com", "ip_changed") in changes
    assert ("b.com", "ip_changed") not in changes
    assert ("c.com", "ip_changed") not in changes
    assert ("d.com", "ip_changed") not in changes

def test_b2_shared_ip(session, monkeypatch):
    resolve = {"a.com": (True, ["1.1.1.1"], "safe"), "b.com": (True, ["1.1.1.1"], "safe"), "c.com": (True, ["1.1.1.1", "2.2.2.2"], "safe")}
    calls = make_env(monkeypatch, resolve=resolve)
    t = Target(name="b2", in_scope=["a.com", "b.com", "c.com"], allow_port_scan=True, allow_shared_ip_scan=False)
    session.add(t)
    session.commit()
    s1 = ReconPipeline(session, t, "full").execute()
    assert s1.stats_json.get("nmap_skipped", {}).get("shared_ip") == 3
    assert len(calls["nmap"]) == 0

    t.allow_shared_ip_scan = True
    session.commit()
    s2 = ReconPipeline(session, t, "full").execute()
    assert s2.stats_json.get("nmap_skipped", {}).get("shared_ip", 0) == 0
    assert len(calls["nmap"]) == 1
    assert set(calls["nmap"][0]["ips"]) == {"1.1.1.1", "2.2.2.2"}
