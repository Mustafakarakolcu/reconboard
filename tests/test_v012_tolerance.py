import pytest
from reconboard.pipeline import ReconPipeline
from reconboard.models import Target, HostSnapshot, ChangeLog
from reconboard import tools

@pytest.fixture()
def mock_tools(monkeypatch):
    monkeypatch.setattr(tools, "find_tool", lambda name: f"/fake/{name}")
    monkeypatch.setattr(tools, "get_tool_version", lambda name: "1.0")
    monkeypatch.setattr(tools, "run_subfinder", lambda *a, **kw: tools.SubfinderResult([], "", "", 0, []))
    monkeypatch.setattr(tools, "query_crtsh", lambda *a, **kw: tools.CrtshResult([], "", 200, ""))
    def fake_resolve(host, timeout):
        if host.startswith("nx"): return False, [], "dns_nxdomain:x"
        return True, ["1.1.1.1"], "safe"
    monkeypatch.setattr(tools.ScopeGuard, "resolve_and_validate_host", fake_resolve)

def test_tolerance_1_ok(session, mock_tools, monkeypatch):
    monkeypatch.setattr(tools, "_get_help", lambda name: "-probe")
    def fake_httpx(hosts, *a, **kw):
        probes = [tools.HttpxProbe(hostname=h, is_live=True, status_code=200) for h in hosts if h != "miss.com"]
        return tools.HttpxResult(probes, "", "", 0, [])
    monkeypatch.setattr(tools, "run_httpx", fake_httpx)

    t = Target(name="t1", in_scope=["miss.com"] + [f"h{i}.com" for i in range(99)])
    session.add(t)
    session.commit()
    scan = ReconPipeline(session, t, "passive_probe").execute()
    assert scan.complete is True

def test_tolerance_10_percent_fails(session, mock_tools, monkeypatch):
    monkeypatch.setattr(tools, "_get_help", lambda name: "-probe")
    def fake_httpx(hosts, *a, **kw):
        probes = [tools.HttpxProbe(hostname=h, is_live=True, status_code=200) for h in hosts if not h.startswith("miss")]
        return tools.HttpxResult(probes, "", "", 0, [])
    monkeypatch.setattr(tools, "run_httpx", fake_httpx)

    t = Target(name="t2", in_scope=[f"miss{i}.com" for i in range(10)] + [f"h{i}.com" for i in range(90)])
    session.add(t)
    session.commit()
    scan = ReconPipeline(session, t, "passive_probe").execute()
    assert scan.complete is False

def test_tolerance_nxdomain(session, mock_tools, monkeypatch):
    monkeypatch.setattr(tools, "_get_help", lambda name: "-probe")
    def fake_httpx(hosts, *a, **kw):
        probes = [tools.HttpxProbe(hostname=h, is_live=True, status_code=200) for h in hosts]
        return tools.HttpxResult(probes, "", "", 0, [])
    monkeypatch.setattr(tools, "run_httpx", fake_httpx)

    t = Target(name="t3", in_scope=[f"nx{i}.com" for i in range(30)] + [f"h{i}.com" for i in range(70)])
    session.add(t)
    session.commit()
    scan = ReconPipeline(session, t, "passive_probe").execute()
    assert scan.complete is True
    assert not any("nx" in p for p in scan.stats_json.get("problems", []))

def test_no_probe_unconfirmed(session, mock_tools, monkeypatch):
    monkeypatch.setattr(tools, "_get_help", lambda name: "")

    def fake_httpx1(hosts, *a, **kw):
        probes = [tools.HttpxProbe(hostname=h, is_live=True, status_code=200) for h in hosts]
        return tools.HttpxResult(probes, "", "", 0, [])
    monkeypatch.setattr(tools, "run_httpx", fake_httpx1)
    t = Target(name="t4", in_scope=["a.com", "b.com"])
    session.add(t)
    session.commit()
    scan1 = ReconPipeline(session, t, "passive_probe").execute()
    assert scan1.complete is True

    def fake_httpx2(hosts, *a, **kw):
        probes = [tools.HttpxProbe(hostname="b.com", is_live=True, status_code=200)]
        return tools.HttpxResult(probes, "", "", 0, [])
    monkeypatch.setattr(tools, "run_httpx", fake_httpx2)
    scan2 = ReconPipeline(session, t, "passive_probe").execute()
    assert scan2.complete is True
    snap_a = session.query(HostSnapshot).filter_by(scan_id=scan2.id, hostname="a.com").one()
    assert snap_a.probe_status == "no_response_unconfirmed"
    assert snap_a.probed is False
    changes = session.query(ChangeLog).filter_by(scan_id=scan2.id, hostname="a.com").all()
    assert not any(c.change_type in ("went_down", "went_live") for c in changes)
