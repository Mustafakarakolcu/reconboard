import pytest
from reconboard.pipeline import ReconPipeline
from reconboard.models import Target, HostSnapshot
from reconboard import tools

def test_pipeline_r1(session, monkeypatch):
    t = Target(name="r1", in_scope=["*.example.com"])
    session.add(t)
    session.commit()

    monkeypatch.setattr(tools.ScopeGuard, "resolve_and_validate_host", lambda host, timeout: (True, ["1.1.1.1"], "safe"))
    monkeypatch.setattr(tools, "find_tool", lambda name: f"/fake/{name}")
    monkeypatch.setattr(tools, "get_tool_version", lambda name: "1.0")
    monkeypatch.setattr(tools, "_get_help", lambda name: "")

    def fake_sub(domain, bin, timeout=0):
        return tools.SubfinderResult(["a.example.com"], "", "", 0, [])
    monkeypatch.setattr(tools, "run_subfinder", fake_sub)

    def fake_crtsh(domain):
        return tools.CrtshResult(["a.example.com"], "", 200, "")
    monkeypatch.setattr(tools, "query_crtsh", fake_crtsh)

    def fake_httpx(hosts, *a, **kw):
        probe = tools.HttpxProbe(hostname="a.example.com", is_live=True, status_code=200)
        return tools.HttpxResult([probe], "", "", 0, [])
    monkeypatch.setattr(tools, "run_httpx", fake_httpx)

    scan = ReconPipeline(session, t, "passive_probe").execute()

    assert scan.status == "completed"
    snap = session.query(HostSnapshot).filter_by(scan_id=scan.id).first()
    assert snap is not None
    assert snap.probe_status == "ok"
