import pytest
import json
from reconboard.models import Target, HostSnapshot, RawToolLog
from reconboard.pipeline import ReconPipeline, PipelineError
from reconboard.tools import HttpxProbe, ToolError
from reconboard import tools
from v012_helpers import make_env

def test_b3_pipeline_redirect(session, monkeypatch):
    probes = {"a.com": HttpxProbe(hostname="a.com", is_live=True, status_code=301, redirect_location="https://other.example.org/x")}
    calls = make_env(monkeypatch, probes=probes)
    t = Target(name="b3", in_scope=["a.com"])
    session.add(t)
    session.commit()
    scan = ReconPipeline(session, t, "passive_probe").execute()
    snap = session.query(HostSnapshot).filter_by(scan_id=scan.id).one()
    assert snap.redirect_location == "https://other.example.org/x"
    assert "other.example.org" not in calls["resolve"]

def test_b5_redaction(session, monkeypatch):
    t = Target(name="b5", in_scope=["a.com", "*.b.com"], custom_headers={"X-Token": "supersecret-value"})
    session.add(t)
    session.commit()
    cmd = ["httpx", "-H", "X-Token: supersecret-value"]
    def fake_sub(*a, **kw): raise tools.ToolError("boom Authorization: Bearer abc123def and X-Token: supersecret-value")
    make_env(monkeypatch, httpx_exit=1, httpx_stderr="Authorization: Bearer abc123def\nLeak: supersecret-value", httpx_stdout="Cookie: sess=xyz789", httpx_command=cmd)
    monkeypatch.setattr(tools, "run_subfinder", fake_sub)
    scan = ReconPipeline(session, t, "passive_probe").execute()
    log = session.query(RawToolLog).filter_by(scan_id=scan.id, tool_name="httpx").one()
    assert "supersecret-value" not in log.command_executed
    assert "abc123def" not in log.stderr
    assert "xyz789" not in log.stdout
    probs = json.dumps(scan.stats_json.get("problems", []))
    assert "supersecret-value" not in probs and "abc123def" not in probs and "xyz789" not in probs
    assert "[REDACTED]" in probs

def test_b6_config_json(session, monkeypatch):
    make_env(monkeypatch, help_text="-probe -allow")
    t = Target(name="b6", in_scope=["a.com"], allow_port_scan=True, allow_shared_ip_scan=True, custom_headers={"X-Auth": "secret123"})
    session.add(t)
    session.commit()
    scan = ReconPipeline(session, t, "passive_probe").execute()
    cfg = scan.config_json
    assert "scope" in cfg and "profile" in cfg and "rates" in cfg
    assert cfg["allow_port_scan"] is True
    assert cfg["allow_shared_ip_scan"] is True
    assert cfg["header_names"] == ["X-Auth"]
    assert "versions" in cfg
    assert "-probe" in cfg["features"]["httpx"] and "-allow" in cfg["features"]["httpx"]
    assert cfg["mode"] == "passive_probe"
    assert cfg["probe_mode"] == "probe"
    assert "ip_allowlist" in cfg
    assert "secret123" not in json.dumps(cfg)

def test_b7_subfinder_requirement(session, monkeypatch):
    def fake_find(name):
        if name == "subfinder": raise ToolError("no subfinder")
        return f"/fake/{name}"
    make_env(monkeypatch)
    monkeypatch.setattr(tools, "find_tool", fake_find)
    t1 = Target(name="b7_exact", in_scope=["a.com"])
    session.add(t1)
    session.commit()
    assert ReconPipeline(session, t1, "passive_probe").execute().complete

    t2 = Target(name="b7_wild", in_scope=["*.a.com"])
    session.add(t2)
    session.commit()
    with pytest.raises(PipelineError, match="no subfinder"):
        ReconPipeline(session, t2, "passive_probe").execute()

def test_c2_nmap_ipv6_and_partial(session, monkeypatch):
    resolve = {"a.com": (True, ["1.1.1.1", "2606:4700::1"], "safe"), "b.com": (True, ["2.2.2.2", "3.3.3.3"], "safe"), "c.com": (True, ["4.4.4.4"], "safe")}
    nmap = {"hosts": {"1.1.1.1": [], "2.2.2.2": []}}
    probes = {h: HttpxProbe(hostname=h, is_live=True) for h in resolve}
    probes["c.com"].cdn_waf = "cdn"
    calls = make_env(monkeypatch, resolve=resolve, nmap=nmap, probes=probes)
    t = Target(name="c2", in_scope=["a.com", "b.com", "c.com"], allow_port_scan=True)
    session.add(t)
    session.commit()
    scan = ReconPipeline(session, t, "full").execute()

    assert not any(":" in ip for ip in calls["nmap"][0]["ips"])
    snaps = {s.hostname: s for s in session.query(HostSnapshot).filter_by(scan_id=scan.id).all()}
    assert snaps["a.com"].port_scan_status == "complete"
    assert snaps["b.com"].port_scan_status == "partial"
    assert snaps["b.com"].scanned_ips == ["2.2.2.2"] and snaps["b.com"].failed_ips == ["3.3.3.3"]
    assert snaps["c.com"].port_scan_status == "none"
    assert snaps["c.com"].scanned_ips == [] and snaps["c.com"].failed_ips == []

def test_c3_discovery_sources(session, monkeypatch):
    make_env(monkeypatch, subfinder_hosts=["sf.a.com", "both.a.com"], crt_hosts=["crt.a.com", "both.a.com"])
    t = Target(name="c3", in_scope=["seed.com", "*.a.com"])
    session.add(t)
    session.commit()
    scan = ReconPipeline(session, t, "passive_probe").execute()
    snaps = {s.hostname: s for s in session.query(HostSnapshot).filter_by(scan_id=scan.id).all()}
    assert snaps["seed.com"].discovery_sources == ["seed"]
    assert snaps["sf.a.com"].discovery_sources == ["subfinder"]
    assert snaps["crt.a.com"].discovery_sources == ["crtsh"]
    assert snaps["both.a.com"].discovery_sources == ["subfinder", "crtsh"]

def test_c4_probe_fields(session, monkeypatch):
    make_env(monkeypatch, probes={"a.com": HttpxProbe(hostname="a.com", is_live=True, cname=["x.com"], content_type="text/html", response_time="1s")})
    t = Target(name="c4", in_scope=["a.com"])
    session.add(t)
    session.commit()
    snap = session.query(HostSnapshot).filter_by(scan_id=ReconPipeline(session, t, "passive_probe").execute().id).one()
    assert snap.cname == ["x.com"] and snap.content_type == "text/html" and snap.response_time == "1s"

def test_crtsh_subfinder_errors(session, monkeypatch):
    make_env(monkeypatch, crt_error="boom")
    t1 = Target(name="crt", in_scope=["*.a.com"])
    session.add(t1)
    session.commit()
    s1 = ReconPipeline(session, t1, "passive_probe").execute()
    assert not s1.complete and "boom" in " ".join(s1.stats_json["problems"])

    make_env(monkeypatch)
    monkeypatch.setattr(tools, "run_subfinder", lambda d, b, t=0: tools.SubfinderResult([], "", "", 1, []))
    s2 = ReconPipeline(session, t1, "passive_probe").execute()
    assert not s2.complete

def test_passive_mode(session, monkeypatch):
    calls = make_env(monkeypatch, subfinder_hosts=["b.a.com"])
    t = Target(name="pass", in_scope=["a.com", "*.a.com"])
    session.add(t)
    session.commit()
    scan = ReconPipeline(session, t, "passive").execute()
    assert not calls["resolve"] and not calls["httpx"] and not calls["nmap"]
    for snap in session.query(HostSnapshot).filter_by(scan_id=scan.id).all():
        assert snap.probe_status == "not_attempted" and snap.probed is False
