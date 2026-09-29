import socket

import pytest
from typer.testing import CliRunner

from reconboard import db, tools
from reconboard.cli import app
from reconboard.models import ChangeLog, HostSnapshot, RawToolLog, ScopeAuditLog, Target
from reconboard.pipeline import PipelineError, ReconPipeline
from reconboard.scope import ScopeValidationError

IPS = {"app.example.com": "93.184.216.34", "cdn.example.com": "104.16.0.1", "internal.example.com": "10.0.0.9"}


def _probe(host, **kw):
    base = dict(hostname=host, status_code=200, title="t", is_live=True, http_ips=[IPS.get(host, "93.184.216.40")])
    base.update(kw)
    return tools.HttpxProbe(**base)


@pytest.fixture()
def fake_tools(monkeypatch):
    calls = {"subfinder": 0, "httpx": [], "nmap": [], "httpx_cmds": []}
    state = {"subfinder_exit": 0, "httpx_exit": 0, "httpx_extra": {}, "hosts": ["app.example.com", "cdn.example.com", "internal.example.com", "admin.example.com",
                       "evil.com", "x.example.com;id", "example.com.evil.com"]}
    monkeypatch.setattr(tools, "find_tool", lambda name: f"/fake/{name}")

    def subfinder(domain, binary="subfinder", timeout=300):
        calls["subfinder"] += 1
        return tools.SubfinderResult(list(state["hosts"]), "", "", state["subfinder_exit"], ["subfinder", "-d", domain])

    def crtsh(domain, **kw):
        return tools.CrtshResult(["*.example.com", "APP.example.com."], "[]", 200)

    def httpx(hosts, binary, rate_limit, threads, custom_headers=None, **kw):
        calls["httpx"].append(list(hosts))
        calls["httpx_cmds"].append(custom_headers)
        if state["httpx_exit"]:
            return tools.HttpxResult([], "", "boom", state["httpx_exit"], ["httpx", "-H", "Authorization: Bearer SECRET"])
        probes = [_probe(h, cdn_waf="cloudflare" if h == "cdn.example.com" else None, **state["httpx_extra"].get(h, {}))
                  for h in hosts]
        return tools.HttpxResult(probes, "", "", 0, ["httpx", "-H", "Authorization: Bearer SECRET"])

    def nmap(ips, binary, max_rate, top_ports=1000):
        calls["nmap"].append(list(ips))
        return tools.NmapResult({ip: [{"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": ""}]
                                 for ip in ips}, "", "", 0, ["nmap"])

    monkeypatch.setattr(tools, "run_subfinder", subfinder)
    monkeypatch.setattr(tools, "query_crtsh", crtsh)
    monkeypatch.setattr(tools, "run_httpx", httpx)
    monkeypatch.setattr(tools, "run_nmap", nmap)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [(socket.AF_INET, 1, 6, "", (IPS.get(host, "93.184.216.40"), 0))])
    calls["state"] = state
    return calls


@pytest.fixture()
def target(session):
    t = Target(name="demo", in_scope=["*.example.com"], out_of_scope=["admin.example.com"], allow_port_scan=True,
               custom_headers={"X-HackerOne-Research": "me"})
    session.add(t)
    session.commit()
    return t


def test_passive_scan_never_probes(session, target, fake_tools):
    scan = ReconPipeline(session, target, "passive").execute()
    assert scan.status == "completed" and fake_tools["httpx"] == [] and fake_tools["nmap"] == []
    snaps = session.query(HostSnapshot).filter_by(scan_id=scan.id).all()
    assert sorted(s.hostname for s in snaps) == ["app.example.com", "cdn.example.com", "internal.example.com"]
    assert not any(s.probed or s.is_live for s in snaps) and snaps[0].probe_status == "not_attempted"


def test_scope_guard_drops_and_audits(session, target, fake_tools):
    scan = ReconPipeline(session, target, "passive_probe").execute()
    sent = fake_tools["httpx"][0]
    assert sorted(sent) == ["app.example.com", "cdn.example.com"]  # internal.example.com -> 10.0.0.9 never reaches httpx
    reasons = {r.candidate_host: r.reason for r in session.query(ScopeAuditLog).filter_by(scan_id=scan.id)}
    assert reasons["admin.example.com"] == "out_of_scope_match"
    assert reasons["evil.com"] == "not_in_scope"
    assert reasons["example.com.evil.com"] == "not_in_scope"
    assert reasons["example.com"] == "not_in_scope"  # crt.sh '*.example.com' -> apex, not covered by the wildcard rule
    assert "invalid_hostname" in reasons.values()
    assert reasons["internal.example.com"] == "prohibited_ip"
    snaps = {s.hostname: s for s in session.query(HostSnapshot).filter_by(scan_id=scan.id)}
    assert snaps["internal.example.com"].probe_status == "blocked_ip" and not snaps["internal.example.com"].probed
    assert snaps["app.example.com"].probe_status == "ok" and snaps["app.example.com"].probed
    assert scan.stats_json["baseline"] is True


def test_full_scan_only_touches_vetted_public_non_cdn_ips(session, target, fake_tools):
    scan = ReconPipeline(session, target, "full").execute()
    assert fake_tools["nmap"] == [["93.184.216.34"]]  # cdn.example.com (CDN) and internal.example.com (10.x) skipped
    snaps = {s.hostname: s for s in session.query(HostSnapshot).filter_by(scan_id=scan.id)}
    assert snaps["app.example.com"].port_scan_status == "complete" and snaps["app.example.com"].open_ports[0]["port"] == 443
    assert snaps["cdn.example.com"].port_scan_status == "none" and snaps["internal.example.com"].port_scan_status == "none"
    assert scan.stats_json["nmap_skipped"] == {"cdn_waf_detected": 1}
    port = snaps["app.example.com"].open_ports[0]
    assert port["ip"] == "93.184.216.34" and port["shared"] is False


def test_full_mode_requires_permission(session, fake_tools):
    t = Target(name="nope", in_scope=["*.example.com"])
    session.add(t)
    session.commit()
    with pytest.raises(PipelineError, match="port scanning"):
        ReconPipeline(session, t, "full")
    with pytest.raises(PipelineError, match="Unknown mode"):
        ReconPipeline(session, t, "turbo")


def test_second_scan_produces_diff_and_raw_logs(session, target, fake_tools):
    ReconPipeline(session, target, "passive_probe").execute()
    fake_tools["state"]["hosts"].append("new.example.com")
    scan2 = ReconPipeline(session, target, "passive_probe").execute()
    changes = session.query(ChangeLog).filter_by(scan_id=scan2.id).all()
    assert [(c.hostname, c.change_type) for c in changes] == [("new.example.com", "new_subdomain")]
    assert scan2.stats_json["baseline"] is False
    assert session.query(RawToolLog).filter_by(scan_id=scan2.id, tool_name="httpx").count() == 1


def test_corrupt_stored_scope_refuses_to_scan(session, target, fake_tools):
    target.out_of_scope.append("*bad*")  # list mutation bypasses the model validator on purpose
    session.commit()
    with pytest.raises(PipelineError, match="invalid"):
        ReconPipeline(session, target, "passive").execute()
    assert fake_tools["subfinder"] == 0


def test_missing_tool_is_a_clean_error(session, target, monkeypatch):
    def missing(name):
        raise tools.ToolError("subfinder not found")
    monkeypatch.setattr(tools, "find_tool", missing)
    with pytest.raises(PipelineError, match="not found"):
        ReconPipeline(session, target, "passive").execute()


def test_target_model_validation(session):
    for kwargs in ({"in_scope": ["*.com"]}, {"in_scope": []}, {"in_scope": ["a.example.com"], "out_of_scope": ["10.0.0.0/8"]},
                   {"in_scope": ["a.example.com"], "custom_headers": {"Host": "x"}},
                   {"in_scope": ["a.example.com"], "rate_limit_profile": "insane"},
                   {"in_scope": ["a.example.com"], "custom_rate_limit": 0}):
        with pytest.raises(ScopeValidationError):
            Target(name="bad", **kwargs)
    t = Target(name="ok", in_scope=["*.Example.COM", "*.example.com"])
    assert t.in_scope == ["*.example.com"]


def test_cli_end_to_end(tmp_path, monkeypatch, fake_tools):
    monkeypatch.setenv("RECONBOARD_DB", f"sqlite:///{tmp_path / 'cli.db'}")
    run = CliRunner().invoke
    bad = run(app, ["target", "add", "x", "-i", "*.co.uk"])
    assert bad.exit_code == 1
    assert run(app, ["target", "add", "demo", "-i", "*.example.com", "-o", "admin.example.com",
                     "-H", "X-HackerOne-Research: me"]).exit_code == 0
    assert run(app, ["target", "add", "demo", "-i", "*.example.com"]).exit_code == 1  # duplicate
    assert "demo" in run(app, ["target", "list"]).output
    assert run(app, ["scan", "demo", "-m", "full", "-y"]).exit_code == 1  # port scan not enabled
    assert run(app, ["scan", "demo", "-m", "bogus"]).exit_code == 1
    scanned = run(app, ["scan", "demo", "-m", "passive_probe"])
    assert scanned.exit_code == 0, scanned.output
    assert "app.example.com" in run(app, ["hosts", "demo", "--live"]).output
    assert "baseline" in run(app, ["changes", "demo"]).output.lower()
    assert "out_of_scope_match" in run(app, ["dropped", "demo"]).output
    md = run(app, ["export", "demo", "-f", "md"]).output
    assert "app.example.com" in md and "| Host |" in md
    assert '"hostname": "app.example.com"' in run(app, ["export", "demo", "-f", "json"]).output
    assert run(app, ["export", "demo", "-f", "xml"]).exit_code == 1


def test_export_neutralises_untrusted_titles(session, target):
    from reconboard.export import to_csv, to_markdown
    from reconboard.models import Host, Scan
    scan = Scan(target_id=target.id, mode="passive_probe", status="completed")
    host = Host(target_id=target.id, hostname="a.example.com")
    session.add_all([scan, host])
    session.commit()
    snap = HostSnapshot(scan_id=scan.id, host_id=host.id, hostname="a.example.com", is_live=True,
                        title='=HYPERLINK("http://evil")', tech=[], open_ports=[])
    assert "'=HYPERLINK" in to_csv([snap])
    snap.title = "<script>alert(1)</script>|x`y"
    md = to_markdown(target, [snap])
    assert "`<script>alert(1)</script>\\|x'y`" in md  # inside a code span: rendered as literal text, pipe escaped


# ---------------------------------------------------------------- v0.1.1: findings from the external review
def test_httpx_result_with_non_public_ip_is_discarded(session, target, fake_tools):
    fake_tools["state"]["httpx_extra"] = {"app.example.com": {"http_ips": ["127.0.0.1"]}}  # rebinding-style answer
    scan = ReconPipeline(session, target, "passive_probe").execute()
    snap = session.query(HostSnapshot).filter_by(scan_id=scan.id, hostname="app.example.com").one()
    assert snap.probe_status == "blocked_ip" and not snap.is_live and snap.status_code is None
    reasons = {r.reason for r in session.query(ScopeAuditLog).filter_by(scan_id=scan.id, candidate_host="app.example.com")}
    assert "httpx_reported_prohibited_ip" in reasons


def test_failed_httpx_run_never_creates_fake_went_down(session, target, fake_tools):
    ReconPipeline(session, target, "passive_probe").execute()
    fake_tools["state"]["httpx_exit"] = 1
    scan2 = ReconPipeline(session, target, "passive_probe").execute()
    assert scan2.complete is False and scan2.stats_json["problems"]
    assert {s.probe_status for s in session.query(HostSnapshot).filter_by(scan_id=scan2.id, probed=True)} == set()
    assert session.query(ChangeLog).filter_by(scan_id=scan2.id).count() == 0
    # the broken scan is not a baseline: a healthy scan 3 compares against scan 1
    fake_tools["state"]["httpx_exit"] = 0
    scan3 = ReconPipeline(session, target, "passive_probe").execute()
    assert scan3.complete and session.query(ChangeLog).filter_by(scan_id=scan3.id).count() == 0


def test_partial_discovery_is_not_used_as_baseline(session, target, fake_tools):
    ReconPipeline(session, target, "passive").execute()  # complete baseline: 3 hosts
    fake_tools["state"]["subfinder_exit"] = 1
    fake_tools["state"]["hosts"] = ["app.example.com"]  # subfinder broke, saw only one host
    partial = ReconPipeline(session, target, "passive").execute()
    assert partial.complete is False and "subfinder exited" in partial.stats_json["problems"][0]
    assert session.query(ChangeLog).filter_by(scan_id=partial.id, change_type="not_seen").count() == 0
    fake_tools["state"]["subfinder_exit"] = 0
    fake_tools["state"]["hosts"] = ["app.example.com", "cdn.example.com", "internal.example.com", "admin.example.com"]
    healthy = ReconPipeline(session, target, "passive").execute()
    assert session.query(ChangeLog).filter_by(scan_id=healthy.id).count() == 0  # NOT 2 fake "new_subdomain"


def test_not_seen_and_reappeared(session, target, fake_tools):
    full = ["app.example.com", "cdn.example.com", "old.example.com"]
    fake_tools["state"]["hosts"] = full
    ReconPipeline(session, target, "passive").execute()
    fake_tools["state"]["hosts"] = ["app.example.com", "cdn.example.com"]
    s2 = ReconPipeline(session, target, "passive").execute()
    assert [(c.hostname, c.change_type) for c in session.query(ChangeLog).filter_by(scan_id=s2.id)] == [("old.example.com", "not_seen")]
    fake_tools["state"]["hosts"] = full
    s3 = ReconPipeline(session, target, "passive").execute()
    assert [(c.hostname, c.change_type) for c in session.query(ChangeLog).filter_by(scan_id=s3.id)] == [("old.example.com", "reappeared")]


def test_scope_change_suppresses_removal_detection_and_scope_is_recorded(session, target, fake_tools):
    s1 = ReconPipeline(session, target, "passive").execute()
    assert s1.scope_json == {"in_scope": ["*.example.com"], "out_of_scope": ["admin.example.com"]}
    target.out_of_scope = ["admin.example.com", "cdn.example.com"]  # tightened scope: cdn host disappears from results
    session.commit()
    s2 = ReconPipeline(session, target, "passive").execute()
    assert s2.stats_json["scope_changed"] is True
    assert session.query(ChangeLog).filter_by(scan_id=s2.id, change_type="not_seen").count() == 0


def test_secrets_are_redacted_in_raw_logs(session, target, fake_tools):
    scan = ReconPipeline(session, target, "passive_probe").execute()
    log = session.query(RawToolLog).filter_by(scan_id=scan.id, tool_name="httpx").one()
    assert "SECRET" not in log.command_executed and "Authorization: [REDACTED]" in log.command_executed


def test_shared_ip_is_flagged(session, target, fake_tools, monkeypatch):
    monkeypatch.setitem(IPS, "twin.example.com", "93.184.216.34")
    fake_tools["state"]["hosts"] = ["app.example.com", "twin.example.com"]
    scan = ReconPipeline(session, target, "full").execute()
    assert fake_tools["nmap"] == [["93.184.216.34"]]
    snaps = {s.hostname: s for s in session.query(HostSnapshot).filter_by(scan_id=scan.id)}
    assert all(s.open_ports[0]["shared"] for s in snaps.values())
    from reconboard.export import to_markdown
    assert "IP is shared" in to_markdown(target, list(snaps.values()), scan=scan)


def test_ip_change_is_reported(session, target, fake_tools, monkeypatch):
    ReconPipeline(session, target, "passive_probe").execute()
    monkeypatch.setitem(IPS, "app.example.com", "93.184.216.99")
    scan2 = ReconPipeline(session, target, "passive_probe").execute()
    kinds = {(c.hostname, c.change_type) for c in session.query(ChangeLog).filter_by(scan_id=scan2.id)}
    assert ("app.example.com", "ip_changed") in kinds


def test_markdown_cannot_inject_links_or_html(session, target):
    from reconboard.export import to_markdown
    snap = HostSnapshot(scan_id="s", host_id="h", hostname="a.example.com", is_live=True, probe_status="ok",
                        title="[Login](https://evil.example) ![x](http://e/i.png) <img src=x onerror=1> https://auto.link",
                        tech=[], open_ports=[])
    md = to_markdown(target, [snap])
    import re
    row = next(line for line in md.splitlines() if line.startswith("| `a.example.com`"))
    outside_code = re.sub(r"`[^`]*`", "", row)  # everything a Markdown renderer would interpret
    assert not any(ch in outside_code for ch in "[]()<>!") and "http" not in outside_code
    assert "`[Login](https://evil.example)" in row


def test_old_database_is_refused_with_clear_message(tmp_path, monkeypatch):
    import sqlite3
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE targets (id text)")
    con.commit()
    con.close()
    monkeypatch.setenv("RECONBOARD_DB", f"sqlite:///{path}")
    result = CliRunner().invoke(app, ["target", "list"])
    assert result.exit_code == 1 and "older ReconBoard" in result.output
    fresh = tmp_path / "fresh.db"
    db.init(f"sqlite:///{fresh}")
    db.init(f"sqlite:///{fresh}")  # re-opening a current-version DB is fine
    assert oct(fresh.stat().st_mode & 0o777) == "0o600"
