from typer.testing import CliRunner
from reconboard.cli import app
from reconboard.models import Target, Scan, HostSnapshot
from reconboard import db, tools

def test_cli_updates(tmp_path, monkeypatch):
    monkeypatch.setenv("RECONBOARD_DB", f"sqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setattr(tools, "run_subfinder", lambda *a, **kw: tools.SubfinderResult([], "", "", 0, []))
    monkeypatch.setattr(tools, "query_crtsh", lambda *a, **kw: tools.CrtshResult([], "", 200, ""))
    monkeypatch.setattr(tools, "run_httpx", lambda *a, **kw: tools.HttpxResult([], "", "", 0, []))
    monkeypatch.setattr(tools, "run_nmap", lambda *a, **kw: tools.NmapResult({}, "", "", 0, [], True, None))
    monkeypatch.setattr(tools, "find_tool", lambda n: f"/fake/{n}")
    monkeypatch.setattr(tools, "get_tool_version", lambda n: "1.0")
    monkeypatch.setattr(tools, "_get_help", lambda n: "")
    run = CliRunner().invoke
    run(app, ["target", "add", "demo", "-i", "*.example.com"])
    assert run(app, ["target", "update", "demo", "--allow-shared-ip-scan", "--allow-port-scan"]).exit_code == 0
    assert run(app, ["scans", "demo"]).exit_code == 0
    assert run(app, ["scan", "demo", "-m", "passive"]).exit_code == 0

def test_cli_hosts_source(tmp_path, monkeypatch):
    monkeypatch.setenv("RECONBOARD_DB", f"sqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setattr(tools, "find_tool", lambda n: f"/fake/{n}")
    monkeypatch.setattr(tools, "get_tool_version", lambda n: "1.0")
    monkeypatch.setattr(tools, "_get_help", lambda n: "")
    monkeypatch.setattr(tools, "run_subfinder", lambda d, b, t=0: tools.SubfinderResult(["sf.acme.io", "both.acme.io"], "", "", 0, []))
    monkeypatch.setattr(tools, "query_crtsh", lambda d: tools.CrtshResult(["crt.acme.io", "both.acme.io"], "", 200, ""))
    run = CliRunner().invoke
    assert run(app, ["target", "add", "hdemo", "-i", "*.acme.io"]).exit_code == 0
    run(app, ["scan", "hdemo", "-m", "passive"])

    res_sf = run(app, ["hosts", "hdemo", "--source", "subfinder"])
    assert "sf.acme.io" in res_sf.output and "both.acme.io" in res_sf.output and "crt.acme.io" not in res_sf.output
    res_both = run(app, ["hosts", "hdemo", "--source", "both"])
    assert "both.acme.io" in res_both.output and "sf.acme.io" not in res_both.output
    res_inv = run(app, ["hosts", "hdemo", "--source", "invalid"])
    assert res_inv.exit_code != 0
    assert "Traceback" not in res_inv.output
