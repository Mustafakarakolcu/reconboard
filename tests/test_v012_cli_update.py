import pytest
from typer.testing import CliRunner
from reconboard.cli import app
from reconboard import db
from reconboard.models import Target, Scan

def test_cli_target_update_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("RECONBOARD_DB", f"sqlite:///{tmp_path / 'cli.db'}")
    run = CliRunner().invoke
    run(app, ["target", "add", "demo", "-i", "*.example.com"])

    res1 = run(app, ["target", "update", "demo", "--profile", "invalid"])
    assert res1.exit_code != 0
    assert "Traceback" not in res1.output

    res2 = run(app, ["target", "update", "demo", "--remove-in-scope", "*.example.com"])
    assert res2.exit_code != 0
    assert "Traceback" not in res2.output

    res3 = run(app, ["target", "update", "demo", "--header", "invalid"])
    assert res3.exit_code != 0
    assert "Traceback" not in res3.output

def test_cli_target_update_flags(tmp_path, monkeypatch):
    monkeypatch.setenv("RECONBOARD_DB", f"sqlite:///{tmp_path / 'cli.db'}")
    run = CliRunner().invoke
    run(app, ["target", "add", "demo2", "-i", "*.example.com", "-H", "Old: val", "--allow-port-scan", "--allow-shared-ip-scan"])

    res = run(app, ["target", "update", "demo2", "--clear-headers", "--no-allow-port-scan", "--no-allow-shared-ip-scan"])
    assert res.exit_code == 0

    with db.session() as s:
        t = s.query(Target).filter_by(name="demo2").one()
        assert t.custom_headers == {}
        assert t.allow_port_scan is False
        assert t.allow_shared_ip_scan is False

def test_scan_show_escaping(tmp_path, monkeypatch):
    monkeypatch.setenv("RECONBOARD_DB", f"sqlite:///{tmp_path / 'cli.db'}")
    db.init()
    with db.session() as s:
        t = Target(name="demo3", in_scope=["*.example.com"])
        s.add(t)
        s.flush()
        scan = Scan(id="12345678", target_id=t.id, mode="[red]mode[/]", status="[red]status[/]", stats_json={"problems": ["[bold red]x[/]"]})
        s.add(scan)
        s.commit()

    res = CliRunner().invoke(app, ["scan-show", "12345678"])
    assert res.exit_code == 0
    assert "[bold red]x[/]" in res.output
    assert "[red]mode[/]" in res.output
