"""ReconBoard command line interface."""
from __future__ import annotations

from typing import List, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from sqlalchemy.exc import IntegrityError

from . import config, db, tools
from .export import to_csv, to_json, to_markdown
from .models import ChangeLog, Host, HostSnapshot, Scan, ScopeAuditLog, Target
from .pipeline import PipelineError, ReconPipeline
from .scope import ScopeValidationError

app = typer.Typer(help="Scope-guarded recon pipeline for AUTHORIZED bug bounty targets.",
                  add_completion=False, no_args_is_help=True)
target_app = typer.Typer(help="Manage targets and their scope.", no_args_is_help=True)
app.add_typer(target_app, name="target")
console = Console()
err_console = Console(stderr=True)


def _fail(message: str) -> "typer.Exit":
    err_console.print(f"[bold red]{escape(message)}[/bold red]")
    raise typer.Exit(1)


def _get_target(session, name: str) -> Target:
    target = session.query(Target).filter(Target.name == name).first()
    if not target:
        _fail(f"Target '{name}' not found. Run 'reconboard target list'.")
    return target


def _latest_scan(session, target: Target) -> Optional[Scan]:
    return (session.query(Scan).filter(Scan.target_id == target.id, Scan.status == "completed")
            .order_by(Scan.started_at.desc()).first())


def _parse_headers(items: List[str]) -> dict:
    headers = {}
    for item in items:
        if ":" not in item:
            _fail(f"Header must look like 'Name: value', got '{item}'.")
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


@app.callback()
def _main() -> None:
    try:
        db.init()
    except db.DatabaseVersionError as exc:
        _fail(str(exc))


@app.command()
def doctor() -> None:
    """Check that subfinder, httpx (ProjectDiscovery) and nmap are installed."""
    table = Table(title="External tools", box=None)
    table.add_column("Tool", style="bold cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim", overflow="fold")
    for name, (ok, detail) in tools.check_tools().items():
        table.add_row(name, "[green]OK[/green]" if ok else "[red]MISSING[/red]", escape(detail))
    console.print(table)
    console.print(f"[dim]Database: {escape(config.db_url())}[/dim]")


@target_app.command("add")
def target_add(
    name: str = typer.Argument(..., help="Short unique name, e.g. clear"),
    in_scope: List[str] = typer.Option(..., "--in-scope", "-i", help="Repeatable. '*.example.com' or 'app.example.com'"),
    out_of_scope: List[str] = typer.Option([], "--out-of-scope", "-o", help="Repeatable. Overrides in-scope."),
    platform: str = typer.Option("HackerOne", "--platform", "-p"),
    allow_port_scan: bool = typer.Option(False, "--allow-port-scan", help="Only if the program permits port scanning."),
    allow_shared_ip_scan: bool = typer.Option(False, "--allow-shared-ip-scan", help="Only if the program permits scanning shared IPs."),
    profile: str = typer.Option("safe", "--profile", help="safe | normal | aggressive"),
    rate_limit: Optional[int] = typer.Option(None, "--rate-limit", help="httpx requests/second override."),
    header: List[str] = typer.Option([], "--header", "-H", help="Repeatable. e.g. 'X-HackerOne-Research: yourname'"),
) -> None:
    """Register a program with strictly validated scope rules."""
    headers = _parse_headers(header)
    with db.session() as session:
        try:
            session.add(Target(name=name, platform=platform, in_scope=in_scope, out_of_scope=out_of_scope,
                               allow_port_scan=allow_port_scan, allow_shared_ip_scan=allow_shared_ip_scan, rate_limit_profile=profile,
                               custom_rate_limit=rate_limit, custom_headers=headers))
            session.commit()
        except ScopeValidationError as exc:
            session.rollback()
            _fail(f"Invalid configuration: {exc}")
        except IntegrityError:
            session.rollback()
            _fail(f"A target named '{name}' already exists.")
    console.print(f"[green]Target '{escape(name)}' created.[/green]")


@target_app.command("list")
def target_list() -> None:
    """List targets."""
    with db.session() as session:
        targets = session.query(Target).order_by(Target.name).all()
        if not targets:
            console.print("[yellow]No targets yet. Use 'reconboard target add'.[/yellow]")
            return
        table = Table(title="Targets", box=None)
        for col in ("Name", "Platform", "Port scan", "Profile", "In scope", "Out of scope"):
            table.add_column(col)
        for t in targets:
            table.add_row(escape(t.name), escape(t.platform or "-"), "yes" if t.allow_port_scan else "no",
                          t.rate_limit_profile, escape(", ".join(t.in_scope)), escape(", ".join(t.out_of_scope) or "-"))
        console.print(table)


@target_app.command("update")
def target_update(
    name: str = typer.Argument(...),
    add_in_scope: List[str] = typer.Option([], "--add-in-scope"),
    remove_in_scope: List[str] = typer.Option([], "--remove-in-scope"),
    add_out_of_scope: List[str] = typer.Option([], "--add-out-of-scope"),
    remove_out_of_scope: List[str] = typer.Option([], "--remove-out-of-scope"),
    allow_port_scan: Optional[bool] = typer.Option(None, "--allow-port-scan/--no-allow-port-scan"),
    allow_shared_ip_scan: Optional[bool] = typer.Option(None, "--allow-shared-ip-scan/--no-allow-shared-ip-scan"),
    profile: Optional[str] = typer.Option(None, "--profile"),
    rate_limit: Optional[int] = typer.Option(None, "--rate-limit"),
    header: List[str] = typer.Option([], "--header", "-H"),
    clear_headers: bool = typer.Option(False, "--clear-headers"),
) -> None:
    """Update a target's configuration."""
    with db.session() as session:
        t = _get_target(session, name)
        new_in = list(t.in_scope)
        if add_in_scope: new_in = sorted(set(new_in + add_in_scope))
        if remove_in_scope: new_in = [x for x in new_in if x not in remove_in_scope]
        new_out = list(t.out_of_scope)
        if add_out_of_scope: new_out = sorted(set(new_out + add_out_of_scope))
        if remove_out_of_scope: new_out = [x for x in new_out if x not in remove_out_of_scope]
        new_headers = {} if clear_headers else dict(t.custom_headers)
        if header: new_headers.update(_parse_headers(header))
        try:
            t.in_scope = new_in
            t.out_of_scope = new_out
            t.custom_headers = new_headers
            if allow_port_scan is not None: t.allow_port_scan = allow_port_scan
            if allow_shared_ip_scan is not None: t.allow_shared_ip_scan = allow_shared_ip_scan
            if profile is not None: t.rate_limit_profile = profile
            if rate_limit is not None: t.custom_rate_limit = rate_limit
            session.commit()
        except (ScopeValidationError, ValueError) as exc:
            session.rollback()
            _fail(f"Invalid configuration: {exc}")
    console.print(f"[green]Target '{escape(name)}' updated.[/green]")

@target_app.command("remove")
def target_remove(name: str = typer.Argument(...), yes: bool = typer.Option(False, "--yes", "-y")) -> None:
    """Delete a target and all its scan data."""
    with db.session() as session:
        target = _get_target(session, name)
        if not yes:
            typer.confirm(f"Delete '{name}' and all its data?", abort=True)
        session.delete(target)
        session.commit()
    console.print(f"[green]Removed '{escape(name)}'.[/green]")


@app.command()
def scan(
    name: str = typer.Argument(...),
    mode: str = typer.Option("passive", "--mode", "-m", help="passive | passive_probe | full"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation for full mode."),
) -> None:
    """Run the pipeline. 'passive' never sends a packet to the target."""
    if mode not in config.MODES:
        _fail(f"Unknown mode '{mode}'. Use: {', '.join(config.MODES)}.")
    with db.session() as session:
        target = _get_target(session, name)
        if mode == "full" and not yes:
            typer.confirm(
                "FULL mode runs nmap (TCP connect + service detection) against the resolved IPs of live, "
                "non-CDN in-scope hosts. Does this program explicitly allow port scanning?", abort=True)
        console.print(f"[bold cyan]Scan '{escape(name)}' ({mode})[/bold cyan]")
        try:
            result = ReconPipeline(session, target, mode, log=lambda m: console.print(f"[dim]- {escape(m)}[/dim]")).execute()
        except PipelineError as exc:
            _fail(str(exc))
        except Exception as exc:
            _fail(f"Scan failed: {exc}")
        stats = result.stats_json or {}
        if result.complete:
            console.print("[green]Scan completed.[/green]")
        else:
            console.print("[yellow]Scan finished WITH PROBLEMS - it will not be used as a baseline for diffs:[/yellow]")
            for text in stats.get("problems", []):
                console.print(f"  [yellow]- {escape(text)}[/yellow]")
        for key, value in stats.items():
            if key != "problems":
                console.print(f"  {key}: {escape(str(value))}")


@app.command("scans")
def scans_list(name: str = typer.Argument(...)) -> None:
    """List scans for a target."""
    with db.session() as session:
        target = _get_target(session, name)
        scans = session.query(Scan).filter(Scan.target_id == target.id).order_by(Scan.started_at.desc()).limit(20).all()
        if not scans:
            console.print("[yellow]No scans yet.[/yellow]")
            return
        table = Table(title=f"Scans for '{escape(name)}'", box=None)
        for col in ("ID", "Mode", "Status", "Complete", "Date"):
            table.add_column(col)
        for s in scans:
            table.add_row(s.id[:8], s.mode, s.status, "yes" if s.complete else "no", str(s.started_at)[:16])
        console.print(table)

@app.command("scan-show")
def scan_show(scan_id: str = typer.Argument(...)) -> None:
    """Show details of a specific scan."""
    with db.session() as session:
        scan = session.query(Scan).filter(Scan.id.startswith(scan_id)).first()
        if not scan:
            _fail("Scan not found.")
        console.print(f"[bold cyan]Scan {escape(scan.id)}[/bold cyan]")
        console.print(f"Mode: {escape(scan.mode)}, Status: {escape(scan.status)}, Complete: {scan.complete}")
        if scan.stats_json:
            for k, v in scan.stats_json.items():
                console.print(f"{escape(k)}: {escape(str(v))}")

@app.command()
def hosts(name: str = typer.Argument(...), live: bool = typer.Option(False, "--live", help="Only live hosts"), source: Optional[str] = typer.Option(None, "--source", help="subfinder|crtsh|both")) -> None:
    """Show hosts from the latest completed scan."""
    if source and source not in ("subfinder", "crtsh", "both"):
        _fail("Source must be 'subfinder', 'crtsh', or 'both'.")
    with db.session() as session:
        target = _get_target(session, name)
        latest = _latest_scan(session, target)
        if not latest:
            _fail("No completed scan yet.")
        query = session.query(HostSnapshot).filter(HostSnapshot.scan_id == latest.id)
        if live:
            query = query.filter(HostSnapshot.is_live.is_(True))
        table = Table(title=f"{escape(name)} - scan {latest.id[:8]} ({latest.mode})", box=None)
        for col in ("Host", "Probe", "Status", "Title", "Tech", "Ports"):
            table.add_column(col, overflow="fold")
        snaps = query.order_by(HostSnapshot.hostname).all()
        if source:
            snaps = [s for s in snaps if source in (s.discovery_sources or []) or (source == "both" and "subfinder" in (s.discovery_sources or []) and "crtsh" in (s.discovery_sources or []))]
        for s in snaps:
            table.add_row(escape(s.hostname), s.probe_status, str(s.status_code or "-"), escape(s.title or "-"),
                          escape(", ".join((s.tech or [])[:3]) or "-"),
                          ",".join(str(p["port"]) for p in (s.open_ports or [])) or "-")
        console.print(table)


@app.command()
def changes(name: str = typer.Argument(...)) -> None:
    """Show what changed in the latest completed scan compared to the one before."""
    with db.session() as session:
        target = _get_target(session, name)
        latest = _latest_scan(session, target)
        if not latest:
            _fail("No completed scan yet.")
        rows = session.query(ChangeLog).filter(ChangeLog.scan_id == latest.id).all()
        if not rows:
            msg = ("No earlier complete scan to compare with (this one is the baseline)."
                   if (latest.stats_json or {}).get("baseline") else "No changes.")
            console.print(f"[green]{msg}[/green]")
            return
        table = Table(title=f"Changes in scan {latest.id[:8]}", box=None)
        for col in ("Host", "Change", "Details"):
            table.add_column(col, overflow="fold")
        for c in rows:
            table.add_row(escape(c.hostname), escape(c.change_type), escape(str(c.details)))
        console.print(table)


@app.command()
def dropped(name: str = typer.Argument(...)) -> None:
    """Show candidates the Scope Guard rejected in the latest scan (audit trail)."""
    with db.session() as session:
        target = _get_target(session, name)
        latest = _latest_scan(session, target)
        if not latest:
            _fail("No completed scan yet.")
        table = Table(title="Dropped by Scope Guard", box=None)
        for col in ("Candidate", "Reason", "Rule"):
            table.add_column(col, overflow="fold")
        for r in session.query(ScopeAuditLog).filter(ScopeAuditLog.scan_id == latest.id).limit(500).all():
            table.add_row(escape(r.candidate_host), escape(r.reason), escape(r.rule_matched or "-"))
        console.print(table)


@app.command()
def export(
    name: str = typer.Argument(...),
    fmt: str = typer.Option("md", "--format", "-f", help="md | json | csv"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write to a file instead of stdout"),
) -> None:
    """Export the latest scan."""
    if fmt not in ("md", "json", "csv"):
        _fail("Format must be md, json or csv.")
    with db.session() as session:
        target = _get_target(session, name)
        latest = _latest_scan(session, target)
        if not latest:
            _fail("No completed scan yet.")
        snaps = session.query(HostSnapshot).filter(HostSnapshot.scan_id == latest.id).order_by(HostSnapshot.hostname).all()
        diffs = session.query(ChangeLog).filter(ChangeLog.scan_id == latest.id).all()
        data = {"md": lambda: to_markdown(target, snaps, diffs, latest), "json": lambda: to_json(target, snaps, diffs, latest),
                "csv": lambda: to_csv(snaps)}[fmt]()
    if output:
        with open(output, "w", encoding="utf-8", newline="") as fh:
            fh.write(data)
        console.print(f"[green]Wrote {escape(output)}[/green]")
    else:
        typer.echo(data)


if __name__ == "__main__":
    app()
