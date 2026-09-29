"""Exporters. Titles and banners come from remote servers, so every value is treated as untrusted."""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Optional, Sequence

from .models import ChangeLog, HostSnapshot, Scan, Target


def _csv_safe(value):
    """Neutralise spreadsheet formula injection (=, +, -, @ at the start of a cell)."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _md(value) -> str:
    """Render untrusted text as an inline code span: no links, HTML, emphasis or images can come out of it."""
    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text).replace("`", "'").replace("|", "\\|").strip()
    return f"`{text}`" if text else "-"


def _host_dict(s: HostSnapshot) -> dict:
    return {
        "hostname": s.hostname, "probe_status": s.probe_status, "is_live": s.is_live, "status_code": s.status_code,
        "url": s.url, "title": s.title,
        "web_server": s.web_server, "tech": s.tech or [], "dns_ips": s.dns_ips or [], "http_ips": s.http_ips or [], "scan_ips": s.scan_ips or [],
        "cdn_waf": s.cdn_waf, "open_ports": s.open_ports or [], "redirect": s.redirect_location, "port_scan_status": s.port_scan_status,
        "cname": s.cname or [], "discovery_sources": s.discovery_sources or [], "scanned_ips": s.scanned_ips or [], "failed_ips": s.failed_ips or []
    }


def to_json(target: Target, snapshots: Sequence[HostSnapshot], changes: Sequence[ChangeLog] = (),
            scan: Optional[Scan] = None) -> str:
    return json.dumps({
        "target": target.name, "platform": target.platform,
        "scan": {"id": scan.id, "mode": scan.mode, "complete": scan.complete, "config": scan.config_json} if scan else None,
        "in_scope": target.in_scope, "out_of_scope": target.out_of_scope,
        "hosts": [_host_dict(s) for s in snapshots],
        "changes": [{"host": c.hostname, "type": c.change_type, "details": c.details} for c in changes],
    }, indent=2)


def to_csv(snapshots: Sequence[HostSnapshot]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Hostname", "Probe", "Live", "Status", "Title", "Web Server", "Technologies", "IPs", "CDN/WAF", "Open Ports"])
    for s in snapshots:
        ports = ";".join(f"{p['port']}/{p.get('service', '')}" for p in (s.open_ports or []))
        writer.writerow([_csv_safe(v) for v in (
            s.hostname, s.probe_status, s.is_live, s.status_code or "", s.title or "", s.web_server or "",
            ",".join(s.tech or []), ",".join(s.dns_ips or []), s.cdn_waf or "", ports)])
    return buf.getvalue()


def to_markdown(target: Target, snapshots: Sequence[HostSnapshot], changes: Sequence[ChangeLog] = (),
                scan: Optional[Scan] = None) -> str:
    scope = (scan.config_json.get("scope") if scan and scan.config_json else None) or {
        "in_scope": target.in_scope, "out_of_scope": target.out_of_scope}
    lines = [
        f"# ReconBoard report: {_md(target.name)}", "",
        f"- **Platform:** {_md(target.platform)}",
        f"- **Scope used in this scan, in:** {_md(', '.join(scope['in_scope']))}",
        f"- **Scope used in this scan, out:** {_md(', '.join(scope['out_of_scope']) or 'none')}",
    ]
    if scan:
        lines.append(f"- **Scan:** {_md(scan.mode)}, complete: {'yes' if scan.complete else 'NO (partial, see problems)'}")
        if scan.config_json and "features" in scan.config_json:
            lines.append(f"- **Features Detected:** {_md(', '.join(k + ':' + '|'.join(v) for k,v in scan.config_json['features'].items()))}")
    lines += [f"- **Hosts:** {len(snapshots)}", ""]
    if changes:
        lines += ["## Changes since previous scan", "", "| Host | Change | Details |", "| :-- | :-- | :-- |"]
        lines += [f"| {_md(c.hostname)} | {_md(c.change_type)} | {_md(json.dumps(c.details))} |" for c in changes]
        lines.append("")
    lines += ["## Hosts", "", "| Host | Probe | Status | Title | Tech | Open ports |", "| :-- | :-- | :-- | :-- | :-- | :-- |"]
    shared = False
    for s in snapshots:
        status = str(s.status_code) if s.status_code else ("live" if s.is_live else "-")
        tech = ", ".join((s.tech or [])[:4]) or "-"
        ports = ", ".join(f"{p['port']}{'*' if p.get('shared') else ''}" for p in (s.open_ports or [])) or "-"
        shared = shared or any(p.get("shared") for p in (s.open_ports or []))
        lines.append(f"| {_md(s.hostname)} | {_md(s.probe_status)} | {_md(status)} | {_md(s.title)} | {_md(tech)} | {_md(ports)} |")
    if shared:
        lines += ["", "\\* IP is shared with other in-scope hosts: the port belongs to the IP, not necessarily to this hostname."]
    return "\n".join(lines) + "\n"
