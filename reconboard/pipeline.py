"""Synchronous recon pipeline.

seeds -> passive discovery (subfinder + crt.sh) -> Scope Guard -> host records
      -> DNS/IP gate -> httpx probe (passive_probe/full) -> vetted-IP nmap (full + allow_port_scan)
      -> snapshots -> diff vs the previous COMPLETE scan
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from . import config, tools
from .diff import compute_diffs
from .models import Host, HostSnapshot, RawToolLog, Scan, ScopeAuditLog, Target, utc_now
from .scope import ScopeGuard, ScopePolicy, ScopeValidationError

MEASURED = ("ok", "no_response", "nxdomain")  # probe_status values that count as a real measurement


class PipelineError(Exception):
    pass


def _minimal_domains(domains: Set[str]) -> Set[str]:
    """Drop domains already covered by a parent in the set (sub.example.com when example.com is present)."""
    return {d for d in domains if not any(d != o and d.endswith("." + o) for o in domains)}


class ReconPipeline:
    def __init__(self, session: Session, target: Target, mode: str = "passive_probe",
                 log: Optional[Callable[[str], None]] = None):
        if mode not in config.MODES:
            raise PipelineError(f"Unknown mode '{mode}'. Use one of: {', '.join(config.MODES)}.")
        if mode == "full" and not target.allow_port_scan:
            raise PipelineError(
                f"'full' mode needs port scanning enabled for '{target.name}' "
                "(target must be created with --allow-port-scan, only if the program permits it)."
            )
        self.s, self.target, self.mode = session, target, mode
        self.log = log or (lambda _msg: None)
        self.scan: Optional[Scan] = None

    # ------------------------------------------------------------ helpers
    def _limits(self) -> Dict[str, int]:
        profile = dict(config.PROFILES[self.target.rate_limit_profile or "safe"])
        if self.target.custom_rate_limit:
            profile["httpx_rate"] = int(self.target.custom_rate_limit)
            profile["httpx_threads"] = min(profile["httpx_threads"], int(self.target.custom_rate_limit))
        return profile

    def _raw(self, tool: str, cmd, code: int, out: str, err: str) -> None:
        secrets = list(self.target.custom_headers.values())
        safe_cmd = tools.redact_text(" ".join(tools.redact_command(cmd)), secrets)
        self.s.add(RawToolLog(scan_id=self.scan.id, tool_name=tool, command_executed=safe_cmd,
                              exit_code=code, stdout=tools.redact_text(out, secrets), stderr=tools.redact_text(err, secrets)))

    def _audit(self, host: str, reason: str, rule: Optional[str] = None) -> None:
        self.s.add(ScopeAuditLog(scan_id=self.scan.id, candidate_host=host[:255], reason=reason[:100],
                                 rule_matched=rule[:255] if rule else None))

    # ------------------------------------------------------------ main
    def execute(self) -> Scan:
        try:
            policy = ScopePolicy.build(self.target.in_scope, self.target.out_of_scope)
        except ScopeValidationError as exc:
            raise PipelineError(f"Stored scope rules are invalid, refusing to scan: {exc}")

        need = []
        if any(r.startswith("*.") for r in policy.in_scope):
            need.append("subfinder")
        if self.mode != "passive":
            need.append("httpx")
        if self.mode == "full":
            need.append("nmap")

        try:
            paths = {name: tools.find_tool(name) for name in need}
        except tools.ToolError as exc:
            raise PipelineError(str(exc))

        def get_features(binary: str) -> List[str]:
            if not binary: return []
            help_text = tools._get_help(binary)
            return [f for f in ["private-ips", "-probe", "-cname", "-content-type", "-response-time", "-allow"] if tools._help_has(help_text, f)]

        httpx_feats = get_features(paths.get("httpx", ""))
        self.scan = Scan(target_id=self.target.id, mode=self.mode, status="running",
                         scope_json={"in_scope": list(policy.in_scope), "out_of_scope": list(policy.out_of_scope)},
                         config_json={
                             "scope": {"in_scope": list(policy.in_scope), "out_of_scope": list(policy.out_of_scope)},
                             "profile": self.target.rate_limit_profile,
                             "rates": self._limits(),
                             "allow_port_scan": self.target.allow_port_scan,
                             "allow_shared_ip_scan": getattr(self.target, "allow_shared_ip_scan", False),
                             "header_names": list(self.target.custom_headers.keys()),
                             "versions": {t: tools.get_tool_version(paths[t]) for t in paths},
                             "features": {t: get_features(paths[t]) if t == "httpx" else [] for t in paths},
                             "mode": self.mode,
                             "probe_mode": "probe" if "-probe" in httpx_feats else "unconfirmed",
                             "ip_allowlist": []
                         })
        self.s.add(self.scan)
        self.s.commit()
        try:
            stats = self._run_stages(policy, paths)
            self.scan.status = "completed"
            self.scan.stats_json = stats
            self.scan.complete = stats["complete"]
        except Exception as exc:
            self.s.rollback()
            self.scan.status = "failed"
            self.scan.error_message = str(exc)[:2000]
            self.scan.completed_at = utc_now()
            self.s.commit()
            raise
        self.scan.completed_at = utc_now()
        self.s.commit()
        return self.scan

    def _dns_gate(self, names: List[str], status: Dict[str, str], resolved: Dict[str, List[str]]) -> Tuple[List[str], Set[str]]:
        """Resolve every host ourselves; only hosts resolving exclusively to public IPs may reach httpx."""
        def work(name: str):
            return name, ScopeGuard.resolve_and_validate_host(name, 3.0)

        sendable: List[str] = []
        vetted_ips: Set[str] = set()
        with ThreadPoolExecutor(max_workers=16) as pool:
            for name, (ok, ips, reason) in pool.map(work, names):
                resolved[name] = list(ips)
                if ok:
                    sendable.append(name)
                    vetted_ips.update(ips)
                elif reason.startswith("dns_nxdomain"):
                    status[name] = "nxdomain"
                elif reason.startswith("dns_timeout"):
                    status[name] = "dns_timeout"
                elif reason.startswith("dns_error"):
                    status[name] = "dns_error"
                elif reason.startswith("prohibited_ip"):
                    status[name] = "blocked_ip"
                    self._audit(name, "prohibited_ip", reason)
                else:
                    status[name] = "dns_error"
        self.s.commit()
        return sendable, vetted_ips

    def _run_stages(self, policy: ScopePolicy, paths: Dict[str, str]) -> dict:
        scan, target = self.scan, self.target
        problems: List[str] = []
        secrets = list(self.target.custom_headers.values())

        def problem(text: str) -> None:
            safe_text = tools.redact_text(text, secrets)
            problems.append(safe_text)
            self.log(f"PROBLEM: {safe_text}")

        # 1. seeds: exact rules are candidates as-is, wildcard rules are enumerated
        enum_domains = _minimal_domains({r[2:] for r in policy.in_scope if r.startswith("*.")})
        raw: Set[str] = {r for r in policy.in_scope if not r.startswith("*.")}
        discovery_sources: Dict[str, set] = {r: {"seed"} for r in raw}
        if "subfinder" in paths:
            for domain in sorted(enum_domains):
                self.log(f"subfinder: {domain}")
                try:
                    res = tools.run_subfinder(domain, paths["subfinder"])
                    self._raw("subfinder", res.command, res.exit_code, res.stdout, res.stderr)
                    for h in res.hosts:
                        raw.add(h)
                        discovery_sources.setdefault(h, set()).add("subfinder")
                    if res.exit_code != 0:
                        problem(f"subfinder exited with {res.exit_code} for {domain}")
                except tools.ToolError as exc:
                    problem(f"subfinder: {exc}")
        for domain in sorted(enum_domains):
            self.log(f"crt.sh: {domain}")
            try:
                crt = tools.query_crtsh(domain)
                self._raw("crtsh", [f"crt.sh?q=%.{domain}"], crt.status_code, crt.raw_response, crt.error)
                for h in crt.hosts:
                    raw.add(h)
                    discovery_sources.setdefault(h, set()).add("crtsh")
                if crt.error:
                    problem(f"crt.sh {domain}: {crt.error}")
                    discovery_ok = False
            except tools.ToolError as exc:
                problem(f"crt.sh: {exc}")
                discovery_ok = False
        discovery_ok = not problems
        self.s.commit()

        # 2. Scope Guard: nothing unvetted goes past this point
        vetted: Set[str] = set()
        dropped: Dict[str, str] = {}
        for candidate in sorted(raw):
            decision = policy.decide(candidate)
            if decision.allowed:
                vetted.add(decision.normalized_host)
            elif decision.normalized_host not in dropped:
                dropped[decision.normalized_host] = decision.reason
                self._audit(decision.normalized_host, decision.reason, decision.rule_matched)
        self.s.commit()
        self.log(f"scope guard: {len(vetted)} in scope, {len(dropped)} dropped")

        # 3. host identity records
        existing = {h.hostname: h for h in self.s.query(Host).filter(Host.target_id == target.id)}
        hosts: Dict[str, Host] = {}
        for name in sorted(vetted):
            host = existing.get(name)
            if host is None:
                host = Host(target_id=target.id, hostname=name)
                self.s.add(host)
            else:
                host.last_seen = utc_now()
            hosts[name] = host
        self.s.commit()

        # 4. DNS gate + probe
        status: Dict[str, str] = {n: "not_attempted" for n in hosts}
        resolved: Dict[str, List[str]] = {}
        probes: Dict[str, tools.HttpxProbe] = {}
        probe_run_ok = True
        nmap_run_ok = True
        probing = self.mode in ("passive_probe", "full")
        sendable = []
        vetted_ips = set()
        is_shared = {n: False for n in hosts}
        if probing and vetted:
            sendable, vetted_ips = self._dns_gate(sorted(vetted), status, resolved)
            cfg = dict(self.scan.config_json)
            cfg["ip_allowlist"] = sorted(vetted_ips)
            self.scan.config_json = cfg
            hosts_per_ip = {}
            for ips in resolved.values():
                for ip in ips:
                    hosts_per_ip[ip] = hosts_per_ip.get(ip, 0) + 1
            for name, ips in resolved.items():
                is_shared[name] = any(hosts_per_ip[ip] > 1 for ip in ips)
            if sendable:
                limits = self._limits()
                self.log(f"httpx: probing {len(sendable)} hosts (rate {limits['httpx_rate']}/s)")
                res = tools.run_httpx(sendable, paths["httpx"], limits["httpx_rate"], limits["httpx_threads"],
                                      target.custom_headers, vetted_ips=list(vetted_ips))
                self._raw("httpx", res.command, res.exit_code, res.stdout, res.stderr)
                probe_supported = "-probe" in self.scan.config_json["features"].get("httpx", [])
                if res.exit_code != 0 or not res.probes:
                    # We cannot tell "host is down" from "httpx did not work": measure nothing.
                    probe_run_ok = False
                    problem(f"httpx run failed or returned nothing (exit {res.exit_code}); probe results ignored")
                    for name in sendable:
                        status[name] = "probe_failed"
                else:
                    by_host = {p.hostname: p for p in res.probes}
                    for name in sendable:
                        probe = by_host.get(name)
                        if probe is None:
                            status[name] = "no_result" if probe_supported else "no_response_unconfirmed"
                            continue
                        if probe.failed:
                            status[name] = "no_response"
                            continue
                        bad = [ip for ip in probe.http_ips if not ScopeGuard.evaluate_ip(ip)[0]]
                        if bad:  # httpx resolved the name again and got something different from our check
                            status[name] = "blocked_ip"
                            self._audit(name, "httpx_reported_prohibited_ip", ",".join(bad))
                            continue
                        status[name] = "ok"
                        probes[name] = probe
                num = sum(1 for v in status.values() if v in ("no_result", "dns_error", "dns_timeout"))
                den = len(vetted) - sum(1 for v in status.values() if v == "nxdomain")
                if den > 0 and num / den > 0.05:
                    probe_run_ok = False
                    problem(f"Unmeasured hosts exceed 5% tolerance ({num}/{den})")
                unm_names = [n for n, v in status.items() if v in ("no_result", "dns_error", "dns_timeout")]
                for unm in unm_names[:20]:
                    problem(f"Unmeasured {unm}: {status[unm]}")
                if len(unm_names) > 20:
                    problem(f"... and {len(unm_names) - 20} more unmeasured hosts")
            if vetted and all(status[n] in ("dns_error", "dns_timeout") for n in vetted):
                problem("All DNS lookups failed")
                probe_run_ok = False
        self.s.commit()

        # 5. port scan (full only) on vetted IPs
        ports_by_host: Dict[str, List[dict]] = {}
        port_scan_status: Dict[str, str] = {n: "none" for n in hosts}
        failed_ips: Dict[str, List[str]] = {n: [] for n in hosts}
        scanned_ips: Dict[str, List[str]] = {n: [] for n in hosts}
        scanned: Set[str] = set()
        nmap_ips: Dict[str, List[str]] = {}
        skipped: Dict[str, int] = {}
        if self.mode == "full":
            host_ips: Dict[str, tuple] = {}
            import ipaddress
            for name in sorted(hosts):
                probe = probes.get(name)
                if not probe or not probe.is_live:
                    continue
                auth = ScopeGuard.authorize_active_scan(name, policy, target.allow_port_scan, probe.cdn_waf)
                if auth.allowed:
                    v4_ips = [ip for ip in auth.ips if ipaddress.ip_address(ip).version == 4]
                    if not v4_ips:
                        if auth.ips:
                            skipped["ipv6_only"] = skipped.get("ipv6_only", 0) + 1
                    else:
                        if is_shared.get(name) and not getattr(target, "allow_shared_ip_scan", False):
                            skipped["shared_ip"] = skipped.get("shared_ip", 0) + 1
                        else:
                            host_ips[name] = v4_ips
                            nmap_ips[name] = list(v4_ips)
                            port_scan_status[name] = "complete"
                else:
                    key = auth.reason.split(":")[0]
                    skipped[key] = skipped.get(key, 0) + 1
            unique_ips = sorted({ip for ips in host_ips.values() for ip in ips})
            if unique_ips:
                self.log(f"nmap: scanning {len(unique_ips)} vetted IPs from {len(host_ips)} hosts")
                res = tools.run_nmap(unique_ips, paths["nmap"], self._limits()["nmap_rate"])
                self._raw("nmap", res.command, res.exit_code, res.stdout, res.stderr)
                if not res.ok:
                    problem(f"nmap failed: {res.error}")
                    nmap_run_ok = False
                for name, ips in host_ips.items():
                    scanned.add(name)
                    if not res.ok:
                        port_scan_status[name] = "partial"
                        failed_ips[name] = list(ips)
                        continue
                    missing = [ip for ip in ips if ip not in res.hosts]
                    present = [ip for ip in ips if ip in res.hosts]
                    scanned_ips[name] = present
                    failed_ips[name] = missing
                    port_scan_status[name] = "partial" if missing else "complete"
                    seen: Dict[tuple, dict] = {}
                    for ip in present:
                        for port in res.hosts.get(ip, []):
                            entry = dict(port, ip=ip, shared=hosts_per_ip.get(ip, 1) > 1)
                            seen.setdefault((port["port"], port["protocol"]), entry)
                    ports_by_host[name] = list(seen.values())
                self.s.commit()

        # 6. snapshots
        snapshots: List[HostSnapshot] = []
        for name, host in hosts.items():
            probe = probes.get(name)
            s_ips = nmap_ips.get(name, [])
            snap = HostSnapshot(
                scan_id=scan.id, host_id=host.id, hostname=name, probe_status=status[name],
                probed=status[name] in MEASURED, port_scan_status=port_scan_status.get(name, "none"),
                dns_ips=list(resolved.get(name, [])), http_ips=probe.http_ips if probe else [],
                scan_ips=s_ips, a=probe.a if probe else [], aaaa=probe.aaaa if probe else [],
                cname=probe.cname if probe else [], tech=probe.tech if probe else [],
                discovery_sources=[src for src in ("seed", "subfinder", "crtsh") if src in discovery_sources.get(name, [])],
                content_type=probe.content_type if probe else None, response_time=probe.response_time if probe else None,
                scanned_ips=scanned_ips.get(name, []), failed_ips=failed_ips.get(name, []),
                is_live=bool(probe and probe.is_live), status_code=probe.status_code if probe else None,
                url=probe.url if probe else None, title=probe.title if probe else None,
                web_server=probe.web_server if probe else None,
                content_length=probe.content_length if probe else None,
                redirect_location=probe.redirect_location if probe else None,
                cdn_waf=probe.cdn_waf if probe else None, open_ports=ports_by_host.get(name, []),
            )
            self.s.add(snap)
            snapshots.append(snap)
        self.s.commit()

        # 7. diff vs the previous COMPLETE scan (partial/failed scans are never a baseline)
        previous = (
            self.s.query(Scan)
            .filter(Scan.target_id == target.id, Scan.id != scan.id, Scan.status == "completed", Scan.complete.is_(True))
            .order_by(Scan.started_at.desc()).first()
        )
        change_count, scope_changed = 0, False
        if previous:
            scope_changed = (previous.scope_json or {}) != scan.scope_json
            before = self.s.query(HostSnapshot).filter(HostSnapshot.scan_id == previous.id).all()
            known = {row[0] for row in self.s.query(HostSnapshot.host_id)
                     .join(Scan, HostSnapshot.scan_id == Scan.id)
                     .filter(Scan.target_id == target.id, Scan.id != scan.id)}
            changes = compute_diffs(scan.id, target.id, snapshots, before, known,
                                    detect_removed=discovery_ok and not scope_changed)
            self.s.add_all(changes)
            change_count = len(changes)
        self.s.commit()

        counts: Dict[str, int] = {}
        for value in status.values():
            counts[value] = counts.get(value, 0) + 1
        return {
            "candidates": len(raw), "in_scope": len(vetted), "dropped": len(dropped),
            "live": sum(1 for s in snapshots if s.is_live), "probe_status": counts,
            "hosts_port_scanned": len(scanned), "open_ports": sum(len(s.open_ports or []) for s in snapshots),
            "nmap_skipped": skipped, "changes": change_count, "baseline": previous is None,
            "scope_changed": scope_changed, "complete": discovery_ok and probe_run_ok and nmap_run_ok, "problems": problems[:20],
        }
