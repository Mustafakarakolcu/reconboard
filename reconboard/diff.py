"""Change detection between two scans of the same target.

Rules that keep the output honest:
* A field is only compared when BOTH snapshots really measured it (`probed` / `port_scan_status`).
* `not_seen` is only produced when discovery was complete in both scans and the scope did not change
  (passive sources are noisy: a host missing once is not proof that it was removed).
* A host that was seen in some earlier scan but not in the previous one is `reappeared`, not `new_subdomain`.
"""
from __future__ import annotations

from typing import AbstractSet, Dict, List, Sequence

from .models import ChangeLog, HostSnapshot


def _ports(snapshot: HostSnapshot) -> Dict[tuple, dict]:
    return {(p["port"], p.get("protocol", "tcp")): p for p in (snapshot.open_ports or [])}


def compute_diffs(
    scan_id: str, target_id: str, current: Sequence[HostSnapshot], previous: Sequence[HostSnapshot],
    known_host_ids: AbstractSet[str] = frozenset(), detect_removed: bool = False,
) -> List[ChangeLog]:
    prev_map = {s.hostname: s for s in previous}
    curr_names = {s.hostname for s in current}
    changes: List[ChangeLog] = []

    def add(snap: HostSnapshot, kind: str, details: dict) -> None:
        changes.append(ChangeLog(
            scan_id=scan_id, target_id=target_id, host_id=snap.host_id,
            hostname=snap.hostname, change_type=kind, details=details,
        ))

    for curr in current:
        prev = prev_map.get(curr.hostname)
        if prev is None:
            kind = "reappeared" if curr.host_id in known_host_ids else "new_subdomain"
            add(curr, kind, {"is_live": curr.is_live, "title": curr.title})
            continue

        if curr.probed and prev.probed:
            if curr.is_live and not prev.is_live:
                add(curr, "went_live", {"status_code": curr.status_code, "title": curr.title})
            elif prev.is_live and not curr.is_live:
                add(curr, "went_down", {"previous_status_code": prev.status_code, "note": "no response from httpx"})
            elif curr.is_live and curr.status_code != prev.status_code:
                add(curr, "status_changed", {"old": prev.status_code, "new": curr.status_code})

            old_tech, new_tech = set(prev.tech or []), set(curr.tech or [])
            if old_tech != new_tech:
                add(curr, "tech_changed", {"added": sorted(new_tech - old_tech), "removed": sorted(old_tech - new_tech)})

            old_ips, new_ips = set(prev.dns_ips or []), set(curr.dns_ips or [])
            if old_ips and new_ips and old_ips.isdisjoint(new_ips) and not curr.cdn_waf and not prev.cdn_waf:
                add(curr, "ip_changed", {"added": sorted(new_ips - old_ips), "removed": sorted(old_ips - new_ips)})

        if curr.port_scan_status == "complete" and prev.port_scan_status == "complete":
            now, before = _ports(curr), _ports(prev)
            for key, data in now.items():
                if key not in before:
                    add(curr, "new_port", data)
            for key, data in before.items():
                if key not in now:
                    add(curr, "closed_port", data)

    if detect_removed:
        for prev in previous:
            if prev.hostname not in curr_names:
                add(prev, "not_seen", {"last_status_code": prev.status_code, "was_live": prev.is_live})
    return changes
