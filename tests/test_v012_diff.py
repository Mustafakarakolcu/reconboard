from reconboard.diff import compute_diffs
from reconboard.models import HostSnapshot

def snap(host, probed=True, port_scan_status="none", live=True, status=200, cdn=None, dns_ips=None):
    return HostSnapshot(scan_id="s", host_id="h-" + host, hostname=host, probed=probed,
                        port_scan_status=port_scan_status, is_live=live, status_code=status if live else None,
                        cdn_waf=cdn, dns_ips=dns_ips or [])

def kinds(changes):
    return sorted((c.hostname, c.change_type) for c in changes)

def test_ip_changed_rules():
    a1 = snap("a.com", dns_ips=["1.1.1.1"])
    a2 = snap("a.com", dns_ips=["2.2.2.2"])
    assert kinds(compute_diffs("s", "t", [a2], [a1])) == [("a.com", "ip_changed")]

    b1 = snap("b.com", dns_ips=["1.1.1.1"])
    b2 = snap("b.com", dns_ips=["1.1.1.1", "2.2.2.2"])
    assert kinds(compute_diffs("s", "t", [b2], [b1])) == []

    c1 = snap("c.com", dns_ips=["1.1.1.1"], cdn="cloudflare")
    c2 = snap("c.com", dns_ips=["2.2.2.2"], cdn="cloudflare")
    assert kinds(compute_diffs("s", "t", [c2], [c1])) == []

def test_unconfirmed_no_went_down():
    a1 = snap("a.com", live=True)
    a2 = snap("a.com", live=False, probed=False)
    assert kinds(compute_diffs("s", "t", [a2], [a1])) == []

def test_not_seen_basic():
    changes = compute_diffs("s", "t", [], [snap("a.com")], detect_removed=True)
    assert len(changes) == 1
    assert changes[0].change_type == "not_seen"
    assert "consecutive_scans_missing" not in changes[0].details
    assert compute_diffs("s", "t", [], [snap("a.com")], detect_removed=False) == []
