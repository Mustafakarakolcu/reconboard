from reconboard.diff import compute_diffs
from reconboard.models import HostSnapshot


def snap(host, probed=True, port_scan_status="none", live=True, status=200, tech=(), ports=()):
    return HostSnapshot(scan_id="s", host_id="h-" + host, hostname=host, probed=probed, port_scan_status=port_scan_status,
                        is_live=live, status_code=status if live else None, tech=list(tech),
                        open_ports=[{"port": p, "protocol": "tcp", "service": "x"} for p in ports])


def kinds(changes):
    return sorted((c.hostname, c.change_type) for c in changes)


def test_new_subdomain_and_flips():
    prev = [snap("a.x.com"), snap("b.x.com", live=False)]
    curr = [snap("a.x.com", live=False), snap("b.x.com"), snap("c.x.com")]
    assert kinds(compute_diffs("n", "t", curr, prev)) == [
        ("a.x.com", "went_down"), ("b.x.com", "went_live"), ("c.x.com", "new_subdomain")]


def test_tech_and_status_changes():
    out = compute_diffs("n", "t", [snap("a.x.com", status=500, tech=["Nginx", "PHP"])], [snap("a.x.com", tech=["Nginx"])])
    assert kinds(out) == [("a.x.com", "status_changed"), ("a.x.com", "tech_changed")]


def test_passive_scan_after_full_scan_creates_no_fake_events():
    prev = [snap("a.x.com", port_scan_status="complete", ports=[22, 80], tech=["Nginx"])]
    curr = [snap("a.x.com", probed=False, live=False, tech=[])]
    assert compute_diffs("n", "t", curr, prev) == []


def test_ports_only_compared_when_both_complete():
    prev = [snap("a.x.com", port_scan_status="complete", ports=[22, 80])]
    curr = [snap("a.x.com", port_scan_status="complete", ports=[80, 443])]
    assert kinds(compute_diffs("n", "t", curr, prev)) == [("a.x.com", "closed_port"), ("a.x.com", "new_port")]
    curr_skipped = [snap("a.x.com", port_scan_status="none", ports=[])]  # e.g. host moved behind a CDN, nmap skipped
    assert compute_diffs("n", "t", curr_skipped, prev) == []


def test_removed_only_when_asked_and_ip_change_ignored_behind_cdn():
    prev = [snap("a.x.com"), snap("gone.x.com")]
    assert compute_diffs("n", "t", [snap("a.x.com")], prev) == []
    out = compute_diffs("n", "t", [snap("a.x.com")], prev, detect_removed=True)
    assert kinds(out) == [("gone.x.com", "not_seen")]
    a, b = snap("c.x.com"), snap("c.x.com")
    a.dns_ips, b.dns_ips = ["1.1.1.1"], ["2.2.2.2"]
    assert kinds(compute_diffs("n", "t", [b], [a])) == [("c.x.com", "ip_changed")]
    a.cdn_waf = b.cdn_waf = "cloudflare"
    assert compute_diffs("n", "t", [b], [a]) == []
