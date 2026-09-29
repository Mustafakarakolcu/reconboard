from reconboard.export import to_csv, to_markdown, to_json
import json
from reconboard.models import Target, HostSnapshot, Scan

def test_export_v012_fields():
    t = Target(name="t", in_scope=["a"])
    s = Scan(id="123", mode="full", complete=True, config_json={"features": {"httpx": ["-probe"]}})
    snap = HostSnapshot(hostname="a.com", probe_status="ok", dns_ips=["1.1.1.1"], port_scan_status="complete", cname=["x.com"], discovery_sources=["seed"], scanned_ips=["1.1.1.1"], failed_ips=[])
    csv_out = to_csv([snap])
    assert "1.1.1.1" in csv_out

    md_out = to_markdown(t, [snap], scan=s)
    assert "1.1.1.1" not in md_out  # md doesn't render IPs
    assert "httpx:-probe" in md_out

    j_out = json.loads(to_json(t, [snap], scan=s))
    assert j_out["scan"]["config"] == s.config_json
    assert j_out["hosts"][0]["cname"] == ["x.com"]
    assert j_out["hosts"][0]["discovery_sources"] == ["seed"]
    assert j_out["hosts"][0]["scanned_ips"] == ["1.1.1.1"]
    assert j_out["hosts"][0]["failed_ips"] == []

    snap.title = "=CMD()"
    assert "'=CMD()" in to_csv([snap])

    snap.title = "http://evil"
    md_out_links = to_markdown(t, [snap], scan=s)
    assert "`http://evil`" in md_out_links
