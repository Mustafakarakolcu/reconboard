import pytest
from reconboard import tools

def test_help_has():
    assert tools._help_has("usage: httpx -probe -cname", "-probe")
    assert tools._help_has("usage: httpx -probe\t-cname", "-probe")
    assert tools._help_has("usage: httpx -probe\n", "-probe")
    assert not tools._help_has("usage: httpx -allow-list", "-allow")
    assert not tools._help_has("usage: httpx -cname", "-probe")

def test_get_tool_version(monkeypatch):
    calls = []
    def fake_run(cmd, timeout):
        calls.append(cmd)
        if "error_bin" in cmd:
            raise Exception("boom")
        return ("Current Version: v1.6.9\n", "", 0)
    monkeypatch.setattr(tools, "_run", fake_run)
    tools._VERSION_CACHE.clear()

    assert tools.get_tool_version("httpx") == "v1.6.9"
    assert tools.get_tool_version("httpx") == "v1.6.9"
    assert len(calls) == 1
    assert calls[0] == ["httpx", "-version"]

    assert tools.get_tool_version("nmap") == "v1.6.9"
    assert calls[1] == ["nmap", "--version"]
    assert tools.get_tool_version("error_bin") == "unknown"

def test_b3_httpx_no_redirects(monkeypatch):
    calls = {}
    monkeypatch.setattr(tools, "_get_help", lambda x: "-probe -allow -follow-redirects -fr -follow-host-redirects")
    monkeypatch.setattr(tools, "_run", lambda cmd, *a, **kw: (calls.setdefault("cmd", list(cmd)) and "", "", 0))
    tools.run_httpx(["a.com"], binary="httpx")
    assert "-follow-redirects" not in calls["cmd"]
    assert "-fr" not in calls["cmd"]
    assert "-follow-host-redirects" not in calls["cmd"]

def test_nmap_ok_status(monkeypatch):
    monkeypatch.setattr(tools.ScopeGuard, "evaluate_ip", lambda ip: (True, ""))
    def run_mock(out, code):
        monkeypatch.setattr(tools, "_run", lambda *a, **kw: (out, "", code))
        return tools.run_nmap(["1.1.1.1"])

    valid_xml = '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="1.1.1.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'
    res1 = run_mock(valid_xml, 0)
    assert res1.ok is True and "1.1.1.1" in res1.hosts

    res2 = run_mock(valid_xml, 1)
    assert res2.ok is True

    assert run_mock("", 0).ok is False
    assert run_mock("", -1).error == "timeout"

    broken_xml = '<?xml version="1.0"?><nmaprun><host><status state="up"'
    assert run_mock(broken_xml, 0).error == "corrupt xml"

def test_b4_parse_httpx_odd_json_more():
    odd = ['{"input": [], "host": 1}', '{"input": {}, "host": null}', '{"input": true, "host": false}']
    for line in odd:
        probe = tools.parse_httpx_line(line)
        assert probe is None or isinstance(probe, tools.HttpxProbe)
    line2 = '{"input": "a.com", "host": [1,2], "host_ip": "1.1.1.1", "a": {"x": 1}, "cname": 42, "tech": [true, 1, ["x"]]}'
    probe2 = tools.parse_httpx_line(line2)
    assert probe2 is not None
    assert probe2.hostname == "a.com"
    assert "1.1.1.1" in probe2.http_ips

    line3 = '{"input": "b.com", "host": "b.com"}'
    probe3 = tools.parse_httpx_line(line3)
    assert not any("b.com" == ip for ip in probe3.http_ips)
