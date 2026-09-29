import pytest

from reconboard import tools
from reconboard.scope import ScopeValidationError


def test_subfinder_parser_json_and_plain():
    text = (
        '{"host":"api.example.com","input":"example.com","source":["x"]}\n'
        '{"host":"DEV.example.com"}\n{"host":"api.example.com"}\n'
        "plain.example.com\n\nnot json {\n"
    )
    assert tools.parse_subfinder_output(text) == ["api.example.com", "dev.example.com", "not json {", "plain.example.com"]


def test_crtsh_parser():
    records = [
        {"name_value": "a.example.com\n*.example.com", "common_name": "a.example.com"},
        {"name_value": "b.example.com"}, "junk", {"name_value": None},
    ]
    assert tools.parse_crtsh_records(records) == ["*.example.com", "a.example.com", "b.example.com"]
    assert tools.parse_crtsh_records({"error": "x"}) == []


def test_httpx_parser_old_and_new_field_names():
    line = ('{"input":"Admin.ClearMe.com","url":"https://admin.clearme.com","status_code":200,"title":"Login\\u001b[31m Portal",'
            '"webserver":"nginx","content_length":1420,"tech":["React","Nginx"],"host_ip":"104.18.2.1",'
            '"a":["104.18.2.1","104.18.2.2"],"cname":["cdn.x.com"],"cdn_name":"cloudflare","location":"https://x.example.com/"}')
    p = tools.parse_httpx_line(line)
    assert p.hostname == "admin.clearme.com" and p.is_live and p.status_code == 200
    assert "\x1b" not in p.title
    assert p.http_ips == ["104.18.2.1"]
    assert p.a == ["104.18.2.1", "104.18.2.2"]
    assert p.cname == ["cdn.x.com"]
    assert p.tech == ["React", "Nginx"]
    assert p.cdn_waf == "cloudflare" and p.redirect_location == "https://x.example.com/"
    new = tools.parse_httpx_line('{"host":"a.example.com","host_ip":"93.184.216.34","status_code":403,"cdn":true}')
    assert new.http_ips == ["93.184.216.34"] and new.cdn_waf == "cdn"


def test_httpx_parser_rejects_garbage():
    assert tools.parse_httpx_line("") is None
    assert tools.parse_httpx_line("plain text") is None
    assert tools.parse_httpx_line("[1,2]") is None
    assert tools.parse_httpx_line('{"status_code":200}') is None
    failed = tools.parse_httpx_line('{"input":"a.example.com","failed":true}')
    assert failed is not None and not failed.is_live and failed.failed is True
    ok = tools.parse_httpx_line('{"input":"a.example.com","status_code":200}')
    assert ok is not None and ok.is_live is True and ok.failed is False


NMAP_XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="93.184.216.34" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.41"/></port>
<port protocol="tcp" portid="8080"><state state="closed"/></port></ports></host>
<host><status state="up"/><address addr="93.184.216.35" addrtype="ipv4"/></host>
<host><status state="down"/><address addr="93.184.216.36" addrtype="ipv4"/></host></nmaprun>"""


def test_nmap_parser():
    res = tools.parse_nmap_xml(NMAP_XML)
    assert set(res) == {"93.184.216.34", "93.184.216.35"}
    assert res["93.184.216.35"] == []
    assert res["93.184.216.34"] == [{"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache httpd 2.4.41"}]


def test_nmap_parser_corrupt_and_hostile_xml():
    assert tools.parse_nmap_xml("") == {}
    assert tools.parse_nmap_xml("<broken") == {}
    bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><nmaprun>&b;</nmaprun>'
    assert tools.parse_nmap_xml(bomb) == {}


def test_nmap_refuses_non_public_or_ipv6():
    for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "2606:4700::1"):
        with pytest.raises(tools.ToolError):
            tools.run_nmap([ip], binary="/bin/true")


def test_tools_refuse_bad_domains():
    for fn in (tools.run_subfinder, tools.query_crtsh):
        with pytest.raises(tools.ToolError):
            fn("example.com; id")
        with pytest.raises(tools.ToolError):
            fn("-oX")
    with pytest.raises(tools.ToolError):
        tools.run_httpx(["ok.example.com", "$(id).example.com"], binary="/bin/true")
    with pytest.raises(ScopeValidationError):
        tools.run_httpx(["ok.example.com"], binary="/bin/true", custom_headers={"Host": "evil"})


def test_clean_text():
    assert tools.clean_text("a\x1b[31mb\nc") == "a [31mb c"
    assert len(tools.clean_text("x" * 1000)) == 300
    assert tools.clean_text(None) is None and tools.clean_text("   ") is None


def test_redact_command_hides_every_header_value():
    cmd = ["httpx", "-json", "-H", "Authorization: Bearer abc", "-H", "Cookie: s=1", "-silent"]
    assert tools.redact_command(cmd) == ["httpx", "-json", "-H", "Authorization: [REDACTED]", "-H", "Cookie: [REDACTED]", "-silent"]


def test_httpx_status_zero_is_not_live():
    assert not tools.parse_httpx_line('{"input":"a.example.com","status_code":0}').is_live


def test_crtsh_oversized_response_is_rejected(monkeypatch):
    import io
    class Resp(io.BytesIO):
        def getcode(self): return 200
        def __enter__(self): return self
        def __exit__(self, *a): pass
    monkeypatch.setattr(tools, "CRTSH_MAX_BYTES", 10)
    monkeypatch.setattr(tools.urllib.request, "urlopen", lambda *a, **k: Resp(b"[" + b"1," * 50 + b"1]"))
    res = tools.query_crtsh("example.com", retries=0)
    assert res.hosts == [] and "larger than" in res.error


def test_httpx_feature_detection(monkeypatch):
    seen = {}
    monkeypatch.setattr(tools, "_run", lambda cmd, timeout, stdin=None: seen.setdefault("cmd", list(cmd)) and ("", "", 0))
    monkeypatch.setattr(tools, "_get_help", lambda b: "-exclude private-ips -probe -cname -content-type -response-time -allow ")
    tools.run_httpx(["a.example.com"], binary="httpx", vetted_ips=["1.1.1.1"])
    cmd = seen["cmd"]
    assert "-exclude" in cmd and "private-ips" in cmd
    assert "-probe" in cmd
    assert "-cname" in cmd
    assert "-content-type" in cmd
    assert "-response-time" in cmd
    assert "-allow" in cmd and "1.1.1.1" in cmd

    seen.clear()
    monkeypatch.setattr(tools, "_get_help", lambda b: "")
    tools.run_httpx(["a.example.com"], binary="httpx")
    assert "-exclude" not in seen.get("cmd", [])
    assert "-probe" not in seen.get("cmd", [])
    assert "-allow" not in seen.get("cmd", [])

def test_redact_text():
    text = "Cmd:\nAuthorization: Bearer abc123def\nCookie: secret123\nHeader: short\ncustom: val123"
    res = tools.redact_text(text, ["val123", "short"])
    assert "abc123def" not in res
    assert "secret123" not in res
    assert "Authorization: [REDACTED]" in res
    assert "Cookie: [REDACTED]" in res
    assert "custom: [REDACTED]" in res
    assert "short" in res
    assert tools.redact_text("random mysecrettoken", ["mysecrettoken"]) == "random [REDACTED]"

def test_as_list():
    assert tools.as_list(["a", "b", ""]) == ["a", "b"]
    assert tools.as_list("a") == ["a"]
    assert tools.as_list({"a": 1}) == []
    assert tools.as_list(None) == []

def test_httpx_allow_temp_file(monkeypatch):
    seen = {}
    import os
    def fake_run(cmd, timeout, stdin=None):
        seen["cmd"] = list(cmd)
        idx = cmd.index("-allow")
        path = cmd[idx+1]
        seen["path"] = path
        assert (os.stat(path).st_mode & 0o777) == 0o600
        with open(path, "r") as f:
            seen["file_content"] = f.read()
        raise tools.ToolError("boom")
    monkeypatch.setattr(tools, "_run", fake_run)
    monkeypatch.setattr(tools, "_get_help", lambda b: "-allow ")
    vetted = [f"1.1.1.{i}" for i in range(60)]
    with pytest.raises(tools.ToolError):
        tools.run_httpx(["a.example.com"], binary="httpx", vetted_ips=vetted)
    assert len(seen["file_content"].strip().split("\n")) == 60
    assert not os.path.exists(seen["path"])
