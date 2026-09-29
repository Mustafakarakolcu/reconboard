import socket
import time

import pytest

from reconboard.scope import ScopeGuard, ScopePolicy, ScopeValidationError


def test_normalize_hostname():
    n = ScopeGuard.normalize_hostname
    assert n("API.EXAMPLE.COM") == "api.example.com"
    assert n("api.example.com.") == "api.example.com"
    assert n("*.corp.example.com") == "corp.example.com"
    assert n("*.*.deep.example.com") == "deep.example.com"
    assert n("https://admin.example.com/login?x=1") == "admin.example.com"
    assert n("portal.example.com:8443") == "portal.example.com"
    assert n("münchen.de") == "xn--mnchen-3ya.de"
    assert n("a..b.com") == ""
    assert n("") == ""


@pytest.mark.parametrize("bad", [
    "a.-b.com", "a.b-.com", "-a.b.com", "localhost", "example.123", "api.example.com;cat /etc/passwd",
    "api.example.com|id", "api.example.com\n127.0.0.1", "api example com", "", "a" * 64 + ".com",
    "a" * 254 + ".com", "user@example.com", "1.2.3.4", "example.com\n",
])
def test_invalid_hostnames(bad):
    assert not ScopeGuard.is_valid_hostname(bad)


def test_exact_rule_matches_only_itself():
    d = ScopeGuard.is_in_scope("example.com", ["example.com"], [])
    assert d.allowed and d.reason == "in_scope_match"
    d = ScopeGuard.is_in_scope("sub.example.com", ["example.com"], [])
    assert not d.allowed and d.reason == "not_in_scope"


def test_in_scope_wildcard_excludes_apex():
    assert not ScopeGuard.is_in_scope("example.com", ["*.example.com"], []).allowed
    assert ScopeGuard.is_in_scope("api.example.com", ["*.example.com"], []).allowed
    assert ScopeGuard.is_in_scope("a.b.c.example.com", ["*.example.com"], []).allowed
    assert ScopeGuard.is_in_scope("example.com", ["*.example.com", "example.com"], []).allowed


def test_out_of_scope_wildcard_covers_apex_and_wins():
    d = ScopeGuard.is_in_scope("blocked.com", ["*.blocked.com", "blocked.com"], ["*.blocked.com"])
    assert not d.allowed and d.reason == "out_of_scope_match"
    d = ScopeGuard.is_in_scope("admin.example.com", ["*.example.com"], ["admin.example.com"])
    assert not d.allowed and d.rule_matched == "admin.example.com"
    d = ScopeGuard.is_in_scope("x.corp.example.com", ["*.example.com"], ["*.corp.example.com"])
    assert not d.allowed and d.rule_matched == "*.corp.example.com"
    assert ScopeGuard.is_in_scope("dev.example.com", ["*.example.com"], ["admin.example.com"]).allowed


@pytest.mark.parametrize("host", ["example.com.evil.com", "evil-example.com", "notexample.com", "xexample.com"])
def test_domain_boundary_confusion(host):
    assert not ScopeGuard.is_in_scope(host, ["*.example.com", "example.com"], []).allowed


def test_unnormalized_rules_are_normalized_not_ignored():
    d = ScopeGuard.is_in_scope("admin.example.com", ["*.example.com"], ["Admin.Example.COM."])
    assert not d.allowed and d.reason == "out_of_scope_match"


@pytest.mark.parametrize("rule,message", [
    ("192.168.1.1", "IP/CIDR"),
    ("10.0.0.0/24", "IP/CIDR"),
    ("admin.*.example.com", "Unsupported wildcard"),
    ("*example.com", "Unsupported wildcard"),
    ("*.a.*.example.com", "Unsupported wildcard"),
    ("*.co.uk", "public suffix"),
    ("*.github.io", "public suffix"),
    ("*.herokuapp.com", "public suffix"),
    ("*.com", "public suffix"),
    ("https://example.com/path", "forbidden"),
    ("example.com:8443", "forbidden"),
    ("", "non-empty"),
])
def test_unsupported_rules_fail_closed(rule, message):
    with pytest.raises(ScopeValidationError, match=message):
        ScopeGuard.validate_and_normalize_pattern(rule)
    with pytest.raises(ScopeValidationError):
        ScopeGuard.is_in_scope("api.example.com", ["*.example.com"], [rule])


def test_private_suffix_subdomain_allowed():
    assert ScopeGuard.validate_and_normalize_pattern("*.myorg.github.io") == "*.myorg.github.io"
    assert ScopeGuard.validate_and_normalize_pattern("*.Example.co.uk") == "*.example.co.uk"


@pytest.mark.parametrize("ip,expected", [
    ("100.64.0.1", (False, "non_global_ip")),
    ("::1", (False, "loopback_ip")),
    ("::ffff:127.0.0.1", (False, "loopback_ip")),
    ("169.254.169.254", (False, "cloud_metadata")),
    ("10.0.0.1", (False, "private_ip_rfc1918")),
    ("172.16.0.1", (False, "private_ip_rfc1918")),
    ("192.168.1.1", (False, "private_ip_rfc1918")),
    ("224.0.0.1", (False, "multicast_ip")),
    ("0.0.0.0", (False, "unspecified_ip")),
    ("not-an-ip", (False, "invalid_ip_format")),
    ("1.1.1.1", (True, "public_ip")),
    ("93.184.216.34", (True, "public_ip")),
])
def test_evaluate_ip(ip, expected):
    assert ScopeGuard.evaluate_ip(ip) == expected


def test_headers():
    ok = {"X-HackerOne-Research": "hunter"}
    assert ScopeGuard.validate_custom_headers(ok) == ok
    for bad in ("Host", "host", "Content-Length", "Transfer-Encoding", "Connection", "Upgrade", "TE", "Proxy-Authorization"):
        with pytest.raises(ScopeValidationError, match="restricted"):
            ScopeGuard.validate_custom_headers({bad: "x"})
    with pytest.raises(ScopeValidationError, match="control"):
        ScopeGuard.validate_custom_headers({"X-A": "v\r\nEvil: 1"})
    with pytest.raises(ScopeValidationError, match="control"):
        ScopeGuard.validate_custom_headers({"X-A": "v\r\n"})  # must not be silently stripped
    with pytest.raises(ScopeValidationError, match="Invalid header name"):
        ScopeGuard.validate_custom_headers({"Bad Name": "x"})


def test_redirects_relative_and_absolute():
    inn = ["*.example.com", "example.com"]
    assert ScopeGuard.evaluate_redirect("https://example.com/login", "/dashboard", inn, []).allowed
    d = ScopeGuard.evaluate_redirect("https://example.com/login", "//evil.com/x", inn, [])
    assert not d.allowed and d.reason == "not_in_scope"
    d = ScopeGuard.evaluate_redirect("https://a.example.com/", "https://auth.example.com/o", inn, ["auth.example.com"])
    assert not d.allowed and d.reason == "out_of_scope_match"


def _fake_dns(ips):
    return lambda host, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


def test_resolve_rejects_private_and_accepts_public(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns(["93.184.216.34"]))
    assert ScopeGuard.resolve_and_validate_host("a.example.com") == (True, ["93.184.216.34"], "safe")
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns(["93.184.216.34", "10.0.0.5"]))
    ok, ips, why = ScopeGuard.resolve_and_validate_host("a.example.com")
    assert not ok and "prohibited_ip:10.0.0.5" in why


def test_resolve_nxdomain(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    ok, _, why = ScopeGuard.resolve_and_validate_host("a.example.com")
    assert not ok and why.startswith("dns_error")


def test_resolve_timeout_is_really_enforced(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: time.sleep(2) or [])
    start = time.monotonic()
    ok, _, why = ScopeGuard.resolve_and_validate_host("a.example.com", timeout=0.3)
    assert time.monotonic() - start < 1.2
    assert not ok and why.startswith("dns_timeout")


def test_authorize_active_scan(monkeypatch):
    policy = ScopePolicy.build(["*.example.com"], ["admin.example.com"])
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns(["93.184.216.34"]))
    auth = ScopeGuard.authorize_active_scan("app.example.com", policy, True)
    assert auth.allowed and auth.ips == ("93.184.216.34",)
    assert ScopeGuard.authorize_active_scan("app.example.com", policy, False).reason == "port_scan_not_allowed_for_target"
    assert ScopeGuard.authorize_active_scan("admin.example.com", policy, True).reason == "scope:out_of_scope_match"
    assert ScopeGuard.authorize_active_scan("app.example.com", policy, True, cdn_waf="cloudflare").reason.startswith("cdn_waf_detected")
    assert ScopeGuard.authorize_active_scan("app.example.com", policy, True, cdn_waf="unknownedge").reason.startswith("cdn_waf_detected")
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns(["127.0.0.1"]))
    assert ScopeGuard.authorize_active_scan("app.example.com", policy, True).reason.startswith("prohibited_ip")
