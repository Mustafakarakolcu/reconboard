from reconboard import tools

def make_env(monkeypatch, resolve=None, probes=None, help_text="", nmap=None, subfinder_hosts=(), crt_hosts=(), crt_error="", httpx_stdout="", httpx_stderr="", httpx_command=None, httpx_exit=0):
    calls = {"httpx": [], "nmap": [], "resolve": []}

    def fake_resolve(host, timeout):
        calls["resolve"].append(host)
        if resolve and host in resolve:
            return resolve[host]
        return True, ["93.184.216.34"], "safe"

    monkeypatch.setattr(tools.ScopeGuard, "resolve_and_validate_host", fake_resolve)
    monkeypatch.setattr(tools, "find_tool", lambda name: f"/fake/{name}")
    monkeypatch.setattr(tools, "get_tool_version", lambda name: "1.0")
    monkeypatch.setattr(tools, "_get_help", lambda name: help_text)

    monkeypatch.setattr(tools, "run_subfinder", lambda d, b, t=300: tools.SubfinderResult(list(subfinder_hosts), "", "", 0, []))
    monkeypatch.setattr(tools, "query_crtsh", lambda d, t=30, r=2: tools.CrtshResult(list(crt_hosts), "", 200, crt_error))

    def fake_httpx(hosts, binary, rate_limit, threads, custom_headers, timeout_seconds=10, vetted_ips=()):
        calls["httpx"].append({"hosts": hosts, "vetted_ips": vetted_ips})
        res_probes = [probes[h] for h in hosts if h in probes] if probes is not None else [tools.HttpxProbe(hostname=h, is_live=True, status_code=200, http_ips=["93.184.216.34"]) for h in hosts]
        return tools.HttpxResult(res_probes, httpx_stdout, httpx_stderr, httpx_exit, httpx_command or [])

    monkeypatch.setattr(tools, "run_httpx", fake_httpx)

    def fake_nmap(ips, binary, max_rate, top_ports=1000):
        calls["nmap"].append({"ips": ips})
        if nmap is not None: return tools.NmapResult(hosts=nmap.get("hosts", {}), stdout="", stderr="", exit_code=nmap.get("code", 0), command=[], ok=nmap.get("ok", True), error=nmap.get("error"))
        return tools.NmapResult({ip: [{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}] for ip in ips}, "", "", 0, [], True, None)

    monkeypatch.setattr(tools, "run_nmap", fake_nmap)
    return calls
