# ReconBoard

Scope-guarded recon pipeline for **authorized** bug bounty work.
`subfinder + crt.sh` (passive) -> Scope Guard -> `httpx` (probe) -> optional `nmap` (vetted IPs only) -> SQLite -> diff between scans.

> Use only against targets you are explicitly authorized to test, and follow each program's rules
> (rate limits, required headers, whether port scanning is allowed).

## Install (Kali)

```bash
sudo apt install subfinder httpx-toolkit nmap      # httpx-toolkit = ProjectDiscovery httpx on Kali
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
reconboard doctor                                  # checks the three tools
python -m pytest                                   # 93 tests, no network needed
```

## Usage

```bash
reconboard target add clear -i "*.clearme.com" -o "admin.clearme.com" -H "X-HackerOne-Research: yourname"
reconboard scan clear                     # passive: sends nothing to the target (default)
reconboard scan clear -m passive_probe    # + httpx probing (redirects never followed)
reconboard scan clear -m full             # + nmap; needs --allow-port-scan
reconboard target update clear --allow-shared-ip-scan  # permit scanning shared IPs
reconboard scans clear                    # list recent scans
reconboard scan-show <scan-id>            # show details and stats
reconboard hosts clear --live
reconboard hosts clear --source subfinder # filter by discovery source
reconboard changes clear                  # diff vs previous scan (first scan is the baseline)
reconboard dropped clear                  # what the Scope Guard rejected, and why
reconboard export clear -f md -o clear.md # md | json | csv
```

Data lives in `~/.reconboard/reconboard.db` (override with `RECONBOARD_DB`).
Tool paths can be overridden with `SUBFINDER_PATH`, `HTTPX_PATH`, `NMAP_PATH`.

## Scope rules

* `*.example.com` in scope = subdomains only (add `example.com` explicitly for the apex).
* `*.example.com` out of scope = subdomains and the apex. Out-of-scope always wins.
* Invalid rules are rejected, never ignored. IP/CIDR rules and wildcards on public suffixes (`*.co.uk`, `*.github.io`) are not supported.

## Safety design (and its limits)

* No shell; arguments as lists; targets to httpx via stdin; domains re-validated right before execution.
* **DNS/IP gate:** Every in-scope host is resolved by ReconBoard first. Hosts resolving exclusively to private/non-public IPs never reach httpx. `-exclude private-ips` is added when supported. ReconBoard passes a global allowlist of all vetted IPs via `-allow` (when supported) to httpx; this is a global allowlist, not a per-host pin.
* **httpx:** Probes the default web ports (80/443) only.
* **nmap:** Scans only live, authorized, non-shared, IPv4 hosts that ReconBoard resolved and vetted itself. Skip reasons are counted in stats.
* Text from remote servers (titles, banners) is sanitised, rendered as inline code in Markdown, and CSV cells are protected against
  formula injection. nmap XML is parsed with `defusedxml`.
* Header values passed with `-H` are redacted from raw tool logs and problem lines, but they ARE stored in the database (`~/.reconboard/`, mode 700/600). The CLI does NOT hide them.

## How diffs stay honest

* Only **complete** scans (all discovery sources and the httpx run succeeded) are used as a baseline. A broken run is reported
  with its problems and ignored for comparison.
* Probe results count only if httpx really ran. Measured outcomes are: ok, no_response, nxdomain. Unmeasured outcomes are: not_attempted, dns_error, dns_timeout, blocked_ip, probe_failed, no_result, no_response_unconfirmed. Unmeasured tolerance: a scan is marked incomplete if more than 5% of the hosts sent to the probe stage (excluding nxdomain hosts) end up unmeasured.
* `not_seen` (host missing from passive sources) is a single-scan hint. It is only reported when discovery was complete in both scans and the scope rules did not change.
* `reappeared` = seen in an older scan, missing in the previous one. Every scan stores the scope rules that were in force.

## Known limitations

* httpx flags `-probe`, `-cname`, `-content-type`, `-response-time` and the interplay of `-allow` with `-exclude private-ips` are UNVERIFIED. `probe_mode` is recorded as "probe" or "unconfirmed".
* Passive sources depend on your subfinder API keys; missing keys mean fewer results.
* No migrations: schema changed in v0.1.2 (version 3). Move your old `~/.reconboard/reconboard.db` away.
* Not included yet: notifications (Discord/Telegram), scheduling (use `cron`), web UI, IP/CIDR scope, IPv6 port scanning.
