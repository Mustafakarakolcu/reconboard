"""Wrappers and parsers for subfinder, crt.sh, httpx (ProjectDiscovery) and nmap.

Safety rules: no shell, argument lists only, targets via stdin where possible, hostnames/IPs
re-validated right before execution, and every string that came from a remote server is
sanitised (control characters removed, length capped) before it is stored or printed.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from defusedxml import ElementTree as SafeET

from .scope import ScopeGuard

INSTALL_HINTS = {
    "subfinder": "subfinder not found. Install: 'sudo apt install subfinder' or 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'",
    "httpx": "ProjectDiscovery httpx not found (on Kali it is 'httpx-toolkit'). Install: 'sudo apt install httpx-toolkit' or 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'",
    "nmap": "nmap not found. Install: 'sudo apt install nmap'",
}


class ToolError(Exception):
    """A tool is missing, misbehaving, or was given input that failed validation."""


_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SECRET_REGEX = re.compile(r"(?i)(Authorization|Cookie|Proxy-Authorization|X-API-Key)\s*[:=]\s*[^\r\n]+")

def redact_text(text: Optional[str], header_values: Sequence[str] = ()) -> Optional[str]:
    if not text:
        return text
    text = _SECRET_REGEX.sub(r"\1: [REDACTED]", text)
    for val in header_values:
        if val and len(val) >= 6:
            text = text.replace(val, "[REDACTED]")
    return text


def clean_text(value, limit: int = 300) -> Optional[str]:
    """Strip control chars (incl. ANSI escapes) and cap length. Used on all remote-supplied text."""
    if not isinstance(value, str):
        return None
    return _CTRL.sub(" ", value).strip()[:limit] or None


def redact_command(cmd: Sequence[str]) -> List[str]:
    """Copy of a command line that is safe to store: header values after -H are never logged."""
    safe: List[str] = []
    redact_next = False
    for token in cmd:
        if redact_next:
            safe.append(token.split(":", 1)[0] + ": [REDACTED]")
            redact_next = False
        else:
            safe.append(token)
            redact_next = token == "-H"
    return safe


def _is_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except (ValueError, TypeError):
        return False

def as_list(value) -> List[str]:
    if isinstance(value, list):
        return [str(x) for x in value if x]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


# ------------------------------------------------------------------ process helpers
def _to_text(data) -> str:
    if data is None:
        return ""
    return data.decode("utf-8", "replace") if isinstance(data, bytes) else data


def _run(cmd: Sequence[str], timeout: int, stdin: Optional[str] = None) -> Tuple[str, str, int]:
    try:
        proc = subprocess.run(
            list(cmd), input=stdin, capture_output=True, text=True, errors="replace",
            timeout=timeout, shell=False,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        raise ToolError(f"Binary not found: {cmd[0]}")
    except subprocess.TimeoutExpired as exc:
        return _to_text(exc.stdout), f"timed out after {timeout}s", -1


def _is_pd_httpx(path: str) -> bool:
    try:
        out, err, _ = _run([path, "-version", "-duc"], timeout=15)
    except ToolError:
        return False
    return "projectdiscovery" in (out + err).lower()


def find_tool(name: str) -> str:
    """Resolve a binary. Override with SUBFINDER_PATH / HTTPX_PATH / NMAP_PATH env vars."""
    override = os.environ.get(f"{name.upper()}_PATH")
    candidates = [override] if override else (["httpx-toolkit", "httpx"] if name == "httpx" else [name])
    for cand in candidates:
        path = shutil.which(cand) if cand else None
        if not path:
            continue
        if name == "httpx" and not _is_pd_httpx(path):
            continue
        return path
    raise ToolError(INSTALL_HINTS[name])


def check_tools() -> Dict[str, Tuple[bool, str]]:
    status: Dict[str, Tuple[bool, str]] = {}
    for name in ("subfinder", "httpx", "nmap"):
        try:
            status[name] = (True, find_tool(name))
        except ToolError as exc:
            status[name] = (False, str(exc))
    return status


def _require_domain(domain: str) -> str:
    normalized = ScopeGuard.normalize_hostname(domain)
    if normalized != domain or not ScopeGuard.is_valid_hostname(normalized):
        raise ToolError(f"Refusing to run a tool on invalid domain: {domain!r}")
    return normalized


# ------------------------------------------------------------------ subfinder
@dataclass(frozen=True)
class SubfinderResult:
    hosts: List[str]
    stdout: str
    stderr: str
    exit_code: int
    command: List[str]


def parse_subfinder_output(text: str) -> List[str]:
    hosts = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        host = None
        if line.startswith("{"):
            try:
                data = json.loads(line)
                host = data.get("host") if isinstance(data, dict) else None
            except json.JSONDecodeError:
                host = None
        else:
            host = line
        if isinstance(host, str) and host.strip():
            hosts.add(host.strip().lower())
    return sorted(hosts)


def run_subfinder(domain: str, binary: str = "subfinder", timeout: int = 300) -> SubfinderResult:
    domain = _require_domain(domain)
    cmd = [binary, "-d", domain, "-silent", "-all", "-json", "-duc"]
    out, err, code = _run(cmd, timeout)
    return SubfinderResult(parse_subfinder_output(out), out, err, code, cmd)


# ------------------------------------------------------------------ crt.sh
@dataclass(frozen=True)
class CrtshResult:
    hosts: List[str]
    raw_response: str
    status_code: int
    error: str = ""


def parse_crtsh_records(records) -> List[str]:
    if not isinstance(records, list):
        return []
    found = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        for key in ("name_value", "common_name"):
            value = rec.get(key)
            if isinstance(value, str):
                for entry in value.split("\n"):
                    entry = entry.strip().lower()
                    if entry:
                        found.add(entry)
    return sorted(found)


CRTSH_MAX_BYTES = 25_000_000


def query_crtsh(domain: str, timeout: float = 30.0, retries: int = 2) -> CrtshResult:
    domain = _require_domain(domain)
    url = f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json"
    request = urllib.request.Request(url, headers={"User-Agent": "ReconBoard/0.1 (security research)"})
    last_error = ""
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                status = resp.getcode()
                raw_body = resp.read(CRTSH_MAX_BYTES + 1)
            if len(raw_body) > CRTSH_MAX_BYTES:
                return CrtshResult([], "", status, f"crt.sh response larger than {CRTSH_MAX_BYTES // 1_000_000} MB, ignored")
            body = raw_body.decode("utf-8", "replace")
            try:
                records = json.loads(body)
            except json.JSONDecodeError:
                last_error = "crt.sh returned non-JSON data"
            else:
                return CrtshResult(parse_crtsh_records(records), body[:5000], status)
        except Exception as exc:  # network errors, HTTP 5xx, timeouts
            last_error = f"crt.sh request error: {exc}"
        if attempt < retries:
            time.sleep(2 * (attempt + 1))
    return CrtshResult([], "", -1, last_error)


# ------------------------------------------------------------------ httpx
@dataclass
class HttpxProbe:
    hostname: str
    url: str = ""
    status_code: Optional[int] = None
    title: Optional[str] = None
    web_server: Optional[str] = None
    content_length: Optional[int] = None
    tech: List[str] = field(default_factory=list)
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)
    cname: List[str] = field(default_factory=list)
    http_ips: List[str] = field(default_factory=list)
    redirect_location: Optional[str] = None
    cdn_waf: Optional[str] = None
    content_type: Optional[str] = None
    response_time: Optional[str] = None
    is_live: bool = False
    failed: bool = False


@dataclass
class HttpxResult:
    probes: List[HttpxProbe]
    stdout: str
    stderr: str
    exit_code: int
    command: List[str]


def parse_httpx_line(line: str) -> Optional[HttpxProbe]:
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    input_val = data.get("input")
    if input_val is None:
        input_val = data.get("host")
    hostname = ScopeGuard.normalize_hostname(str(input_val or ""))
    if not hostname:
        return None

    http_ips: List[str] = []
    for key in ("host_ip", "host"):
        value = data.get(key)
        if value and _is_ip(value) and str(value) not in http_ips:
            http_ips.append(str(value))

    a = [ip for ip in as_list(data.get("a")) if _is_ip(ip)]
    aaaa = [ip for ip in as_list(data.get("aaaa")) if _is_ip(ip)]
    cname = as_list(data.get("cname"))

    status = data.get("status_code")
    status = status if isinstance(status, int) and not isinstance(status, bool) and status > 0 else None
    length = data.get("content_length")
    length = length if isinstance(length, int) and not isinstance(length, bool) else None

    cdn = clean_text(data.get("cdn_name"), 100)
    if not cdn and data.get("cdn") is True:
        cdn = "cdn"

    tech = [t for t in (clean_text(x, 80) for x in as_list(data.get("tech"))) if t]
    location = clean_text(data.get("location"), 300)
    ctype = clean_text(data.get("content_type"), 100)
    rtime = clean_text(str(data.get("time")), 50) if data.get("time") else None

    # UNVERIFIED: httpx JSON keys `cname`, `content_type`, `time` are feature-detected but their exact emission behavior is unverified.
    # UNVERIFIED: what exact fields `-probe` emits is unverified. Only `failed` is used as the explicit-failure signal.
    is_failed = data.get("failed") is True
    return HttpxProbe(
        hostname=hostname,
        url=clean_text(data.get("url"), 300) or "",
        status_code=status,
        title=clean_text(data.get("title"), 300),
        web_server=clean_text(data.get("webserver"), 150),
        content_length=length,
        tech=tech,
        a=a,
        aaaa=aaaa,
        cname=cname,
        http_ips=http_ips,
        redirect_location=location,
        cdn_waf=cdn,
        content_type=ctype,
        response_time=rtime,
        is_live=status is not None and not is_failed,
        failed=is_failed,
    )

def _help_has(help_text: str, flag: str) -> bool:
    return bool(re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", help_text))

_VERSION_CACHE: Dict[str, str] = {}

def get_tool_version(binary: str) -> str:
    if binary not in _VERSION_CACHE:
        import os, re
        flag = "--version" if os.path.basename(binary).lower().startswith("nmap") else "-version"
        try:
            out, err, _ = _run([binary, flag], timeout=5)
            match = re.search(r"v?\d+\.\d+(?:\.\d+)?", out + err)
            _VERSION_CACHE[binary] = match.group(0) if match else "unknown"
        except Exception:
            _VERSION_CACHE[binary] = "unknown"
    return _VERSION_CACHE[binary]

_HELP_CACHE: Dict[str, str] = {}

def _get_help(binary: str) -> str:
    if binary not in _HELP_CACHE:
        try:
            out, err, _ = _run([binary, "-h"], timeout=15)
            _HELP_CACHE[binary] = out + err
        except ToolError:
            _HELP_CACHE[binary] = ""
    return _HELP_CACHE[binary]


def run_httpx(
    hosts: Sequence[str], binary: str = "httpx-toolkit", rate_limit: int = 20, threads: int = 10,
    custom_headers: Optional[Dict[str, str]] = None, timeout_seconds: int = 10,
    vetted_ips: Sequence[str] = ()
) -> HttpxResult:
    """Probe hosts via stdin. Redirects are deliberately never followed."""
    if not hosts:
        return HttpxResult([], "", "", 0, [])
    for host in hosts:
        _require_domain(host)
    headers = ScopeGuard.validate_custom_headers(custom_headers)
    cmd = [
        binary, "-json", "-silent", "-no-color", "-duc",
        "-threads", str(threads), "-rate-limit", str(rate_limit), "-timeout", str(timeout_seconds),
        "-retries", "1", "-status-code", "-title", "-tech-detect", "-web-server", "-content-length",
        "-location", "-cdn", "-ip",
    ]
    
    # UNVERIFIED: behavior of `-allow` together with `-exclude private-ips` is unverified.
    help_text = _get_help(binary)
    if _help_has(help_text, "private-ips"):
        cmd += ["-exclude", "private-ips"]
    if _help_has(help_text, "-probe"):
        cmd.append("-probe")
    if _help_has(help_text, "-cname"):
        cmd.append("-cname")
    if _help_has(help_text, "-content-type"):
        cmd.append("-content-type")
    if _help_has(help_text, "-response-time"):
        cmd.append("-response-time")
        
    tmp_allow = None
    if _help_has(help_text, "-allow") and vetted_ips:
        if len(vetted_ips) > 50:
            fd, tmp_allow = tempfile.mkstemp(prefix="httpx_allow_", text=True)
            os.chmod(tmp_allow, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(vetted_ips) + "\n")
            cmd += ["-allow", tmp_allow]
        else:
            cmd += ["-allow", ",".join(vetted_ips)]
            
    for name, value in headers.items():
        cmd += ["-H", f"{name}: {value}"]
    overall = max(300, int(len(hosts) / max(rate_limit, 1) * 4) + 120)
    
    try:
        out, err, code = _run(cmd, overall, stdin="\n".join(hosts) + "\n")
    finally:
        if tmp_allow:
            try:
                os.unlink(tmp_allow)
            except OSError:
                pass
                
    probes = [p for p in (parse_httpx_line(line) for line in out.splitlines()) if p]
    return HttpxResult(probes, out, err, code, cmd)


# ------------------------------------------------------------------ nmap
@dataclass
class NmapResult:
    hosts: Dict[str, List[dict]]  # ip -> open ports (hosts that were up, even if empty)
    stdout: str
    stderr: str
    exit_code: int
    command: List[str]
    ok: bool = True
    error: Optional[str] = None


def parse_nmap_xml(xml: str) -> Dict[str, List[dict]]:
    if not xml or not xml.strip():
        return {}
    try:
        root = SafeET.fromstring(xml)
    except (SafeET.ParseError, ValueError):  # ValueError covers defusedxml's entity/DTD rejections
        return {}
    results: Dict[str, List[dict]] = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host.find("address[@addrtype='ipv6']")
        if addr is None or not _is_ip(addr.get("addr")):
            continue
        ports: List[dict] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                try:
                    number = int(port.get("portid", "0"))
                except ValueError:
                    continue
                svc = port.find("service")
                product = clean_text(svc.get("product", ""), 100) if svc is not None else None
                version = clean_text(svc.get("version", ""), 100) if svc is not None else None
                ports.append({
                    "port": number,
                    "protocol": port.get("protocol", "tcp"),
                    "state": "open",
                    "service": (clean_text(svc.get("name", ""), 50) if svc is not None else None) or "unknown",
                    "version": " ".join(x for x in (product, version) if x),
                })
        results[addr.get("addr")] = ports
    return results


def run_nmap(ips: Sequence[str], binary: str = "nmap", max_rate: int = 50, top_ports: int = 1000) -> NmapResult:
    """TCP connect scan (no root needed) against already-vetted public IPv4 addresses only."""
    if not ips:
        return NmapResult({}, "", "", 0, [])
    for ip in ips:
        ok, why = ScopeGuard.evaluate_ip(ip)
        if not ok or ipaddress.ip_address(ip).version != 4:
            raise ToolError(f"Refusing to scan {ip!r}: {why if not ok else 'only IPv4 is supported'}")
    cmd = [
        binary, "-sT", "-Pn", "-n", "-sV", "--open", "--top-ports", str(top_ports),
        "--max-rate", str(max_rate), "-T3", "-oX", "-", *ips,
    ]
    out, err, code = _run(cmd, max(1800, 150 * len(ips)))
    ok = True
    error = None
    if code == -1:
        ok, error = False, "timeout"
    elif not out.strip():
        ok, error = False, "empty output"
    else:
        try:
            SafeET.fromstring(out)
        except (SafeET.ParseError, ValueError):
            ok, error = False, "corrupt xml"
    hosts = parse_nmap_xml(out)
    if ok and code != 0 and not hosts:
        ok = False
        error = "non-zero exit with no parsable hosts"
    return NmapResult(hosts, out, err, code, cmd, ok, error)
