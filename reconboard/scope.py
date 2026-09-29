"""Scope enforcement: the safety core of ReconBoard.

Matching semantics
------------------
* In-scope  ``*.example.com`` -> every subdomain, NOT the apex (list the apex explicitly).
* Out-of-scope ``*.example.com`` -> every subdomain AND the apex (deny stays conservative).
* ``example.com`` (no wildcard) -> that exact hostname only.
* Out-of-scope always wins over in-scope. Anything not listed is denied.
* Invalid / unsupported rules raise ScopeValidationError (fail closed, never ignored).
* IP and CIDR scope rules are NOT supported.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import urllib.parse
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List, Optional, Sequence, Tuple

import tldextract

LABEL_REGEX = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
HEADER_NAME_REGEX = re.compile(r"[A-Za-z0-9!#$%&'*+\-.^_`|~]+")
CONTROL_CHAR_REGEX = re.compile(r"[\x00-\x1f\x7f]")

DENIED_HEADER_NAMES = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te"}

KNOWN_CDN_WAF_SIGNATURES = (
    "cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva", "sucuri",
    "edgecast", "stackpath", "azure", "keycdn", "alibaba", "qcloud", "google", "cdn", "waf",
)

# Offline public-suffix list (bundled snapshot, no network). Private suffixes such as
# github.io / herokuapp.com are included so "*.github.io" cannot be used as a scope rule.
_psl = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=None, include_psl_private_domains=True)


class ScopeValidationError(ValueError):
    """Raised for invalid scope rules, hostnames or HTTP headers."""


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    rule_matched: Optional[str]
    normalized_host: str


@dataclass(frozen=True)
class ActiveScanAuth:
    allowed: bool
    ips: Tuple[str, ...]
    reason: str


def _is_ip_or_cidr(value: str) -> bool:
    for parser in (ipaddress.ip_address, lambda v: ipaddress.ip_network(v, strict=False)):
        try:
            parser(value)
            return True
        except ValueError:
            continue
    return False


@lru_cache(maxsize=4096)
def _normalize_pattern_cached(pattern: str) -> str:
    clean = pattern.strip()
    if _is_ip_or_cidr(clean):
        raise ScopeValidationError(
            f"IP/CIDR scope rules ('{pattern}') are not supported. Use hostnames or '*.domain' wildcards."
        )
    if any(c in clean for c in "/\\:?# \t\r\n@"):
        raise ScopeValidationError(f"Scope rule '{pattern}' contains forbidden characters (URL, path, port, space).")

    if clean.startswith("*."):
        remainder = clean[2:]
        if "*" in remainder:
            raise ScopeValidationError(
                f"Unsupported wildcard in '{pattern}': only a single leading '*.' is allowed."
            )
        base = ScopeGuard.normalize_hostname(remainder)
        if "." not in base:
            raise ScopeValidationError(f"Wildcard on a public suffix / TLD is not permitted: '{pattern}'.")
        if not ScopeGuard.is_valid_hostname(base):
            raise ScopeValidationError(f"Wildcard base in '{pattern}' is not a valid domain.")
        if not _psl(base).domain:
            raise ScopeValidationError(f"Wildcard on a public suffix is not permitted: '{pattern}'.")
        return f"*.{base}"

    if "*" in clean:
        raise ScopeValidationError(
            f"Unsupported wildcard in '{pattern}': only a single leading '*.' is allowed (no mid-string wildcards)."
        )
    normalized = ScopeGuard.normalize_hostname(clean)
    if not ScopeGuard.is_valid_hostname(normalized):
        raise ScopeValidationError(f"Scope rule '{pattern}' is not a valid hostname.")
    return normalized


class ScopeGuard:
    # ---------- hostnames ----------
    @classmethod
    def normalize_hostname(cls, raw_input: str) -> str:
        """Lowercase, strip scheme/port/trailing dot/'*.' prefixes, convert to punycode. '' if unusable."""
        if not raw_input or not isinstance(raw_input, str):
            return ""
        candidate = raw_input.strip()
        try:
            if "://" in candidate:
                candidate = urllib.parse.urlsplit(candidate).hostname or ""
        except ValueError:
            return ""
        if ":" in candidate and not candidate.startswith("["):
            candidate = candidate.split(":")[0]
        while candidate.startswith("*."):
            candidate = candidate[2:]
        candidate = candidate.rstrip(".").lower()
        try:
            return candidate.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return ""

    @classmethod
    def is_valid_hostname(cls, host: str) -> bool:
        """RFC 1123: <=253 chars, >=2 labels, each label 1-63 chars, no edge hyphens, not an IP."""
        if not host or not isinstance(host, str) or len(host) > 253:
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            pass
        labels = host.split(".")
        if len(labels) < 2 or labels[-1].isdigit():
            return False
        return all(label and len(label) <= 63 and LABEL_REGEX.fullmatch(label) for label in labels)

    @classmethod
    def validate_and_normalize_pattern(cls, pattern: str) -> str:
        if not pattern or not isinstance(pattern, str):
            raise ScopeValidationError("Scope rule must be a non-empty string.")
        return _normalize_pattern_cached(pattern)

    # ---------- IPs ----------
    @classmethod
    def evaluate_ip(cls, ip_str: str) -> Tuple[bool, str]:
        if not ip_str or not isinstance(ip_str, str):
            return False, "invalid_ip_format"
        try:
            ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False, "invalid_ip_format"
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if str(ip) == "169.254.169.254":
            return False, "cloud_metadata"
        if ip.is_link_local:
            return False, "link_local_ip"
        if ip.is_loopback:
            return False, "loopback_ip"
        if ip.is_unspecified:
            return False, "unspecified_ip"
        if ip.is_private:
            return False, "private_ip_rfc1918"
        if ip.is_multicast:
            return False, "multicast_ip"
        if ip.is_reserved:
            return False, "reserved_ip"
        if ip.is_unspecified:
            return False, "unspecified_ip"
        if not ip.is_global:
            return False, "non_global_ip"
        return True, "public_ip"

    # ---------- matching ----------
    @classmethod
    def matches_pattern(cls, host: str, pattern: str, is_out_of_scope: bool = False) -> bool:
        """`host` and `pattern` must already be normalized."""
        if pattern.startswith("*."):
            base = pattern[2:]
            if host.endswith("." + base):
                return True
            return is_out_of_scope and host == base
        return host == pattern

    @classmethod
    def is_in_scope(cls, candidate: str, in_scope: Sequence[str], out_of_scope: Sequence[str]) -> ScopeDecision:
        return ScopePolicy.build(in_scope, out_of_scope).decide(candidate)

    @classmethod
    def evaluate_redirect(
        cls, current_url: str, redirect_target: str, in_scope: Sequence[str], out_of_scope: Sequence[str]
    ) -> ScopeDecision:
        resolved = urllib.parse.urljoin(current_url, redirect_target)
        return cls.is_in_scope(resolved, in_scope, out_of_scope)

    # ---------- DNS / active scanning ----------
    @classmethod
    def resolve_and_validate_host(cls, hostname: str, timeout: float = 3.0) -> Tuple[bool, List[str], str]:
        """Resolve (bounded wait) and vet every returned IP.

        The caller stops waiting after `timeout`, but the lookup thread itself may linger until the
        system resolver gives up. Rebinding/TOCTOU is only prevented if the returned IPs are passed to the
        scanner directly (nmap stage does this). For httpx this is a pre-check, NOT a pin: httpx resolves
        the name again on its own.
        """
        normalized = cls.normalize_hostname(hostname)
        if not cls.is_valid_hostname(normalized):
            return False, [], "invalid_hostname"

        def _resolve(host: str) -> List[str]:
            found: List[str] = []
            for item in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
                ip = item[4][0]
                if ip not in found:
                    found.append(ip)
            return found

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(_resolve, normalized)
            try:
                ips = future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                return False, [], f"dns_timeout:{timeout}s"
            except socket.gaierror as err:
                if getattr(err, "errno", None) == getattr(socket, "EAI_NONAME", -2):
                    return False, [], f"dns_nxdomain:{err}"
                return False, [], f"dns_error:{err}"
            except OSError as err:
                return False, [], f"dns_error:{err}"
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        if not ips:
            return False, [], "no_dns_records_found"
        for ip in ips:
            ok, why = cls.evaluate_ip(ip)
            if not ok:
                return False, ips, f"prohibited_ip:{ip}:{why}"
        return True, ips, "safe"

    @classmethod
    def should_skip_nmap(cls, cdn_waf: Optional[str], ip_addresses: Sequence[str]) -> Tuple[bool, str]:
        if cdn_waf and cdn_waf.strip():
            lowered = cdn_waf.lower()
            for sig in KNOWN_CDN_WAF_SIGNATURES:
                if sig in lowered:
                    return True, f"cdn_waf_detected:{sig}"
            return True, f"cdn_waf_detected:{lowered[:40]}"
        if not ip_addresses:
            return True, "no_resolved_ips"
        for ip in ip_addresses:
            ok, why = cls.evaluate_ip(ip)
            if not ok:
                return True, f"prohibited_ip:{ip}:{why}"
        return False, "safe_for_nmap"

    @classmethod
    def authorize_active_scan(
        cls, hostname: str, policy: "ScopePolicy", allow_port_scan: bool,
        cdn_waf: Optional[str] = None, dns_timeout: float = 3.0,
    ) -> ActiveScanAuth:
        """Single gate for port scanning. Returns the vetted IPv4 addresses nmap may touch."""
        if not allow_port_scan:
            return ActiveScanAuth(False, (), "port_scan_not_allowed_for_target")
        decision = policy.decide(hostname)
        if not decision.allowed:
            return ActiveScanAuth(False, (), f"scope:{decision.reason}")
        ok, ips, reason = cls.resolve_and_validate_host(decision.normalized_host, dns_timeout)
        if not ok:
            return ActiveScanAuth(False, tuple(ips), reason)
        skip, why = cls.should_skip_nmap(cdn_waf, ips)
        if skip:
            return ActiveScanAuth(False, tuple(ips), why)
        v4 = tuple(ip for ip in ips if ipaddress.ip_address(ip).version == 4)
        if not v4:
            return ActiveScanAuth(False, tuple(ips), "ipv6_only_not_supported")
        return ActiveScanAuth(True, v4, "authorized")

    # ---------- headers ----------
    @classmethod
    def validate_custom_headers(cls, headers: Optional[Dict[str, str]]) -> Dict[str, str]:
        if not headers:
            return {}
        validated: Dict[str, str] = {}
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise ScopeValidationError("Header names and values must be strings.")
            if CONTROL_CHAR_REGEX.search(value) or CONTROL_CHAR_REGEX.search(name):
                raise ScopeValidationError(f"Header '{name.strip()}' contains control characters or line breaks.")
            clean_name, clean_value = name.strip(), value.strip()
            if not HEADER_NAME_REGEX.fullmatch(clean_name):
                raise ScopeValidationError(f"Invalid header name '{clean_name}'.")
            lower = clean_name.lower()
            if lower in DENIED_HEADER_NAMES or lower.startswith("proxy-"):
                raise ScopeValidationError(f"Header '{clean_name}' is restricted and cannot be set.")
            validated[clean_name] = clean_value
        return validated


@dataclass(frozen=True)
class ScopePolicy:
    """Immutable, validated-once scope rules for one scan."""

    in_scope: Tuple[str, ...]
    out_of_scope: Tuple[str, ...]

    @classmethod
    def build(cls, in_scope: Sequence[str], out_of_scope: Sequence[str]) -> "ScopePolicy":
        return cls(
            tuple(ScopeGuard.validate_and_normalize_pattern(r) for r in in_scope),
            tuple(ScopeGuard.validate_and_normalize_pattern(r) for r in out_of_scope),
        )

    def decide(self, candidate: str) -> ScopeDecision:
        host = ScopeGuard.normalize_hostname(candidate)
        if not host or not ScopeGuard.is_valid_hostname(host):
            return ScopeDecision(False, "invalid_hostname", None, host or candidate)
        for rule in self.out_of_scope:
            if ScopeGuard.matches_pattern(host, rule, is_out_of_scope=True):
                return ScopeDecision(False, "out_of_scope_match", rule, host)
        for rule in self.in_scope:
            if ScopeGuard.matches_pattern(host, rule):
                return ScopeDecision(True, "in_scope_match", rule, host)
        return ScopeDecision(False, "not_in_scope", None, host)
