"""Database models. Datetimes are stored as naive UTC (SQLite drops tzinfo anyway)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import relationship, validates

from . import config
from .db import Base
from .scope import ScopeGuard, ScopeValidationError


def _uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _rules(value):
    if not isinstance(value, (list, tuple)):
        raise ScopeValidationError("Scope rules must be a list.")
    out = []
    for item in value:
        norm = ScopeGuard.validate_and_normalize_pattern(item)
        if norm not in out:
            out.append(norm)
    return out


class Target(Base):
    __tablename__ = "targets"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(120), unique=True, nullable=False, index=True)
    platform = Column(String(50), default="HackerOne")
    in_scope = Column(MutableList.as_mutable(JSON), nullable=False, default=list)
    out_of_scope = Column(MutableList.as_mutable(JSON), nullable=False, default=list)
    allow_port_scan = Column(Boolean, nullable=False, default=False)
    allow_shared_ip_scan = Column(Boolean, nullable=False, default=False)
    rate_limit_profile = Column(String(30), nullable=False, default="safe")
    custom_rate_limit = Column(Integer, nullable=True)
    custom_headers = Column(MutableDict.as_mutable(JSON), nullable=False, default=dict)
    created_at = Column(DateTime, default=utc_now)

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    hosts = relationship("Host", back_populates="target", cascade="all, delete-orphan")

    @validates("in_scope")
    def _v_in_scope(self, _key, value):
        rules = _rules(value)
        if not rules:
            raise ScopeValidationError("in_scope needs at least one rule.")
        return rules

    @validates("out_of_scope")
    def _v_out_of_scope(self, _key, value):
        return _rules(value)

    @validates("custom_headers")
    def _v_headers(self, _key, value):
        return ScopeGuard.validate_custom_headers(value)

    @validates("rate_limit_profile")
    def _v_profile(self, _key, value):
        if value not in config.PROFILES:
            raise ScopeValidationError(f"Profile must be one of: {', '.join(config.PROFILES)}.")
        return value

    @validates("custom_rate_limit")
    def _v_rate(self, _key, value):
        if value is not None and not (1 <= int(value) <= 1000):
            raise ScopeValidationError("custom rate limit must be between 1 and 1000 requests/second.")
        return value


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    mode = Column(String(30), nullable=False, default="passive")
    status = Column(String(30), nullable=False, default="pending")
    started_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, nullable=True)
    stats_json = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    # complete = discovery sources AND the probe run all succeeded. Only complete scans are used as diff baselines.
    complete = Column(Boolean, nullable=False, default=False)
    scope_json = Column(JSON, nullable=True)  # scope rules that were in force for this scan (audit trail)
    config_json = Column(JSON, nullable=True)

    target = relationship("Target", back_populates="scans")
    snapshots = relationship("HostSnapshot", back_populates="scan", cascade="all, delete-orphan")
    change_logs = relationship("ChangeLog", back_populates="scan", cascade="all, delete-orphan")
    scope_audit_logs = relationship("ScopeAuditLog", back_populates="scan", cascade="all, delete-orphan")
    raw_tool_logs = relationship("RawToolLog", back_populates="scan", cascade="all, delete-orphan")


class Host(Base):
    """Stable identity of a hostname across scans."""

    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("target_id", "hostname", name="uq_target_hostname"),)

    id = Column(String(36), primary_key=True, default=_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    tags = Column(MutableList.as_mutable(JSON), default=list)
    notes = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)

    target = relationship("Target", back_populates="hosts")
    snapshots = relationship("HostSnapshot", back_populates="host", cascade="all, delete-orphan")


class HostSnapshot(Base):
    """State of one host during one scan. `probed` / `port_scan_status` say which fields are meaningful."""

    __tablename__ = "host_snapshots"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    host_id = Column(String(36), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(255), nullable=False)
    probe_status = Column(String(30), nullable=False, default="not_attempted")
    probed = Column(Boolean, nullable=False, default=False)
    url = Column(String(300), nullable=True)
    dns_ips = Column(JSON, default=list)
    http_ips = Column(JSON, default=list)
    scan_ips = Column(JSON, default=list)
    cname = Column(JSON, default=list)
    tech = Column(JSON, default=list)
    a = Column(JSON, default=list)
    aaaa = Column(JSON, default=list)
    discovery_sources = Column(JSON, default=list)
    content_type = Column(String(100), nullable=True)
    response_time = Column(String(50), nullable=True)
    port_scan_status = Column(String(20), nullable=True)
    scanned_ips = Column(JSON, default=list)
    failed_ips = Column(JSON, default=list)
    is_live = Column(Boolean, default=False)
    status_code = Column(Integer, nullable=True)
    title = Column(Text, nullable=True)
    web_server = Column(String(150), nullable=True)
    content_length = Column(Integer, nullable=True)
    redirect_location = Column(Text, nullable=True)
    cdn_waf = Column(String(100), nullable=True)
    open_ports = Column(JSON, default=list)
    created_at = Column(DateTime, default=utc_now)

    scan = relationship("Scan", back_populates="snapshots")
    host = relationship("Host", back_populates="snapshots")


class ChangeLog(Base):
    __tablename__ = "change_logs"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    host_id = Column(String(36), ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    hostname = Column(String(255), nullable=False)
    change_type = Column(String(50), nullable=False)
    details = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=utc_now)

    scan = relationship("Scan", back_populates="change_logs")


class ScopeAuditLog(Base):
    """Every candidate the Scope Guard dropped, with the reason."""

    __tablename__ = "scope_audit_logs"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    candidate_host = Column(String(255), nullable=False)
    reason = Column(String(100), nullable=False)
    rule_matched = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utc_now)

    scan = relationship("Scan", back_populates="scope_audit_logs")


class RawToolLog(Base):
    __tablename__ = "raw_tool_logs"
    MAX_CHARS = 100_000

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_name = Column(String(50), nullable=False)
    command_executed = Column(Text, nullable=False)
    exit_code = Column(Integer, nullable=False)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    scan = relationship("Scan", back_populates="raw_tool_logs")

    @validates("stdout", "stderr")
    def _truncate(self, _key, value):
        if value and len(value) > self.MAX_CHARS:
            return value[: self.MAX_CHARS] + f"\n... [truncated at {self.MAX_CHARS} characters]"
        return value
