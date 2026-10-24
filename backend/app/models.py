from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base

# Alle Zeiten werden in UTC ohne Zeitzonenangabe gespeichert.


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    token_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    role: Mapped[str | None] = mapped_column(String(10), nullable=True)  # admin | user
    active: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    alert_email: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # Warnungen per E-Mail (leer = ja für Admins)


class Invite(Base):
    __tablename__ = "invites"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    used_by_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
    actor: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(40))
    detail: Mapped[str | None] = mapped_column(String(300), nullable=True)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class KeyValue(Base):
    """Kleiner Zustandsspeicher für Hintergrundaufgaben (öffentliche IP, letzte Läufe …)."""
    __tablename__ = "kv_state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Agent(Base):
    """Ein kleiner Dienst auf einem Server: liefert Zugriffsprotokolle des Proxy Managers und Live-Verbindungen."""
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(120), nullable=True)
    version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    info: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON: Adressen, System, Last
    connections: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON: letzte Momentaufnahme
    connections_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    log_files: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON: beobachtete Dateien
    enforce_blocks: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # vom Agenten gemeldet
    block_status: Mapped[str | None] = mapped_column(String(300), nullable=True)
    lines_total: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    parse_errors: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


class AccessEvent(Base):
    __tablename__ = "access_events"
    __table_args__ = (
        Index("ix_access_ts_host", "ts", "host"),
        Index("ix_access_ip_ts", "ip", "ts"),
    )

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    agent_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    host: Mapped[str] = mapped_column(String(253))
    method: Mapped[str] = mapped_column(String(12))
    scheme: Mapped[str | None] = mapped_column(String(8), nullable=True)
    path: Mapped[str] = mapped_column(String(1000))
    status: Mapped[int] = mapped_column(Integer)
    bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    ip: Mapped[str] = mapped_column(String(45))
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    asn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    as_org: Mapped[str | None] = mapped_column(String(120), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    referer: Mapped[str | None] = mapped_column(String(400), nullable=True)
    upstream: Mapped[str | None] = mapped_column(String(120), nullable=True)
    blocked: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # vom Proxy abgewiesen (Sperrliste)


class PortFinding(Base):
    __tablename__ = "port_findings"
    __table_args__ = (UniqueConstraint("target", "port", "source", name="uq_port_finding"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(10))  # scan | shodan
    service: Mapped[str | None] = mapped_column(String(80), nullable=True)
    banner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    open: Mapped[bool] = mapped_column(Boolean, default=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ExpectedPort(Base):
    """Ports, die du als gewollt markiert hast (zum Beispiel 80 und 443 für den Proxy)."""
    __tablename__ = "expected_ports"

    port: Mapped[int] = mapped_column(Integer, primary_key=True)
    note: Mapped[str | None] = mapped_column(String(120), nullable=True)


class SiteCheck(Base):
    __tablename__ = "site_checks"

    host: Mapped[str] = mapped_column(String(253), primary_key=True)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    grade: Mapped[str | None] = mapped_column(String(2), nullable=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cert_expires: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cert_issuer: Mapped[str | None] = mapped_column(String(200), nullable=True)
    cert_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    tls_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    https_redirect: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    checks: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON-Liste der Einzelprüfungen
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    source: Mapped[str | None] = mapped_column(String(10), nullable=True)  # npm | manual
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incident_ip_kind", "ip", "kind"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45))
    kind: Mapped[str] = mapped_column(String(20))  # scanner | bruteforce | notfound | badagent | flood
    severity: Mapped[str] = mapped_column(String(6))  # info | warn | crit
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    hosts: Mapped[str | None] = mapped_column(String(400), nullable=True)
    sample: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON: Beispielanfragen
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    as_org: Mapped[str | None] = mapped_column(String(120), nullable=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)


class BlockEntry(Base):
    __tablename__ = "blocklist"

    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String(49), unique=True)
    reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    auto: Mapped[bool] = mapped_column(Boolean, default=False)


class Monitor(Base):
    __tablename__ = "monitors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    url: Mapped[str] = mapped_column(String(500))
    expect: Mapped[str] = mapped_column(String(40), default="200-399")
    keyword: Mapped[str | None] = mapped_column(String(120), nullable=True)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(10), default="manual")  # manual | npm
    state: Mapped[str] = mapped_column(String(8), default="unknown")  # up | down | unknown
    fails: Mapped[int] = mapped_column(Integer, default=0)
    last_check: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    changed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MonitorResult(Base):
    __tablename__ = "monitor_results"
    __table_args__ = (Index("ix_monres_mon_ts", "monitor_id", "ts"),)

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    monitor_id: Mapped[int] = mapped_column(ForeignKey("monitors.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime)
    ok: Mapped[bool] = mapped_column(Boolean)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)


class DynRecord(Base):
    """DNS-Records, die NetworkHelper bei einer neuen öffentlichen IP automatisch nachzieht."""
    __tablename__ = "dyn_records"
    __table_args__ = (UniqueConstraint("domain", "name", "type", name="uq_dyn_record"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(253))
    name: Mapped[str] = mapped_column(String(253))  # Subdomain, "" = Hauptdomain
    type: Mapped[str] = mapped_column(String(6), default="A")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    last_update: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(300), nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    severity: Mapped[str] = mapped_column(String(6))  # info | warn | crit
    kind: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    dedupe_key: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    send_error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    read: Mapped[bool] = mapped_column(Boolean, default=False)

