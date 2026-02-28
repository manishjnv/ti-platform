"""SQLAlchemy ORM models for the IntelWatch TI Platform."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    ARRAY,
    Boolean,
    DateTime,
    Enum as SAEnum,
    Float,
    Integer,
    SmallInteger,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

import enum


class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(
        SAEnum("admin", "analyst", "viewer", name="user_role", create_type=False),
        nullable=False,
        default="viewer",
    )
    avatar_url: Mapped[str | None] = mapped_column(Text)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class IntelItem(Base):
    __tablename__ = "intel_items"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)

    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_url: Mapped[str | None] = mapped_column(Text)
    source_reliability: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    source_ref: Mapped[str | None] = mapped_column(String(500))

    feed_type: Mapped[str] = mapped_column(String(30), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(30), nullable=False, default="other")
    tlp: Mapped[str] = mapped_column(String(30), nullable=False, default="TLP:CLEAR")

    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    geo: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    industries: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    cve_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    affected_products: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)

    related_ioc_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    exploit_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    exploitability_score: Mapped[float | None] = mapped_column(Float)

    ai_summary: Mapped[str | None] = mapped_column(Text)
    ai_summary_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    source_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(30), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    sighting_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    geo: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    source_names: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    context: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IntelIOCLink(Base):
    __tablename__ = "intel_ioc_links"

    intel_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    intel_ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    ioc_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    relationship: Mapped[str] = mapped_column(String(50), nullable=False, default="associated")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FeedSyncState(Base):
    __tablename__ = "feed_sync_state"

    feed_name: Mapped[str] = mapped_column(String(100), primary_key=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_cursor: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="idle")
    items_fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    items_stored: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True, server_default=func.now())


class ScoringConfig(Base):
    __tablename__ = "scoring_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    weights: Mapped[dict] = mapped_column(JSONB, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)  # T1059, T1059.001
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(50), nullable=False)
    tactic_label: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    platforms: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    detection: Mapped[str | None] = mapped_column(Text)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    parent_id: Mapped[str | None] = mapped_column(String(20))
    data_sources: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IntelAttackLink(Base):
    __tablename__ = "intel_attack_links"

    intel_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    intel_ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    mapping_type: Mapped[str] = mapped_column(String(30), nullable=False, default="auto")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Relationship(Base):
    __tablename__ = "relationships"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(30), nullable=False)
    target_id: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[str] = mapped_column(String(30), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False, default="related-to")
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    auto_generated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
