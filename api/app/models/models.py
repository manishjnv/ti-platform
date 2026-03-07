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
    # IPinfo Lite enrichment
    asn: Mapped[str | None] = mapped_column(String(20), nullable=True)
    as_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    as_domain: Mapped[str | None] = mapped_column(String(200), nullable=True)
    country_code: Mapped[str | None] = mapped_column(String(5), nullable=True)
    country: Mapped[str | None] = mapped_column(String(100), nullable=True)
    continent_code: Mapped[str | None] = mapped_column(String(5), nullable=True)
    continent: Mapped[str | None] = mapped_column(String(50), nullable=True)
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    meta: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── Notification System ─────────────────────────────────

class NotificationRule(Base):
    __tablename__ = "notification_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    rule_type: Mapped[str] = mapped_column(String(50), nullable=False, default="threshold")
    conditions: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    channels: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=lambda: ["in_app"])
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cooldown_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trigger_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    message: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    category: Mapped[str] = mapped_column(String(50), nullable=False, default="alert")
    entity_type: Mapped[str | None] = mapped_column(String(30))
    entity_id: Mapped[str | None] = mapped_column(Text)
    meta: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── Report System ────────────────────────────────────────

class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    content: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    report_type: Mapped[str] = mapped_column(
        SAEnum("incident", "threat_advisory", "weekly_summary", "ioc_bulletin", "custom",
               name="report_type", create_type=False),
        nullable=False, default="custom",
    )
    status: Mapped[str] = mapped_column(
        SAEnum("draft", "review", "published", "archived",
               name="report_status", create_type=False),
        nullable=False, default="draft",
    )
    severity: Mapped[str] = mapped_column(
        SAEnum("critical", "high", "medium", "low", "info", "unknown",
               name="severity_level", create_type=False),
        nullable=False, default="medium",
    )
    tlp: Mapped[str] = mapped_column(
        SAEnum("TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR",
               name="tlp_level", create_type=False),
        nullable=False, default="TLP:GREEN",
    )
    author_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    template: Mapped[str | None] = mapped_column(String(50))
    linked_intel_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    linked_ioc_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    linked_technique_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReportItem(Base):
    __tablename__ = "report_items"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    item_type: Mapped[str] = mapped_column(String(30), nullable=False)
    item_id: Mapped[str] = mapped_column(Text, nullable=False)
    item_title: Mapped[str | None] = mapped_column(Text)
    item_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    added_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── User Settings ────────────────────────────────────────

class UserSetting(Base):
    __tablename__ = "user_settings"

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    preferences: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ─── Cyber News ───────────────────────────────────────────

class NewsItem(Base):
    __tablename__ = "news_items"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    headline: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(200), nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    category: Mapped[str] = mapped_column(
        SAEnum(
            "active_threats", "exploited_vulnerabilities", "ransomware_breaches",
            "nation_state", "cloud_identity", "ot_ics", "security_research",
            "tools_technology", "policy_regulation",
            name="news_category", create_type=False,
        ),
        nullable=False, default="active_threats",
    )
    summary: Mapped[str | None] = mapped_column(Text)
    executive_brief: Mapped[str | None] = mapped_column(Text)
    risk_assessment: Mapped[str | None] = mapped_column(Text)
    attack_narrative: Mapped[str | None] = mapped_column(Text)
    recommended_priority: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")

    # Structured intelligence (AI-enriched)
    why_it_matters: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    threat_actors: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    malware_families: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    campaign_name: Mapped[str | None] = mapped_column(String(300))
    cves: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    vulnerable_products: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    tactics_techniques: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    initial_access_vector: Mapped[str | None] = mapped_column(Text)
    post_exploitation: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    targeted_sectors: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    targeted_regions: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    impacted_assets: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)

    # Structured JSON blocks
    ioc_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    timeline: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    detection_opportunities: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    mitigation_recommendations: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)

    # Detection engineering (AI-generated)
    yara_rule: Mapped[str | None] = mapped_column(Text)
    kql_rule: Mapped[str | None] = mapped_column(Text)
    reference_links: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)

    # Scoring
    confidence: Mapped[str] = mapped_column(
        SAEnum("high", "medium", "low", name="confidence_level", create_type=False),
        nullable=False, default="medium",
    )
    relevance_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)

    # Processing state
    ai_enriched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    raw_content: Mapped[str | None] = mapped_column(Text)
    source_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # Cross-source correlation: tracks other sources covering the same story
    correlated_sources: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class NewsFeedStatus(Base):
    """Tracks per-RSS-source fetch health for the Cyber News pipeline."""
    __tablename__ = "news_feed_status"

    source_name: Mapped[str] = mapped_column(String(200), primary_key=True)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")  # ok, error, timeout, unknown
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    articles_last_fetch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_articles: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_checked: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ─── Intelligence Extraction (derived from news) ─────────


class VulnerableProduct(Base):
    """Aggregated vulnerable products extracted from AI-enriched news (48h window)."""
    __tablename__ = "intel_vulnerable_products"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    product_name: Mapped[str] = mapped_column(String(300), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(200))
    cve_id: Mapped[str | None] = mapped_column(String(50))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    epss_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    exploit_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    patch_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    affected_versions: Mapped[str | None] = mapped_column(Text)
    targeted_sectors: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    targeted_regions: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    source_news_ids: Mapped[list[str]] = mapped_column(ARRAY(UUID(as_uuid=True)), nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    confidence: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    is_false_positive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatCampaign(Base):
    """Aggregated threat actors & campaigns from AI-enriched news (7d window)."""
    __tablename__ = "intel_threat_campaigns"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_name: Mapped[str] = mapped_column(String(300), nullable=False)
    campaign_name: Mapped[str | None] = mapped_column(String(300))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    targeted_sectors: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    targeted_regions: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    malware_used: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    techniques_used: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    cves_exploited: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    source_news_ids: Mapped[list[str]] = mapped_column(ARRAY(UUID(as_uuid=True)), nullable=False, default=list)
    confidence: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    is_false_positive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ─── Case / Incident Management ──────────────────────────


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    case_type: Mapped[str] = mapped_column(
        SAEnum("incident_response", "investigation", "hunt", "rfi",
               name="case_type", create_type=False),
        nullable=False, default="investigation",
    )
    status: Mapped[str] = mapped_column(
        SAEnum("new", "in_progress", "pending", "resolved", "closed",
               name="case_status", create_type=False),
        nullable=False, default="new",
    )
    priority: Mapped[str] = mapped_column(
        SAEnum("critical", "high", "medium", "low",
               name="case_priority", create_type=False),
        nullable=False, default="medium",
    )
    severity: Mapped[str] = mapped_column(
        SAEnum("critical", "high", "medium", "low", "info", "unknown",
               name="severity_level", create_type=False),
        nullable=False, default="medium",
    )
    tlp: Mapped[str] = mapped_column(
        SAEnum("TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR",
               name="tlp_level", create_type=False),
        nullable=False, default="TLP:GREEN",
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    linked_intel_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    linked_ioc_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    linked_observable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CaseItem(Base):
    __tablename__ = "case_items"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    item_type: Mapped[str] = mapped_column(String(30), nullable=False)
    item_id: Mapped[str] = mapped_column(Text, nullable=False)
    item_title: Mapped[str | None] = mapped_column(Text)
    item_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    added_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CaseActivity(Base):
    __tablename__ = "case_activities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    meta: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
