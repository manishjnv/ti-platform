"""Pydantic schemas for API request/response models."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict


# ─── Enums ───────────────────────────────────────────────
class SeverityLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    unknown = "unknown"


class FeedType(str, Enum):
    vulnerability = "vulnerability"
    ioc = "ioc"
    malware = "malware"
    threat_actor = "threat_actor"
    campaign = "campaign"
    exploit = "exploit"
    advisory = "advisory"


class AssetType(str, Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash_md5 = "hash_md5"
    hash_sha1 = "hash_sha1"
    hash_sha256 = "hash_sha256"
    email = "email"
    cve = "cve"
    file = "file"
    other = "other"


class TLPLevel(str, Enum):
    red = "TLP:RED"
    amber_strict = "TLP:AMBER+STRICT"
    amber = "TLP:AMBER"
    green = "TLP:GREEN"
    clear = "TLP:CLEAR"


class UserRole(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


# ─── Intel Item ──────────────────────────────────────────
class IntelItemBase(BaseModel):
    title: str
    summary: str | None = None
    description: str | None = None
    published_at: datetime | None = None
    severity: SeverityLevel = SeverityLevel.unknown
    risk_score: int = Field(default=0, ge=0, le=100)
    confidence: int = Field(default=50, ge=0, le=100)
    source_name: str
    source_url: str | None = None
    source_reliability: int = Field(default=50, ge=0, le=100)
    source_ref: str | None = None
    feed_type: FeedType
    asset_type: AssetType = AssetType.other
    tlp: TLPLevel = TLPLevel.clear
    tags: list[str] = Field(default_factory=list)
    geo: list[str] = Field(default_factory=list)
    industries: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    related_ioc_count: int = 0
    is_kev: bool = False
    exploit_available: bool = False
    exploitability_score: float | None = None


class IntelItemResponse(IntelItemBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ingested_at: datetime
    updated_at: datetime
    ai_summary: str | None = None
    ai_summary_at: datetime | None = None
    source_hash: str


class IntelItemListResponse(BaseModel):
    items: list[IntelItemResponse]
    total: int
    page: int
    page_size: int
    pages: int


# ─── IOC ─────────────────────────────────────────────────
class IOCResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    value: str
    ioc_type: AssetType
    first_seen: datetime
    last_seen: datetime
    sighting_count: int
    risk_score: int
    tags: list[str]
    geo: list[str]
    source_names: list[str]
    context: dict


class IOCSearchResult(BaseModel):
    iocs: list[IOCResponse]
    intel_items: list[IntelItemResponse]
    total: int


# ─── Search ──────────────────────────────────────────────
class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=500)
    feed_type: FeedType | None = None
    severity: SeverityLevel | None = None
    asset_type: AssetType | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class SearchResponse(BaseModel):
    results: list[IntelItemResponse]
    total: int
    page: int
    page_size: int
    pages: int
    query: str
    detected_type: str | None = None


# ─── Dashboard ───────────────────────────────────────────
class SeverityCount(BaseModel):
    severity: str
    feed_type: str
    count: int
    avg_risk_score: float


class DashboardResponse(BaseModel):
    severity_distribution: list[SeverityCount]
    top_risks: list[IntelItemResponse]
    total_items: int
    items_last_24h: int
    avg_risk_score: float
    kev_count: int
    feed_status: list[FeedStatusResponse]


# ─── Feed Status ─────────────────────────────────────────
class FeedStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    feed_name: str
    last_run: datetime | None = None
    last_success: datetime | None = None
    status: str
    items_fetched: int
    items_stored: int
    error_message: str | None = None
    run_count: int


# ─── User ────────────────────────────────────────────────
class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    name: str | None = None
    role: UserRole
    avatar_url: str | None = None
    last_login: datetime | None = None
    is_active: bool


class UserUpdate(BaseModel):
    role: UserRole | None = None
    is_active: bool | None = None


# ─── Audit ───────────────────────────────────────────────
class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: uuid.UUID | None = None
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    details: dict
    ip_address: str | None = None
    created_at: datetime


# ─── Risk Scoring ────────────────────────────────────────
class ScoringWeights(BaseModel):
    kev_presence: float = Field(default=25, ge=0, le=100)
    severity: float = Field(default=25, ge=0, le=100)
    source_reliability: float = Field(default=15, ge=0, le=100)
    freshness: float = Field(default=20, ge=0, le=100)
    ioc_prevalence: float = Field(default=15, ge=0, le=100)


class ScoringConfigResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    weights: dict
    is_active: bool


# ─── MITRE ATT&CK ───────────────────────────────────────
class AttackTechniqueResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    tactic: str
    tactic_label: str
    description: str | None = None
    url: str | None = None
    platforms: list[str] = Field(default_factory=list)
    detection: str | None = None
    is_subtechnique: bool = False
    parent_id: str | None = None
    data_sources: list[str] = Field(default_factory=list)
    intel_count: int = 0  # populated at query time


class AttackTechniqueListResponse(BaseModel):
    techniques: list[AttackTechniqueResponse]
    total: int
    tactics: list[str]


class AttackMatrixCell(BaseModel):
    """A single cell in the matrix heatmap."""
    id: str
    name: str
    count: int = 0
    max_risk: int = 0


class AttackMatrixTactic(BaseModel):
    """One column (tactic) in the matrix."""
    tactic: str
    label: str
    techniques: list[AttackMatrixCell]


class AttackMatrixResponse(BaseModel):
    tactics: list[AttackMatrixTactic]
    total_techniques: int
    total_mapped: int


class IntelAttackLinkResponse(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    tactic_label: str
    confidence: int
    mapping_type: str
    url: str | None = None


# ─── Graph / Relationships ───────────────────────────────
class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    severity: str | None = None
    risk_score: int | None = None
    source: str | None = None
    feed_type: str | None = None
    ioc_type: str | None = None
    tactic: str | None = None


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str
    confidence: int = 50
    first_seen: str | None = None
    last_seen: str | None = None
    metadata: dict = Field(default_factory=dict)


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    center: str
    total_nodes: int
    total_edges: int


class RelatedIntelItem(BaseModel):
    id: str
    title: str
    severity: str
    risk_score: int
    source_name: str
    feed_type: str
    ingested_at: str
    relationship_type: str
    confidence: int
    meta: dict = Field(default_factory=dict)


class GraphStatsResponse(BaseModel):
    total_relationships: int
    by_type: dict[str, int]
    avg_confidence: float


# ─── Health ──────────────────────────────────────────────
class HealthResponse(BaseModel):
    status: str
    version: str
    postgres: bool
    redis: bool
    opensearch: bool
    environment: str


# ─── Notifications ───────────────────────────────────────
class NotificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    rule_id: uuid.UUID | None = None
    title: str
    message: str | None = None
    severity: str
    category: str
    entity_type: str | None = None
    entity_id: str | None = None
    metadata: dict = Field(default_factory=dict)
    is_read: bool
    read_at: datetime | None = None
    created_at: datetime


class NotificationListResponse(BaseModel):
    notifications: list[NotificationResponse]
    total: int
    unread_count: int


class NotificationRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    description: str | None = None
    rule_type: str
    conditions: dict
    channels: list[str]
    is_active: bool
    is_system: bool
    cooldown_minutes: int
    last_triggered_at: datetime | None = None
    trigger_count: int
    created_at: datetime
    updated_at: datetime


class NotificationRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=150)
    description: str | None = None
    rule_type: str = "threshold"
    conditions: dict = Field(default_factory=dict)
    channels: list[str] = Field(default_factory=lambda: ["in_app"])
    is_active: bool = True
    cooldown_minutes: int = Field(default=15, ge=1, le=1440)


class NotificationRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    rule_type: str | None = None
    conditions: dict | None = None
    channels: list[str] | None = None
    is_active: bool | None = None
    cooldown_minutes: int | None = None


class NotificationMarkRead(BaseModel):
    notification_ids: list[uuid.UUID]


class NotificationStatsResponse(BaseModel):
    unread_count: int
    last_24h_total: int
    by_category: dict[str, int]
    by_severity: dict[str, int]
