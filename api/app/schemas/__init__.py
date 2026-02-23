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


# ─── Health ──────────────────────────────────────────────
class HealthResponse(BaseModel):
    status: str
    version: str
    postgres: bool
    redis: bool
    opensearch: bool
    environment: str
