export interface IntelItem {
  id: string;
  title: string;
  summary: string | null;
  description: string | null;
  published_at: string | null;
  ingested_at: string;
  updated_at: string;
  severity: Severity;
  risk_score: number;
  confidence: number;
  source_name: string;
  source_url: string | null;
  source_reliability: number;
  source_ref: string | null;
  feed_type: FeedType;
  asset_type: AssetType;
  tlp: string;
  tags: string[];
  geo: string[];
  industries: string[];
  cve_ids: string[];
  affected_products: string[];
  related_ioc_count: number;
  is_kev: boolean;
  exploit_available: boolean;
  exploitability_score: number | null;
  ai_summary: string | null;
  ai_summary_at: string | null;
  source_hash: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
export type FeedType = 'vulnerability' | 'ioc' | 'malware' | 'threat_actor' | 'campaign' | 'exploit' | 'advisory';
export type AssetType = 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'email' | 'cve' | 'file' | 'other';

export interface IntelListResponse {
  items: IntelItem[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface SearchResponse {
  results: IntelItem[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
  query: string;
  detected_type: string | null;
}

export interface SeverityCount {
  severity: string;
  feed_type: string;
  count: number;
  avg_risk_score: number;
}

export interface FeedStatus {
  feed_name: string;
  last_run: string | null;
  last_success: string | null;
  status: string;
  items_fetched: number;
  items_stored: number;
  error_message: string | null;
  run_count: number;
}

export interface DashboardData {
  severity_distribution: SeverityCount[];
  top_risks: IntelItem[];
  total_items: number;
  items_last_24h: number;
  avg_risk_score: number;
  kev_count: number;
  feed_status: FeedStatus[];
}

export interface TrendingProduct {
  name: string;
  count: number;
  avg_risk: number;
  exploit: boolean;
}

export interface ThreatActorInsight {
  name: string;
  count: number;
  avg_risk: number;
  cves: string[];
  industries: string[];
  regions: string[];
}

export interface RansomwareInsight {
  name: string;
  count: number;
  avg_risk: number;
  exploit: boolean;
  industries: string[];
  regions: string[];
}

export interface MalwareInsight {
  name: string;
  count: number;
  avg_risk: number;
  regions: string[];
}

export interface DashboardInsights {
  trending_products: Record<string, TrendingProduct[]>;
  threat_actors: ThreatActorInsight[];
  ransomware: RansomwareInsight[];
  malware_families: MalwareInsight[];
  exploit_count: number;
  threat_geography: GeoInsight[];
  target_industries: IndustryInsight[];
  attack_techniques: NameCount[];
  ingestion_trend: TrendPoint[];
  exploit_summary: ExploitSummary;
}

export interface GeoInsight {
  name: string;
  count: number;
  avg_risk: number;
}

export interface IndustryInsight {
  name: string;
  count: number;
  avg_risk: number;
}

export interface TrendPoint {
  date: string;
  count: number;
}

export interface ExploitSummary {
  with_exploit: number;
  kev_count: number;
  avg_epss: number;
  high_epss_count: number;
  total: number;
  exploit_pct: number;
  kev_pct: number;
}

export interface InsightDetailItem {
  id: string;
  title: string;
  summary: string | null;
  severity: string;
  risk_score: number;
  confidence: number;
  source_name: string;
  source_url: string | null;
  feed_type: string;
  tags: string[];
  geo: string[];
  industries: string[];
  cve_ids: string[];
  affected_products: string[];
  exploit_available: boolean;
  is_kev: boolean;
  published_at: string | null;
  ingested_at: string | null;
  related_ioc_count: number;
  exploitability_score: number | null;
}

export interface NameCount {
  name: string;
  count: number;
}

export interface InsightDetailSummary {
  total_items: number;
  avg_risk: number;
  exploit_count: number;
  severity_distribution: Record<string, number>;
  top_cves: NameCount[];
  top_tags: NameCount[];
  top_regions: NameCount[];
  top_industries: NameCount[];
  top_products: NameCount[];
}

export interface InsightDetail {
  items: InsightDetailItem[];
  summary: InsightDetailSummary;
}

export interface AllInsightEntity {
  name: string;
  count: number;
  avg_risk: number;
  cves: string[];
  industries: string[];
  regions: string[];
}

export interface User {
  id: string;
  email: string;
  name: string | null;
  role: 'admin' | 'analyst' | 'viewer';
  avatar_url: string | null;
  last_login: string | null;
  is_active: boolean;
}

export interface SearchFilters {
  query: string;
  feed_type?: FeedType;
  severity?: Severity;
  asset_type?: AssetType;
  date_from?: string;
  date_to?: string;
  page: number;
  page_size: number;
}

// ─── MITRE ATT&CK ──────────────────────────────────────
export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  tactic_label: string;
  description: string | null;
  url: string | null;
  platforms: string[];
  detection: string | null;
  is_subtechnique: boolean;
  parent_id: string | null;
  data_sources: string[];
  intel_count: number;
}

export interface AttackTechniqueListResponse {
  techniques: AttackTechnique[];
  total: number;
  tactics: string[];
}

export interface AttackMatrixCell {
  id: string;
  name: string;
  count: number;
  max_risk: number;
}

export interface AttackMatrixTactic {
  tactic: string;
  label: string;
  techniques: AttackMatrixCell[];
}

export interface AttackMatrixResponse {
  tactics: AttackMatrixTactic[];
  total_techniques: number;
  total_mapped: number;
}

export interface IntelAttackLink {
  technique_id: string;
  technique_name: string;
  tactic: string;
  tactic_label: string;
  confidence: number;
  mapping_type: string;
  url: string | null;
}

// ─── Relationship Graph ─────────────────────────────────
export interface GraphNode {
  id: string;
  type: string;
  label: string;
  severity?: Severity;
  risk_score?: number;
  source?: string;
  feed_type?: FeedType;
  ioc_type?: string;
  tactic?: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  confidence: number;
  first_seen: string | null;
  last_seen: string | null;
  metadata: Record<string, unknown>;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  center: string;
  total_nodes: number;
  total_edges: number;
}

export interface RelatedIntelItem {
  id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  source_name: string;
  feed_type: FeedType;
  ingested_at: string;
  relationship_type: string;
  confidence: number;
  meta: Record<string, unknown>;
}

export interface GraphStatsResponse {
  total_relationships: number;
  by_type: Record<string, number>;
  avg_confidence: number;
}

// ─── Intel Enrichment ───────────────────────────────────
export interface EnrichmentThreatActor {
  name: string;
  aliases: string[];
  motivation: string;
  confidence: string;
  description: string;
}

export interface EnrichmentAttackTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  description: string;
  mitigations: string[];
}

export interface EnrichmentAffectedVersion {
  product: string;
  vendor: string;
  versions_affected: string;
  fixed_version: string | null;
  patch_url: string | null;
  cpe: string | null;
}

export interface EnrichmentTimelineEvent {
  date: string | null;
  event: string;
  description: string;
  type: string;
}

export interface EnrichmentCampaign {
  name: string;
  date: string;
  description: string;
  impact: string;
}

export interface EnrichmentExploitInfo {
  epss_estimate: number | null;
  exploit_maturity: string;
  in_the_wild: boolean;
  ransomware_use: boolean;
  description: string | null;
}

export interface EnrichmentRemediation {
  priority: string | null;
  guidance: string[];
  workarounds: string[];
  references: { title: string; url: string }[];
}

export interface IntelEnrichment {
  executive_summary: string | null;
  threat_actors: EnrichmentThreatActor[];
  attack_techniques: EnrichmentAttackTechnique[];
  affected_versions: EnrichmentAffectedVersion[];
  timeline_events: EnrichmentTimelineEvent[];
  notable_campaigns: EnrichmentCampaign[];
  exploitation_info: EnrichmentExploitInfo;
  remediation: EnrichmentRemediation;
  related_cves: string[];
  tags_suggested: string[];
}

export interface RelatedIntelItemEnriched {
  id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  source_name: string;
  feed_type: FeedType;
  ingested_at: string;
  relationship_type: string;
  confidence: number;
  shared_cves: string[];
  shared_tags: string[];
  shared_products: string[];
}

// ─── Notifications ──────────────────────────────────────
export interface Notification {
  id: string;
  user_id: string;
  rule_id: string | null;
  title: string;
  message: string | null;
  severity: Severity;
  category: 'alert' | 'feed_error' | 'risk_change' | 'correlation' | 'system';
  entity_type: string | null;
  entity_id: string | null;
  metadata: Record<string, unknown>;
  is_read: boolean;
  read_at: string | null;
  created_at: string;
}

export interface NotificationListResponse {
  notifications: Notification[];
  total: number;
  unread_count: number;
}

export interface NotificationRule {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  rule_type: 'threshold' | 'keyword' | 'feed_error' | 'risk_change' | 'correlation';
  conditions: Record<string, unknown>;
  channels: string[];
  is_active: boolean;
  is_system: boolean;
  cooldown_minutes: number;
  last_triggered_at: string | null;
  trigger_count: number;
  created_at: string;
  updated_at: string;
}

export interface NotificationRuleCreate {
  name: string;
  description?: string;
  rule_type?: string;
  conditions?: Record<string, unknown>;
  channels?: string[];
  is_active?: boolean;
  cooldown_minutes?: number;
}

export interface NotificationStats {
  unread_count: number;
  last_24h_total: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
}

// ─── Reports ────────────────────────────────────────────
export type ReportStatus = 'draft' | 'review' | 'published' | 'archived';
export type ReportType = 'incident' | 'threat_advisory' | 'weekly_summary' | 'ioc_bulletin' | 'custom';

export interface ReportItem {
  id: string;
  report_id: string;
  item_type: 'intel' | 'ioc' | 'technique';
  item_id: string;
  item_title: string | null;
  item_metadata: Record<string, unknown>;
  added_by: string | null;
  notes: string | null;
  created_at: string;
}

export interface Report {
  id: string;
  title: string;
  summary: string | null;
  content: {
    sections?: Array<{
      key: string;
      title: string;
      hint?: string;
      body: string;
    }>;
  };
  report_type: ReportType;
  status: ReportStatus;
  severity: Severity;
  tlp: string;
  author_id: string;
  template: string | null;
  linked_intel_count: number;
  linked_ioc_count: number;
  linked_technique_count: number;
  tags: string[];
  created_at: string;
  updated_at: string;
  published_at: string | null;
  items: ReportItem[];
  author_email: string | null;
}

export interface ReportListResponse {
  reports: Report[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface ReportCreate {
  title: string;
  summary?: string;
  content?: Record<string, unknown>;
  report_type?: ReportType;
  severity?: Severity;
  tlp?: string;
  template?: string;
  tags?: string[];
}

export interface ReportUpdate {
  title?: string;
  summary?: string;
  content?: Record<string, unknown>;
  report_type?: ReportType;
  status?: ReportStatus;
  severity?: Severity;
  tlp?: string;
  template?: string;
  tags?: string[];
}

export interface ReportStats {
  total_reports: number;
  by_status: Record<string, number>;
  by_type: Record<string, number>;
  recent_published: number;
}

export interface ReportTemplate {
  label: string;
  description: string;
  sections: Array<{
    key: string;
    title: string;
    hint?: string;
  }>;
}
