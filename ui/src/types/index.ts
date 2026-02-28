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
