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
