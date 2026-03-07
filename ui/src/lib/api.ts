const API_PREFIX = "/api/v1";

async function fetcher<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_PREFIX}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    credentials: "include",
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }));
    const err = new Error(error.detail || `HTTP ${res.status}`) as Error & { status: number };
    err.status = res.status;
    throw err;
  }

  return res.json();
}

// ─── Auth ───────────────────────────────────────────────
export async function getAuthConfig() {
  return fetcher<{
    google_configured: boolean;
    email_otp_enabled: boolean;
    app_name: string;
  }>("/auth/config");
}

export async function getGoogleAuthUrl() {
  return fetcher<{ url: string; state: string }>("/auth/google/url");
}

export async function sendOTP(email: string) {
  return fetcher<{ status: string; message: string }>("/auth/otp/send", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
}

export async function verifyOTP(email: string, code: string) {
  return fetcher<{
    status: string;
    user: import("@/types").User;
  }>("/auth/otp/verify", {
    method: "POST",
    body: JSON.stringify({ email, code }),
  });
}

export async function logout() {
  return fetcher<{ status: string }>("/auth/logout", { method: "POST" });
}

export async function checkSession() {
  return fetcher<{
    status: string;
    user: import("@/types").User;
  }>("/auth/session");
}

// ─── Intel ──────────────────────────────────────────────
export async function getIntelItems(params: Record<string, string | number | undefined> = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== "") query.set(k, String(v));
  });
  return fetcher<import("@/types").IntelListResponse>(`/intel?${query}`);
}

export async function getIntelItem(id: string) {
  return fetcher<import("@/types").IntelItem>(`/intel/${id}`);
}

export function getExportUrl(params: Record<string, string> = {}) {
  const query = new URLSearchParams(params);
  return `${API_PREFIX}/intel/export?${query}`;
}

// ─── Search ─────────────────────────────────────────────
export async function searchIntel(body: import("@/types").SearchFilters) {
  return fetcher<import("@/types").SearchResponse>("/search", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export interface SearchAggStats {
  type_distribution: Array<{ name: string; count: number }>;
  severity_distribution: Array<{ name: string; count: number }>;
  feed_distribution: Array<{ name: string; count: number }>;
  source_distribution: Array<{ name: string; count: number }>;
  total: number;
  avg_risk: number;
  kev_count: number;
}

export async function getSearchStats(): Promise<SearchAggStats> {
  return fetcher<SearchAggStats>("/search/stats");
}

export interface LiveLookupResult {
  source: string;
  type: string;
  title: string;
  description: string;
  severity: string;
  risk_score: number;
  confidence: number;
  [key: string]: unknown;
}

export interface AiAnalysis {
  summary: string;
  threat_actors: string[];
  timeline: { date: string; event: string }[];
  affected_products: string[];
  fix_remediation: string | null;
  known_breaches: string | null;
  key_findings: string[];
}

export interface LiveLookupResponse {
  query: string;
  detected_type: string | null;
  timestamp: string;
  sources_queried: string[];
  results: LiveLookupResult[];
  ai_summary: string | null;
  ai_analysis: AiAnalysis | null;
  errors: string[];
}

export async function liveLookup(query: string): Promise<LiveLookupResponse> {
  return fetcher<LiveLookupResponse>("/search/live-lookup", {
    method: "POST",
    body: JSON.stringify({ query }),
  });
}

// ─── Dashboard ──────────────────────────────────────────
export async function getDashboard() {
  return fetcher<import("@/types").DashboardData>("/dashboard");
}

export async function getDashboardInsights() {
  return fetcher<import("@/types").DashboardInsights>("/dashboard/insights");
}

export async function getInsightDetail(type: string, name: string) {
  return fetcher<import("@/types").InsightDetail>(
    `/dashboard/insights/detail?type=${encodeURIComponent(type)}&name=${encodeURIComponent(name)}`
  );
}

export async function getAllInsights(type: string) {
  return fetcher<import("@/types").AllInsightEntity[]>(
    `/dashboard/insights/all?type=${encodeURIComponent(type)}`
  );
}

// ─── User ───────────────────────────────────────────────
export async function getCurrentUser() {
  return fetcher<import("@/types").User>("/me");
}

// ─── Health ─────────────────────────────────────────────
export async function getHealth() {
  return fetcher<{ status: string; version: string }>("/health");
}

export async function getStatusBar() {
  return fetcher<import("@/types").StatusBarData>("/status/bar");
}

// ─── Admin ──────────────────────────────────────────────
export async function triggerFeed(feedName: string) {
  return fetcher<{ status: string; job_id: string }>(`/feeds/${feedName}/trigger`, {
    method: "POST",
  });
}

export async function triggerAllFeeds() {
  return fetcher<{ status: string; job_id: string }>("/feeds/trigger-all", {
    method: "POST",
  });
}

export async function getFeedStatus() {
  return fetcher<import("@/types").FeedStatus[]>("/feeds/status");
}

// ─── MITRE ATT&CK ──────────────────────────────────────
export async function getAttackMatrix() {
  return fetcher<import("@/types").AttackMatrixResponse>("/techniques/matrix");
}

export async function getAttackTechniques(params: Record<string, string | number | boolean | undefined> = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== "") query.set(k, String(v));
  });
  return fetcher<import("@/types").AttackTechniqueListResponse>(`/techniques?${query}`);
}

export async function getAttackTechniqueDetail(id: string) {
  return fetcher<{
    technique: import("@/types").AttackTechnique;
    intel_items: import("@/types").IntelItem[];
    subtechniques: import("@/types").AttackTechnique[];
    intel_count: number;
  }>(`/techniques/${id}`);
}

export async function getIntelAttackLinks(itemId: string) {
  return fetcher<import("@/types").IntelAttackLink[]>(`/techniques/intel/${itemId}/techniques`);
}

// ─── Relationship Graph ─────────────────────────────────
export async function getGraphExplore(params: {
  entity_id: string;
  entity_type?: string;
  depth?: number;
  limit?: number;
}) {
  const query = new URLSearchParams();
  query.set("entity_id", params.entity_id);
  if (params.entity_type) query.set("entity_type", params.entity_type);
  if (params.depth) query.set("depth", String(params.depth));
  if (params.limit) query.set("limit", String(params.limit));
  return fetcher<import("@/types").GraphResponse>(`/graph/explore?${query}`);
}

export async function getRelatedIntel(itemId: string, limit = 20) {
  return fetcher<import("@/types").RelatedIntelItem[]>(`/graph/related/${itemId}?limit=${limit}`);
}

export async function getIntelEnrichment(itemId: string) {
  return fetcher<import("@/types").IntelEnrichment>(`/intel/${itemId}/enrichment`);
}

export async function getIntelRelated(itemId: string, limit = 20) {
  return fetcher<import("@/types").RelatedIntelItemEnriched[]>(`/intel/${itemId}/related?limit=${limit}`);
}

export interface IntelLinkedIOC {
  id: string;
  value: string;
  ioc_type: string;
  risk_score: number;
  first_seen: string | null;
  last_seen: string | null;
  sighting_count: number;
  tags: string[];
  geo: string[];
  source_names: string[];
  relationship: string;
  country_code: string | null;
  country: string | null;
  asn: string | null;
  as_name: string | null;
  ports: number[];
  vulns: string[];
  cpes: string[];
  hostnames: string[];
  internetdb_tags: string[];
  epss_score: number | null;
  epss_percentile: number | null;
}

export async function getIntelIOCs(itemId: string, limit = 50) {
  return fetcher<IntelLinkedIOC[]>(`/intel/${itemId}/iocs?limit=${limit}`);
}

export async function getGraphStats() {
  return fetcher<import("@/types").GraphStatsResponse>("/graph/stats");
}

// ─── Notifications ──────────────────────────────────────
export async function getNotifications(params: {
  unread_only?: boolean;
  category?: string;
  limit?: number;
  offset?: number;
} = {}) {
  const query = new URLSearchParams();
  if (params.unread_only) query.set("unread_only", "true");
  if (params.category) query.set("category", params.category);
  if (params.limit) query.set("limit", String(params.limit));
  if (params.offset) query.set("offset", String(params.offset));
  return fetcher<import("@/types").NotificationListResponse>(`/notifications?${query}`);
}

export async function getUnreadCount() {
  return fetcher<{ unread_count: number }>("/notifications/unread-count");
}

export async function getNotificationStats() {
  return fetcher<import("@/types").NotificationStats>("/notifications/stats");
}

export async function markNotificationsRead(notificationIds: string[]) {
  return fetcher<{ marked: number }>("/notifications/mark-read", {
    method: "POST",
    body: JSON.stringify({ notification_ids: notificationIds }),
  });
}

export async function markAllNotificationsRead() {
  return fetcher<{ marked: number }>("/notifications/mark-all-read", {
    method: "POST",
  });
}

export async function deleteNotification(id: string) {
  return fetcher<{ deleted: boolean }>(`/notifications/${id}`, {
    method: "DELETE",
  });
}

export async function clearAllNotifications() {
  return fetcher<{ cleared: number }>("/notifications", {
    method: "DELETE",
  });
}

export async function getNotificationRules() {
  return fetcher<import("@/types").NotificationRule[]>("/notifications/rules");
}

export async function createNotificationRule(data: import("@/types").NotificationRuleCreate) {
  return fetcher<import("@/types").NotificationRule>("/notifications/rules", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function updateNotificationRule(id: string, data: Partial<import("@/types").NotificationRuleCreate>) {
  return fetcher<import("@/types").NotificationRule>(`/notifications/rules/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function deleteNotificationRule(id: string) {
  return fetcher<{ deleted: boolean }>(`/notifications/rules/${id}`, {
    method: "DELETE",
  });
}

export async function toggleNotificationRule(id: string) {
  return fetcher<import("@/types").NotificationRule>(`/notifications/rules/${id}/toggle`, {
    method: "POST",
  });
}

// ─── Reports ────────────────────────────────────────────
export async function getReports(params: Record<string, string | number | undefined> = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== "") query.set(k, String(v));
  });
  return fetcher<import("@/types").ReportListResponse>(`/reports?${query}`);
}

export async function getReport(id: string) {
  return fetcher<import("@/types").Report>(`/reports/${id}`);
}

export async function createReport(data: import("@/types").ReportCreate) {
  return fetcher<import("@/types").Report>("/reports", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function updateReport(id: string, data: import("@/types").ReportUpdate) {
  return fetcher<import("@/types").Report>(`/reports/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function deleteReport(id: string) {
  return fetcher<{ deleted: boolean }>(`/reports/${id}`, {
    method: "DELETE",
  });
}

export async function getReportTemplates() {
  return fetcher<Record<string, import("@/types").ReportTemplate>>("/reports/templates");
}

export async function getReportStats() {
  return fetcher<import("@/types").ReportStats>("/reports/stats");
}

export async function addReportItem(reportId: string, data: {
  item_type: string;
  item_id: string;
  item_title?: string;
  item_metadata?: Record<string, unknown>;
  notes?: string;
}) {
  return fetcher<import("@/types").ReportItem>(`/reports/${reportId}/items`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function removeReportItem(reportId: string, itemId: string) {
  return fetcher<{ deleted: boolean }>(`/reports/${reportId}/items/${itemId}`, {
    method: "DELETE",
  });
}

export async function generateReportAISummary(reportId: string, includeLinkedItems = true) {
  return fetcher<{ summary: string }>(`/reports/${reportId}/ai-summary`, {
    method: "POST",
    body: JSON.stringify({ include_linked_items: includeLinkedItems }),
  });
}

export async function generateReportAISections(reportId: string, includeLinkedItems = true) {
  return fetcher<{ summary: string; sections: Array<{ key: string; title: string; hint?: string; body: string }> }>(
    `/reports/${reportId}/ai-generate`,
    {
      method: "POST",
      body: JSON.stringify({ include_linked_items: includeLinkedItems }),
    }
  );
}

export async function exportReport(reportId: string, format = "markdown", includeTlpWatermark = true) {
  const query = new URLSearchParams({ format, include_tlp_watermark: String(includeTlpWatermark) });
  return `${API_PREFIX}/reports/${reportId}/export?${query}`;
}

// ─── Settings ───────────────────────────────────────────

// ─── IOC Database ───────────────────────────────────────
export interface IOCItem {
  id: string;
  value: string;
  ioc_type: string;
  risk_score: number;
  first_seen: string | null;
  last_seen: string | null;
  sighting_count: number;
  tags: string[];
  geo: string[];
  source_names: string[];
  context: Record<string, unknown>;
  created_at: string | null;
  linked_intel_count: number;
  // IPinfo enrichment
  asn: string | null;
  as_name: string | null;
  as_domain: string | null;
  country_code: string | null;
  country: string | null;
  continent_code: string | null;
  continent: string | null;
  enriched_at: string | null;
}

export interface IOCListResponse {
  items: IOCItem[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface IOCStatsResponse {
  total_iocs: number;
  type_distribution: Array<{ name: string; count: number }>;
  risk_distribution: Record<string, number>;
  source_distribution: Array<{ name: string; count: number }>;
  unique_sources: number;
  avg_risk_score: number;
  recent_24h: number;
  high_risk_count: number;
  top_risky: Array<{
    id: string;
    value: string;
    ioc_type: string;
    risk_score: number;
    tags: string[];
    source_names: string[];
    last_seen: string | null;
    sighting_count: number;
  }>;
  tag_distribution: Array<{ name: string; count: number }>;
  geo_distribution: Array<{ name: string; count: number }>;
  // IPinfo enrichment stats
  country_distribution: Array<{ name: string; code: string; count: number }>;
  asn_distribution: Array<{ asn: string; name: string; count: number }>;
  continent_distribution: Array<{ name: string; code: string; count: number }>;
  enrichment_coverage: { enriched: number; total_ips: number };
}

export async function getIOCs(params: {
  page?: number;
  page_size?: number;
  search?: string;
  ioc_type?: string;
  min_risk?: number;
  max_risk?: number;
  source?: string;
  country_code?: string;
  asn?: string;
  sort_by?: string;
  sort_dir?: string;
} = {}): Promise<IOCListResponse> {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") query.set(k, String(v));
  });
  return fetcher<IOCListResponse>(`/iocs?${query}`);
}

export async function getIOCStats(): Promise<IOCStatsResponse> {
  return fetcher<IOCStatsResponse>("/iocs/stats");
}

export interface IOCEnrichmentResult {
  virustotal: Record<string, unknown> | null;
  shodan: Record<string, unknown> | null;
  errors: string[];
}

export async function enrichIOC(value: string, ioc_type: string): Promise<IOCEnrichmentResult> {
  const query = new URLSearchParams({ value, ioc_type });
  return fetcher<IOCEnrichmentResult>(`/iocs/enrich?${query}`);
}

// ─── Settings (cont'd) ────────────────────────────────── 
export async function getUserSettings() {
  return fetcher<{ settings: Record<string, unknown> }>("/settings");
}

export async function updateUserSettings(settings: Record<string, unknown>) {
  return fetcher<{ settings: Record<string, unknown> }>("/settings", {
    method: "PUT",
    body: JSON.stringify({ settings }),
  });
}

export async function getApiKeyStatus() {
  return fetcher<{
    keys: Array<{
      name: string;
      configured: boolean;
      masked: string;
      model?: string | null;
    }>;
    configured_count: number;
    total_count: number;
  }>("/settings/api-keys");
}

export async function getPlatformInfo() {
  return fetcher<{
    version: string;
    environment: string;
    domain: string;
    domain_ui: string;
    domain_api: string;
    ai_enabled: boolean;
    ai_model: string | null;
    total_feeds: number;
    active_feeds: number;
  }>("/settings/platform-info");
}

// ─── Cyber News ─────────────────────────────────────────
export async function getNews(params: {
  page?: number;
  page_size?: number;
  category?: string;
  tag?: string;
  search?: string;
  min_relevance?: number;
  ai_enriched?: boolean;
  sort_by?: string;
  sort_order?: string;
} = {}): Promise<import("@/types").NewsListResponse> {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") query.set(k, String(v));
  });
  return fetcher<import("@/types").NewsListResponse>(`/news?${query}`);
}

export async function getNewsItem(id: string): Promise<import("@/types").NewsItem> {
  return fetcher<import("@/types").NewsItem>(`/news/${id}`);
}

export async function getNewsCategories(): Promise<import("@/types").NewsCategoriesResponse> {
  return fetcher<import("@/types").NewsCategoriesResponse>("/news/categories");
}

export async function getNewsStats(): Promise<import("@/types").NewsStatsResponse> {
  return fetcher<import("@/types").NewsStatsResponse>("/news/stats");
}

export async function getIntelStats(): Promise<import("@/types").IntelStatsResponse> {
  return fetcher<import("@/types").IntelStatsResponse>("/intel/stats");
}

export async function getNewsFeedStatus(): Promise<import("@/types").NewsFeedStatus[]> {
  return fetcher<import("@/types").NewsFeedStatus[]>("/news/feed-status");
}

export async function getNewsPipelineStatus(): Promise<import("@/types").NewsPipelineStatus> {
  return fetcher<import("@/types").NewsPipelineStatus>("/news/pipeline-status");
}

export async function refreshNews(): Promise<{ status: string; job_id: string }> {
  return fetcher<{ status: string; job_id: string }>("/news/refresh", {
    method: "POST",
  });
}

export async function downloadNewsReport(
  id: string,
  format: "pdf" | "html" | "markdown" = "pdf",
): Promise<void> {
  const response = await fetch(`/api/v1/news/${id}/report?format=${format}`, {
    credentials: "include",
  });
  if (!response.ok) throw new Error("Failed to generate report");
  const blob = await response.blob();
  const ext = format === "pdf" ? "pdf" : format === "html" ? "html" : "md";
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download =
    response.headers
      .get("Content-Disposition")
      ?.split("filename=")[1]
      ?.replace(/"/g, "") || `IntelWatch-Report.${ext}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ─── Intelligence Extraction ────────────────────────────

export async function getVulnerableProducts(params: {
  search?: string;
  severity?: string;
  sort_by?: string;
  sort_order?: string;
  limit?: number;
  window?: string;
} = {}): Promise<import("@/types").VulnerableProductsListResponse> {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") query.set(k, String(v));
  });
  return fetcher<import("@/types").VulnerableProductsListResponse>(`/news/vulnerable-products?${query}`);
}

export async function getThreatCampaigns(params: {
  search?: string;
  severity?: string;
  sort_by?: string;
  sort_order?: string;
  limit?: number;
  window?: string;
} = {}): Promise<import("@/types").ThreatCampaignsListResponse> {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") query.set(k, String(v));
  });
  return fetcher<import("@/types").ThreatCampaignsListResponse>(`/news/threat-campaigns?${query}`);
}

export async function getExtractionStats(): Promise<import("@/types").ExtractionStatsResponse> {
  return fetcher<import("@/types").ExtractionStatsResponse>("/news/extraction-stats");
}

export function getExtractionExportUrl(type: "vulnerable-products" | "threat-campaigns", format: "csv" | "json", window?: string): string {
  const params = new URLSearchParams({ format });
  if (window) params.set("window", window);
  return `${API_PREFIX}/news/${type}/export?${params}`;
}

export async function bulkCveLookup(cves: string[]): Promise<{
  requested: number;
  found: number;
  missing: string[];
  results: Record<string, import("@/types").VulnerableProduct>;
}> {
  return fetcher(`/news/cve-lookup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cves }),
  });
}

export async function getVendorStats(): Promise<Array<{
  vendor: string;
  count: number;
  critical: number;
  high: number;
  kev_count: number;
}>> {
  return fetcher("/news/vendor-stats");
}

export async function toggleFalsePositive(
  type: "vulnerable-products" | "threat-campaigns",
  id: string,
  value: boolean
): Promise<{ id: string; is_false_positive: boolean }> {
  return fetcher(`/news/${type}/${id}/false-positive?value=${value}`, {
    method: "PATCH",
  });
}

// ─── Cases / Incident Management ────────────────────────
export async function getCases(params: {
  page?: number;
  page_size?: number;
  status?: string;
  priority?: string;
  case_type?: string;
  assignee_id?: string;
  search?: string;
  sort_by?: string;
  sort_order?: string;
  severity?: string;
  tlp?: string;
  date_from?: string;
  date_to?: string;
  tag?: string;
} = {}): Promise<import("@/types").CaseListResponse> {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") query.set(k, String(v));
  });
  return fetcher<import("@/types").CaseListResponse>(`/cases?${query}`);
}

export async function getCase(id: string): Promise<import("@/types").Case> {
  return fetcher<import("@/types").Case>(`/cases/${id}`);
}

export async function createCase(data: import("@/types").CaseCreate): Promise<import("@/types").Case> {
  return fetcher<import("@/types").Case>("/cases", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function updateCase(id: string, data: import("@/types").CaseUpdate): Promise<import("@/types").Case> {
  return fetcher<import("@/types").Case>(`/cases/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function deleteCase(id: string): Promise<{ deleted: boolean }> {
  return fetcher<{ deleted: boolean }>(`/cases/${id}`, {
    method: "DELETE",
  });
}

export async function getCaseStats(): Promise<import("@/types").CaseStats> {
  return fetcher<import("@/types").CaseStats>("/cases/stats");
}

export async function addCaseItem(caseId: string, data: {
  item_type: string;
  item_id: string;
  item_title?: string;
  item_metadata?: Record<string, unknown>;
  notes?: string;
}): Promise<import("@/types").CaseItem> {
  return fetcher<import("@/types").CaseItem>(`/cases/${caseId}/items`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function removeCaseItem(caseId: string, itemId: string): Promise<{ deleted: boolean }> {
  return fetcher<{ deleted: boolean }>(`/cases/${caseId}/items/${itemId}`, {
    method: "DELETE",
  });
}

export async function addCaseComment(caseId: string, comment: string): Promise<import("@/types").CaseActivity> {
  return fetcher<import("@/types").CaseActivity>(`/cases/${caseId}/comments`, {
    method: "POST",
    body: JSON.stringify({ comment }),
  });
}

export async function getCaseAssignees(): Promise<import("@/types").Assignee[]> {
  return fetcher<import("@/types").Assignee[]>("/cases/assignees");
}

export async function bulkUpdateCaseStatus(caseIds: string[], status: string): Promise<{ updated: number }> {
  return fetcher<{ updated: number }>("/cases/bulk/status", {
    method: "POST",
    body: JSON.stringify({ case_ids: caseIds, status }),
  });
}

export async function bulkAssignCases(caseIds: string[], assigneeId: string | null): Promise<{ updated: number }> {
  return fetcher<{ updated: number }>("/cases/bulk/assign", {
    method: "POST",
    body: JSON.stringify({ case_ids: caseIds, assignee_id: assigneeId }),
  });
}

export async function bulkDeleteCases(caseIds: string[]): Promise<{ deleted: number }> {
  return fetcher<{ deleted: number }>("/cases/bulk/delete", {
    method: "POST",
    body: JSON.stringify({ case_ids: caseIds }),
  });
}

export function getCaseExportUrl(format: "json" | "csv", ids?: string[]): string {
  const base = `${process.env.NEXT_PUBLIC_API_URL || "/api/v1"}/cases/export?format=${format}`;
  if (ids && ids.length > 0) return `${base}&ids=${ids.join(",")}`;
  return base;
}

export async function cloneCase(caseId: string, overrides?: { title?: string; description?: string }): Promise<import("@/types").Case> {
  return fetcher<import("@/types").Case>(`/cases/${caseId}/clone`, {
    method: "POST",
    body: JSON.stringify(overrides || {}),
  });
}

// ─── Cross-Enrichment ───────────────────────────────────

export async function getDashboardEnrichment(days?: number): Promise<import("@/types").DashboardEnrichment> {
  const q = days ? `?days=${days}` : "";
  return fetcher<import("@/types").DashboardEnrichment>(`/enrichment/dashboard${q}`);
}

export async function getIntelCampaignContext(cveIds: string[], products: string[]): Promise<import("@/types").IntelCampaignContext> {
  return fetcher<import("@/types").IntelCampaignContext>("/enrichment/intel-context", {
    method: "POST",
    body: JSON.stringify({ cve_ids: cveIds, products }),
  });
}

export async function getIntelBatchEnrichment(itemIds: string[]): Promise<import("@/types").IntelBatchEnrichment> {
  return fetcher<import("@/types").IntelBatchEnrichment>("/enrichment/intel-batch", {
    method: "POST",
    body: JSON.stringify({ item_ids: itemIds }),
  });
}

export async function getIOCCampaignContext(value: string): Promise<import("@/types").IOCCampaignContext> {
  return fetcher<import("@/types").IOCCampaignContext>(`/enrichment/ioc-context?value=${encodeURIComponent(value)}`);
}

export async function getTechniqueUsage(days?: number): Promise<import("@/types").TechniqueUsageItem[]> {
  const q = days ? `?days=${days}` : "";
  return fetcher<import("@/types").TechniqueUsageItem[]>(`/enrichment/technique-usage${q}`);
}

export async function getTechniqueDetailEnrichment(techniqueId: string): Promise<import("@/types").TechniqueDetailEnrichment> {
  return fetcher<import("@/types").TechniqueDetailEnrichment>(`/enrichment/technique-detail?technique_id=${encodeURIComponent(techniqueId)}`);
}

export async function getThreatVelocity(): Promise<import("@/types").ThreatVelocityItem[]> {
  return fetcher<import("@/types").ThreatVelocityItem[]>("/enrichment/velocity");
}

export async function getOrgExposure(sectors: string[], regions: string[], techStack: string[]): Promise<import("@/types").OrgExposure> {
  return fetcher<import("@/types").OrgExposure>("/enrichment/org-exposure", {
    method: "POST",
    body: JSON.stringify({ sectors, regions, tech_stack: techStack }),
  });
}

export async function getDetectionRules(params: {
  rule_type?: string;
  severity?: string;
  campaign?: string;
  technique_id?: string;
  limit?: number;
  offset?: number;
} = {}): Promise<import("@/types").DetectionRule[]> {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") query.set(k, String(v));
  });
  return fetcher<import("@/types").DetectionRule[]>(`/enrichment/detection-rules?${query}`);
}

export async function getDetectionCoverage(): Promise<import("@/types").DetectionCoverage> {
  return fetcher<import("@/types").DetectionCoverage>("/enrichment/detection-coverage");
}

export async function syncDetectionRules(): Promise<{ synced: number }> {
  return fetcher<{ synced: number }>("/enrichment/detection-rules/sync", { method: "POST" });
}

export async function generateBriefing(days?: number): Promise<Record<string, unknown>> {
  return fetcher<Record<string, unknown>>("/enrichment/generate-briefing", {
    method: "POST",
    body: JSON.stringify({ days: days || 7 }),
  });
}

export async function getBriefings(limit?: number): Promise<import("@/types").ThreatBriefingSummary[]> {
  const q = limit ? `?limit=${limit}` : "";
  return fetcher<import("@/types").ThreatBriefingSummary[]>(`/enrichment/briefings${q}`);
}

// ─── AI Settings (Admin) ────────────────────────────────

export async function getAISettings(): Promise<import("@/types").AISettings> {
  return fetcher<import("@/types").AISettings>("/ai-settings");
}

export async function updateAISettings(data: Partial<import("@/types").AISettings>): Promise<import("@/types").AISettings> {
  return fetcher<import("@/types").AISettings>("/ai-settings", {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function testAIProvider(params: {
  url: string;
  key: string;
  model: string;
  provider_type?: string;
}): Promise<{ success: boolean; status: number; response?: string; error?: string }> {
  return fetcher<{ success: boolean; status: number; response?: string; error?: string }>("/ai-settings/test-provider", {
    method: "POST",
    body: JSON.stringify(params),
  });
}

export async function getAIUsage(): Promise<import("@/types").AIUsage> {
  return fetcher<import("@/types").AIUsage>("/ai-settings/usage");
}

export async function resetAIUsage(): Promise<{ status: string }> {
  return fetcher<{ status: string }>("/ai-settings/reset-usage", { method: "POST" });
}

export async function getAIDefaults(): Promise<Record<string, unknown>> {
  return fetcher<Record<string, unknown>>("/ai-settings/defaults");
}

export async function resetAIDefaults(): Promise<import("@/types").AISettings> {
  return fetcher<import("@/types").AISettings>("/ai-settings/reset-defaults", { method: "POST" });
}

export async function getAIHealth(): Promise<import("@/types").AIHealthStatus> {
  return fetcher<import("@/types").AIHealthStatus>("/ai-settings/health");
}

export async function promoteAIFallback(index: number): Promise<import("@/types").AISettings> {
  return fetcher<import("@/types").AISettings>("/ai-settings/promote-fallback", {
    method: "POST",
    body: JSON.stringify({ index }),
  });
}

export async function getAIDefaultPrompts(): Promise<Record<string, string>> {
  return fetcher<Record<string, string>>("/ai-settings/default-prompts");
}
