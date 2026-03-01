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
    auth_method: "google" | "cloudflare_sso" | "local";
    sso_login_url: string | null;
    cf_logout_url: string | null;
    cf_team_domain: string | null;
    google_client_id: string | null;
    app_name: string;
    environment: string;
    dev_bypass: boolean;
  }>("/auth/config");
}

export async function login() {
  return fetcher<{
    status: string;
    user: import("@/types").User;
  }>("/auth/login", { method: "POST" });
}

export async function googleLogin(credential: string) {
  return fetcher<{
    status: string;
    user: import("@/types").User;
  }>("/auth/google", {
    method: "POST",
    body: JSON.stringify({ credential }),
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
}

export async function getIOCs(params: {
  page?: number;
  page_size?: number;
  search?: string;
  ioc_type?: string;
  min_risk?: number;
  max_risk?: number;
  source?: string;
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
