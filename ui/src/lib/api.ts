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

// ─── Dashboard ──────────────────────────────────────────
export async function getDashboard() {
  return fetcher<import("@/types").DashboardData>("/dashboard");
}

// ─── User ───────────────────────────────────────────────
export async function getCurrentUser() {
  return fetcher<import("@/types").User>("/me");
}

// ─── Health ─────────────────────────────────────────────
export async function getHealth() {
  return fetcher<{ status: string; version: string }>("/health");
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
