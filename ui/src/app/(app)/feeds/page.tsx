"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useAppStore } from "@/store";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import * as api from "@/lib/api";
import type { NewsFeedStatus, NewsPipelineStatus } from "@/types";
import {
  Rss,
  CheckCircle2,
  XCircle,
  Clock,
  RefreshCw,
  AlertTriangle,
  Newspaper,
  ExternalLink,
  Timer,
  Wifi,
  WifiOff,
} from "lucide-react";

/* ── Status Helpers ─────────────────────────────────────── */

const STATUS_META: Record<
  string,
  { icon: React.ReactNode; color: string; bg: string; label: string }
> = {
  ok: {
    icon: <CheckCircle2 className="h-4 w-4" />,
    color: "#22c55e",
    bg: "rgba(34,197,94,0.1)",
    label: "OK",
  },
  success: {
    icon: <CheckCircle2 className="h-4 w-4" />,
    color: "#22c55e",
    bg: "rgba(34,197,94,0.1)",
    label: "OK",
  },
  active: {
    icon: <CheckCircle2 className="h-4 w-4" />,
    color: "#22c55e",
    bg: "rgba(34,197,94,0.1)",
    label: "ACTIVE",
  },
  error: {
    icon: <XCircle className="h-4 w-4" />,
    color: "#ef4444",
    bg: "rgba(239,68,68,0.1)",
    label: "ERROR",
  },
  timeout: {
    icon: <Timer className="h-4 w-4" />,
    color: "#f97316",
    bg: "rgba(249,115,22,0.1)",
    label: "TIMEOUT",
  },
  stale: {
    icon: <AlertTriangle className="h-4 w-4" />,
    color: "#eab308",
    bg: "rgba(234,179,8,0.1)",
    label: "STALE",
  },
  unknown: {
    icon: <Clock className="h-4 w-4" />,
    color: "#6b7280",
    bg: "rgba(107,114,128,0.1)",
    label: "UNKNOWN",
  },
};

function getStatusMeta(status: string) {
  return STATUS_META[status.toLowerCase()] ?? STATUS_META.unknown;
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "Never";
  const d = new Date(dateStr);
  const now = new Date();
  const secs = Math.floor((now.getTime() - d.getTime()) / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

/* ── Tab Type ───────────────────────────────────────────── */
type TabType = "intel" | "news";

export default function FeedStatusPage() {
  const { dashboard, dashboardLoading, fetchDashboard } = useAppStore();

  const [activeTab, setActiveTab] = useState<TabType>("intel");
  const [newsFeeds, setNewsFeeds] = useState<NewsFeedStatus[]>([]);
  const [newsLoading, setNewsLoading] = useState(false);
  const [pipelineStatus, setPipelineStatus] = useState<NewsPipelineStatus | null>(null);

  useEffect(() => {
    fetchDashboard();
    loadNewsFeeds();
    loadPipelineStatus();
  }, [fetchDashboard]);

  async function loadNewsFeeds() {
    setNewsLoading(true);
    try {
      const data = await api.getNewsFeedStatus();
      setNewsFeeds(data);
    } catch {
      // silent — show empty
    } finally {
      setNewsLoading(false);
    }
  }

  async function loadPipelineStatus() {
    try {
      const data = await api.getNewsPipelineStatus();
      setPipelineStatus(data);
    } catch { /* silent */ }
  }

  /* ── Intel Feeds data ─────────────────────────────── */
  const intelFeeds = useMemo(() => {
    if (!dashboard?.feed_status) return [];
    return dashboard.feed_status.map((fs) => ({
      name: fs.feed_name,
      status: fs.status || "unknown",
      last_run: fs.last_run || fs.last_success || null,
      items: fs.items_fetched ?? fs.items_stored ?? null,
      error: fs.error_message || null,
    }));
  }, [dashboard]);

  /* ── Stats ────────────────────────────────────────── */
  const intelHealthy = intelFeeds.filter(
    (f) => f.status === "ok" || f.status === "active" || f.status === "success"
  ).length;
  const intelErrored = intelFeeds.filter(
    (f) => f.status === "error" || f.status === "failed"
  ).length;

  const newsHealthy = newsFeeds.filter((f) => f.status === "ok").length;
  const newsErrored = newsFeeds.filter(
    (f) => f.status === "error" || f.status === "timeout"
  ).length;
  const newsUnknown = newsFeeds.filter((f) => f.status === "unknown").length;

  const loading =
    activeTab === "intel"
      ? dashboardLoading && !dashboard
      : newsLoading && newsFeeds.length === 0;

  if (loading) return <Loading text="Loading feed status..." />;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <Rss className="h-5 w-5 text-primary" />
            Feed Status
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Monitor threat intelligence and news feed connectors
          </p>
        </div>
        <button
          onClick={() => {
            fetchDashboard();
            loadNewsFeeds();
            loadPipelineStatus();
          }}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-primary/10 text-primary text-xs font-medium hover:bg-primary/20 transition-colors"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      {/* Tab Switcher */}
      <div className="flex gap-1 p-1 rounded-lg bg-muted/60 w-fit">
        <button
          onClick={() => setActiveTab("intel")}
          className={`flex items-center gap-1.5 px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${
            activeTab === "intel"
              ? "bg-background text-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          <Rss className="h-3.5 w-3.5" />
          Intel Feeds
          <span className="ml-1 text-[10px] opacity-60">({intelFeeds.length})</span>
        </button>
        <button
          onClick={() => setActiveTab("news")}
          className={`flex items-center gap-1.5 px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${
            activeTab === "news"
              ? "bg-background text-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          <Newspaper className="h-3.5 w-3.5" />
          News Feeds
          <span className="ml-1 text-[10px] opacity-60">({newsFeeds.length})</span>
        </button>
      </div>

      {/* ─── Intel Feeds Tab ───────────────────────────── */}
      {activeTab === "intel" && (
        <>
          {/* Stats */}
          <div className="grid grid-cols-3 gap-3">
            <Card className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg bg-primary/10">
                  <Rss className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Total Feeds</p>
                  <p className="text-xl font-bold">{intelFeeds.length}</p>
                </div>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: "rgba(34,197,94,0.1)" }}>
                  <CheckCircle2 className="h-5 w-5" style={{ color: "#22c55e" }} />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Healthy</p>
                  <p className="text-xl font-bold" style={{ color: "#22c55e" }}>
                    {intelHealthy}
                  </p>
                </div>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: "rgba(239,68,68,0.1)" }}>
                  <XCircle className="h-5 w-5" style={{ color: "#ef4444" }} />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Errors</p>
                  <p className="text-xl font-bold" style={{ color: "#ef4444" }}>
                    {intelErrored}
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Intel Feed Cards */}
          <div className="space-y-3">
            {intelFeeds.length === 0 ? (
              <Card>
                <CardContent className="py-12 text-center text-xs text-muted-foreground/60">
                  No feed connectors configured
                </CardContent>
              </Card>
            ) : (
              intelFeeds.map((feed) => {
                const meta = getStatusMeta(feed.status);
                return (
                  <Card key={feed.name} className="border-border/40 overflow-hidden">
                    <div className="h-1" style={{ background: meta.color }} />
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div
                            className="p-2 rounded-lg shrink-0"
                            style={{ background: meta.bg }}
                          >
                            <span style={{ color: meta.color }}>{meta.icon}</span>
                          </div>
                          <div>
                            <p className="text-sm font-semibold">
                              {feed.name
                                .replace(/_/g, " ")
                                .replace(/\b\w/g, (l: string) => l.toUpperCase())}
                            </p>
                            <div className="flex items-center gap-3 mt-0.5">
                              <Badge
                                variant="outline"
                                className="text-[10px]"
                                style={{ borderColor: meta.color, color: meta.color }}
                              >
                                {feed.status.toUpperCase()}
                              </Badge>
                              {feed.last_run && (
                                <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                                  <Clock className="h-3 w-3" />
                                  Last run: {new Date(feed.last_run).toLocaleString()}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          {feed.items !== null && (
                            <p className="text-lg font-bold">
                              {feed.items.toLocaleString()}
                            </p>
                          )}
                          <p className="text-[10px] text-muted-foreground">
                            {feed.items !== null ? "items ingested" : "—"}
                          </p>
                        </div>
                      </div>
                      {feed.error && (
                        <div className="mt-3 p-2 rounded-md bg-red-500/10 text-red-400 text-xs font-mono">
                          {feed.error}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })
            )}
          </div>
        </>
      )}

      {/* ─── News Feeds Tab ────────────────────────────── */}
      {activeTab === "news" && (
        <>
          {/* Pipeline Status Banner */}
          {pipelineStatus && pipelineStatus.status !== "ok" && (
            <div className={`flex items-center gap-2 px-3 py-2 rounded-md text-xs font-medium border ${
              pipelineStatus.status === "down"
                ? "bg-red-500/10 border-red-500/30 text-red-400"
                : pipelineStatus.status === "degraded"
                  ? "bg-orange-500/10 border-orange-500/30 text-orange-400"
                  : "bg-yellow-500/10 border-yellow-500/30 text-yellow-400"
            }`}>
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              <span>
                {pipelineStatus.status === "down"
                  ? "News pipeline is down — all feed sources are failing"
                  : pipelineStatus.status === "degraded"
                    ? `News pipeline degraded — ${pipelineStatus.total_sources_failing} sources failing, no new articles in the last hour`
                    : `No new cyber news in the last hour (${pipelineStatus.stored_last_24h} in last 24h)`}
              </span>
              {pipelineStatus.last_article_at && (
                <span className="text-muted-foreground ml-auto shrink-0">
                  Last article: {timeAgo(pipelineStatus.last_article_at)}
                </span>
              )}
            </div>
          )}

          {/* Stats */}
          <div className="grid grid-cols-4 gap-3">
            <Card className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg bg-primary/10">
                  <Newspaper className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Total Sources</p>
                  <p className="text-xl font-bold">{newsFeeds.length}</p>
                </div>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: "rgba(34,197,94,0.1)" }}>
                  <Wifi className="h-5 w-5" style={{ color: "#22c55e" }} />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Online</p>
                  <p className="text-xl font-bold" style={{ color: "#22c55e" }}>
                    {newsHealthy}
                  </p>
                </div>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: "rgba(239,68,68,0.1)" }}>
                  <WifiOff className="h-5 w-5" style={{ color: "#ef4444" }} />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Failing</p>
                  <p className="text-xl font-bold" style={{ color: "#ef4444" }}>
                    {newsErrored}
                  </p>
                </div>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: "rgba(107,114,128,0.1)" }}>
                  <Clock className="h-5 w-5" style={{ color: "#6b7280" }} />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Not Checked</p>
                  <p className="text-xl font-bold" style={{ color: "#6b7280" }}>
                    {newsUnknown}
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* News Feed Cards */}
          <div className="space-y-3">
            {newsFeeds.length === 0 ? (
              <Card>
                <CardContent className="py-12 text-center text-xs text-muted-foreground/60">
                  {newsLoading
                    ? "Loading news feed status..."
                    : "No news feed data yet — status will appear after the first fetch cycle"}
                </CardContent>
              </Card>
            ) : (
              newsFeeds.map((feed) => {
                const meta = getStatusMeta(feed.status);
                const hasConsecutiveFailures =
                  feed.consecutive_failures > 0 && feed.status !== "ok";
                return (
                  <Card
                    key={feed.source_name}
                    className="border-border/40 overflow-hidden"
                  >
                    <div className="h-1" style={{ background: meta.color }} />
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div
                            className="p-2 rounded-lg shrink-0"
                            style={{ background: meta.bg }}
                          >
                            <span style={{ color: meta.color }}>{meta.icon}</span>
                          </div>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <p className="text-sm font-semibold truncate">
                                {feed.source_name}
                              </p>
                              <a
                                href={feed.source_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-muted-foreground hover:text-primary transition-colors shrink-0"
                                title="Open feed URL"
                              >
                                <ExternalLink className="h-3 w-3" />
                              </a>
                            </div>
                            <div className="flex items-center gap-3 mt-0.5 flex-wrap">
                              <Badge
                                variant="outline"
                                className="text-[10px]"
                                style={{
                                  borderColor: meta.color,
                                  color: meta.color,
                                }}
                              >
                                {meta.label}
                              </Badge>
                              {hasConsecutiveFailures && (
                                <Badge
                                  variant="outline"
                                  className="text-[10px] border-red-500/40 text-red-400"
                                >
                                  {feed.consecutive_failures} consecutive failure
                                  {feed.consecutive_failures !== 1 ? "s" : ""}
                                </Badge>
                              )}
                              {feed.last_checked && (
                                <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                                  <Clock className="h-3 w-3" />
                                  Checked: {timeAgo(feed.last_checked)}
                                </span>
                              )}
                              {feed.last_success && (
                                <span className="text-[10px] text-emerald-500 flex items-center gap-1">
                                  <CheckCircle2 className="h-3 w-3" />
                                  Last OK: {timeAgo(feed.last_success)}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="text-right shrink-0 ml-3">
                          <p className="text-lg font-bold">
                            {feed.articles_last_fetch}
                          </p>
                          <p className="text-[10px] text-muted-foreground">
                            last fetch
                          </p>
                          {feed.total_articles > 0 && (
                            <p className="text-[10px] text-muted-foreground mt-0.5">
                              {feed.total_articles.toLocaleString()} total
                            </p>
                          )}
                        </div>
                      </div>
                      {feed.last_error && feed.status !== "ok" && (
                        <div className="mt-3 p-2 rounded-md bg-red-500/10 text-red-400 text-xs font-mono break-all">
                          {feed.last_error}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })
            )}
          </div>
        </>
      )}
    </div>
  );
}
