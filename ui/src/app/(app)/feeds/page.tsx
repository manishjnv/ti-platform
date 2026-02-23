"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useAppStore } from "@/store";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import {
  Rss,
  CheckCircle2,
  XCircle,
  Clock,
  RefreshCw,
  AlertTriangle,
  ArrowUpDown,
} from "lucide-react";

const STATUS_META: Record<
  string,
  { icon: React.ReactNode; color: string; bg: string }
> = {
  ok: {
    icon: <CheckCircle2 className="h-4 w-4" />,
    color: "#22c55e",
    bg: "rgba(34,197,94,0.1)",
  },
  active: {
    icon: <CheckCircle2 className="h-4 w-4" />,
    color: "#22c55e",
    bg: "rgba(34,197,94,0.1)",
  },
  error: {
    icon: <XCircle className="h-4 w-4" />,
    color: "#ef4444",
    bg: "rgba(239,68,68,0.1)",
  },
  stale: {
    icon: <AlertTriangle className="h-4 w-4" />,
    color: "#eab308",
    bg: "rgba(234,179,8,0.1)",
  },
  unknown: {
    icon: <Clock className="h-4 w-4" />,
    color: "#6b7280",
    bg: "rgba(107,114,128,0.1)",
  },
};

function getStatusMeta(status: string) {
  return STATUS_META[status.toLowerCase()] ?? STATUS_META.unknown;
}

export default function FeedStatusPage() {
  const { dashboard, dashboardLoading, fetchDashboard } = useAppStore();

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  const feeds = useMemo(() => {
    if (!dashboard?.feed_status) return [];
    return dashboard.feed_status.map((fs) => ({
      name: fs.feed_name,
      status: fs.status || "unknown",
      last_run: fs.last_run || fs.last_success || null,
      items: fs.items_fetched ?? fs.items_stored ?? null,
      error: fs.error_message || null,
    }));
  }, [dashboard]);

  const healthy = feeds.filter(
    (f) => f.status === "ok" || f.status === "active"
  ).length;
  const errored = feeds.filter((f) => f.status === "error").length;

  if (dashboardLoading && !dashboard) return <Loading text="Loading feed status..." />;

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
            Monitor and manage threat intelligence feed connectors
          </p>
        </div>
        <button
          onClick={() => fetchDashboard()}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-primary/10 text-primary text-xs font-medium hover:bg-primary/20 transition-colors"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        <Card className="border-border/50">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Rss className="h-5 w-5 text-primary" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Total Feeds</p>
              <p className="text-xl font-bold">{feeds.length}</p>
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
                {healthy}
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
                {errored}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Feed Cards */}
      <div className="space-y-3">
        {feeds.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center text-xs text-muted-foreground/60">
              No feed connectors configured
            </CardContent>
          </Card>
        ) : (
          feeds.map((feed) => {
            const meta = getStatusMeta(feed.status);
            return (
              <Card key={feed.name} className="border-border/40 overflow-hidden">
                <div
                  className="h-1"
                  style={{ background: meta.color }}
                />
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
                        <p className="text-lg font-bold">{feed.items.toLocaleString()}</p>
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
    </div>
  );
}
