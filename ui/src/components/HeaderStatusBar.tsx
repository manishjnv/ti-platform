"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  Database,
  Shield,
  AlertTriangle,
  Clock,
  Server,
} from "lucide-react";
import { getStatusBar } from "@/lib/api";
import type { StatusBarData } from "@/types";

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function HeaderStatusBar() {
  const [data, setData] = useState<StatusBarData | null>(null);
  const [error, setError] = useState(false);

  const fetchStatus = useCallback(async () => {
    try {
      const d = await getStatusBar();
      setData(d);
      setError(false);
    } catch {
      setError(true);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const id = setInterval(fetchStatus, 30_000);
    return () => clearInterval(id);
  }, [fetchStatus]);

  if (error && !data) {
    return (
      <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-red-500/10 text-red-400 text-[10px] font-medium">
        <AlertTriangle className="h-3 w-3" />
        Offline
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center gap-2 animate-pulse">
        <div className="h-5 w-16 rounded bg-muted/30" />
        <div className="h-5 w-20 rounded bg-muted/30" />
        <div className="h-5 w-16 rounded bg-muted/30" />
      </div>
    );
  }

  const isOk = data.status === "ok";
  const servicesDown = [
    !data.postgres && "PG",
    !data.redis && "Redis",
    !data.opensearch && "OS",
  ].filter(Boolean);

  const threatCount = data.critical_count + data.high_count;

  return (
    <div className="flex items-center gap-1.5">
      {/* System health pill */}
      <div
        className={`group relative flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium cursor-default transition-colors ${
          isOk
            ? "bg-emerald-500/10 text-emerald-400"
            : "bg-amber-500/10 text-amber-400"
        }`}
      >
        <Server className="h-3 w-3" />
        {isOk ? "Healthy" : "Degraded"}
        {/* Tooltip */}
        <div className="absolute left-1/2 -translate-x-1/2 top-full mt-1.5 z-50 hidden group-hover:block">
          <div className="bg-popover border border-border/50 rounded-lg shadow-xl px-3 py-2 text-[10px] whitespace-nowrap">
            <div className="flex items-center gap-2 mb-1">
              <span className={data.postgres ? "text-emerald-400" : "text-red-400"}>●</span>
              PostgreSQL
            </div>
            <div className="flex items-center gap-2 mb-1">
              <span className={data.redis ? "text-emerald-400" : "text-red-400"}>●</span>
              Redis
            </div>
            <div className="flex items-center gap-2">
              <span className={data.opensearch ? "text-emerald-400" : "text-red-400"}>●</span>
              OpenSearch
            </div>
          </div>
        </div>
      </div>

      <div className="w-px h-4 bg-border/30" />

      {/* Total intel */}
      <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-muted/20 text-[10px] text-muted-foreground font-medium">
        <Database className="h-3 w-3" />
        <span className="text-foreground">{data.total_intel.toLocaleString()}</span>
        Intel
        {data.intel_24h > 0 && (
          <span className="text-emerald-400 ml-0.5">+{data.intel_24h}</span>
        )}
      </div>

      {/* Critical+High threats */}
      {threatCount > 0 && (
        <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-red-500/10 text-[10px] font-medium text-red-400">
          <Shield className="h-3 w-3" />
          {threatCount.toLocaleString()}
          <span className="text-muted-foreground">Crit/High</span>
        </div>
      )}

      {/* Last feed */}
      {data.last_feed_at && (
        <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-muted/20 text-[10px] text-muted-foreground font-medium">
          <Clock className="h-3 w-3" />
          <span className="text-foreground">{timeAgo(data.last_feed_at)}</span>
        </div>
      )}
    </div>
  );
}
