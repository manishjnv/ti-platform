"use client";

import React, { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  Clock,
  Database,
  Flame,
  Gauge,
  Grid3X3,
  Search,
  Server,
  Shield,
} from "lucide-react";
import { getStatusBar } from "@/lib/api";
import type { StatusBarData } from "@/types";

/* ─── helpers ─────────────────────────────────────────── */
function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function threatLevel(avg: number): { label: string; color: string; bg: string } {
  if (avg >= 75) return { label: "Critical", color: "text-red-400", bg: "bg-red-500/10" };
  if (avg >= 55) return { label: "High", color: "text-orange-400", bg: "bg-orange-500/10" };
  if (avg >= 35) return { label: "Medium", color: "text-amber-400", bg: "bg-amber-500/10" };
  return { label: "Low", color: "text-emerald-400", bg: "bg-emerald-500/10" };
}

/* ─── Inline sparkline (SVG) ─────────────────────────── */
function MiniSparkline({ data }: { data: number[] }) {
  if (!data.length) return null;
  const max = Math.max(...data, 1);
  const w = 56;
  const h = 16;
  const points = data.map((v, i) => {
    const x = (i / Math.max(data.length - 1, 1)) * w;
    const y = h - (v / max) * (h - 2) - 1;
    return `${x},${y}`;
  });
  return (
    <svg width={w} height={h} className="shrink-0">
      <polyline
        points={points.join(" ")}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
        className="text-emerald-400"
      />
    </svg>
  );
}

/* ─── Divider ─────────────────────────────────────────── */
const Sep = () => <div className="w-px h-5 bg-border/30 shrink-0" />;

/* ─── Pill wrapper ────────────────────────────────────── */
function Pill({
  children,
  className = "",
  title,
}: {
  children: React.ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <div
      title={title}
      className={`flex items-center gap-1 h-7 px-2 rounded-md text-[10px] font-medium shrink-0 ${className}`}
    >
      {children}
    </div>
  );
}

/* ─── Main component ──────────────────────────────────── */
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

  /* Loading / error states */
  if (error && !data) {
    return (
      <Pill className="bg-red-500/10 text-red-400">
        <AlertTriangle className="h-3 w-3" /> Offline
      </Pill>
    );
  }
  if (!data) {
    return (
      <div className="flex items-center gap-1.5 animate-pulse">
        {[48, 56, 40, 48, 40].map((w, i) => (
          <div key={i} className="h-5 rounded bg-muted/30" style={{ width: w }} />
        ))}
      </div>
    );
  }

  const isOk = data.status === "ok";
  const tl = threatLevel(data.avg_risk_score);
  const allUp = isOk && data.active_feeds > 0;

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {/* 1 ── System Health + Live ───────────────────── */}
      <div className="group relative">
        <Pill className={allUp ? "bg-emerald-500/10 text-emerald-400" : "bg-amber-500/10 text-amber-400"}>
          <span className="relative flex h-2 w-2 shrink-0">
            {allUp && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            )}
            <span className={`relative inline-flex rounded-full h-2 w-2 ${allUp ? "bg-emerald-500" : "bg-amber-500"}`} />
          </span>
          {allUp ? "Live" : "Degraded"}
        </Pill>
        <div className="absolute left-1/2 -translate-x-1/2 top-full mt-1 z-50 hidden group-hover:block">
          <div className="bg-popover border border-border/50 rounded-lg shadow-xl px-3 py-2 text-[10px] whitespace-nowrap space-y-1">
            <div className="flex items-center gap-2">
              <span className={data.postgres ? "text-emerald-400" : "text-red-400"}>●</span> Database
            </div>
            <div className="flex items-center gap-2">
              <span className={data.redis ? "text-emerald-400" : "text-red-400"}>●</span> Cache
            </div>
            <div className="flex items-center gap-2">
              <span className={data.opensearch ? "text-emerald-400" : "text-red-400"}>●</span> Search Index
            </div>
          </div>
        </div>
      </div>

      <Sep />

      {/* 2 ── Threat Level Gauge ─────────────────────── */}
      <Pill className={`${tl.bg} ${tl.color}`} title={`Avg risk score: ${data.avg_risk_score}`}>
        <Gauge className="h-3 w-3" />
        {tl.label}
      </Pill>

      <Sep />

      {/* 3 ── Total Intel + 24h delta ────────────────── */}
      <Pill className="bg-muted/20 text-muted-foreground" title="Total ingested intel items">
        <Database className="h-3 w-3" />
        <span className="text-foreground">{data.total_intel.toLocaleString()}</span>
        {data.intel_24h > 0 && (
          <span className="text-emerald-400">24h +{data.intel_24h.toLocaleString()}</span>
        )}
      </Pill>

      <Sep />

      {/* 4 ── Crit/High threats ──────────────────────── */}
      {(data.critical_count + data.high_count) > 0 && (
        <>
          <Pill className="bg-red-500/10 text-red-400">
            <Shield className="h-3 w-3" />
            {(data.critical_count + data.high_count).toLocaleString()}
            <span className="text-muted-foreground">Crit/High</span>
          </Pill>
          <Sep />
        </>
      )}

      {/* 5 ── Active CVEs / KEV ──────────────────────── */}
      {data.kev_count > 0 && (
        <>
          <Pill className="bg-orange-500/10 text-orange-400" title="Known Exploited Vulnerabilities (CISA KEV)">
            <Flame className="h-3 w-3" />
            {data.kev_count} KEV
          </Pill>
          <Sep />
        </>
      )}

      {/* 6 ── Feed Sparkline ─────────────────────────── */}
      {data.sparkline && data.sparkline.length > 0 && (
        <>
          <div className="group relative flex items-center gap-1 h-7 px-2 rounded-md bg-muted/20 shrink-0">
            <MiniSparkline data={data.sparkline} />
            <div className="absolute left-1/2 -translate-x-1/2 top-full mt-1 z-50 hidden group-hover:block">
              <div className="bg-popover border border-border/50 rounded-lg shadow-xl px-3 py-1.5 text-[10px] whitespace-nowrap text-muted-foreground">
                Ingestion volume (24h hourly)
              </div>
            </div>
          </div>
          <Sep />
        </>
      )}

      {/* 7 ── Last Feed ──────────────────────────────── */}
      {data.last_feed_at && (
        <>
          <Pill className="bg-muted/20 text-muted-foreground" title="Last successful feed ingestion">
            <Clock className="h-3 w-3" />
            <span className="text-foreground">{timeAgo(data.last_feed_at)}</span>
          </Pill>
          <Sep />
        </>
      )}

      {/* 8 ── ATT&CK Coverage ────────────────────────── */}
      <Link href="/techniques" className="no-underline">
        <Pill className="bg-violet-500/10 text-violet-400 hover:bg-violet-500/20 transition-colors cursor-pointer" title="MITRE ATT&CK technique coverage">
          <Grid3X3 className="h-3 w-3" />
          {data.attack_coverage_pct}%
        </Pill>
      </Link>

      {/* 9 ── Search Stats ───────────────────────────── */}
      {data.searches_today > 0 && (
        <>
          <Sep />
          <Pill className="bg-muted/20 text-muted-foreground" title="Searches performed today">
            <Search className="h-3 w-3" />
            <span className="text-foreground">{data.searches_today}</span>
            today
          </Pill>
        </>
      )}

    </div>
  );
}
