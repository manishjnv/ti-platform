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
  Shield,
  TrendingUp,
  TrendingDown,
  Minus,
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

type ThreatInfo = { label: string; iconBg: string; iconText: string; pillBg: string; pillText: string; glow: string };
function threatLevel(avg: number): ThreatInfo {
  if (avg >= 75) return { label: "Critical", iconBg: "bg-red-500/20 dark:bg-red-500/25", iconText: "text-red-600 dark:text-red-400", pillBg: "bg-red-50 dark:bg-red-500/10 border-red-200/60 dark:border-red-500/20", pillText: "text-red-700 dark:text-red-300", glow: "shadow-red-500/10 dark:shadow-red-500/5" };
  if (avg >= 55) return { label: "High", iconBg: "bg-orange-500/20 dark:bg-orange-500/25", iconText: "text-orange-600 dark:text-orange-400", pillBg: "bg-orange-50 dark:bg-orange-500/10 border-orange-200/60 dark:border-orange-500/20", pillText: "text-orange-700 dark:text-orange-300", glow: "shadow-orange-500/10 dark:shadow-orange-500/5" };
  if (avg >= 35) return { label: "Medium", iconBg: "bg-amber-500/20 dark:bg-amber-500/25", iconText: "text-amber-600 dark:text-amber-400", pillBg: "bg-amber-50 dark:bg-amber-500/10 border-amber-200/60 dark:border-amber-500/20", pillText: "text-amber-700 dark:text-amber-300", glow: "shadow-amber-500/10 dark:shadow-amber-500/5" };
  return { label: "Low", iconBg: "bg-emerald-500/20 dark:bg-emerald-500/25", iconText: "text-emerald-600 dark:text-emerald-400", pillBg: "bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200/60 dark:border-emerald-500/20", pillText: "text-emerald-700 dark:text-emerald-300", glow: "shadow-emerald-500/10 dark:shadow-emerald-500/5" };
}

/* ─── Inline sparkline (SVG) ─────────────────────────── */
function MiniSparkline({ data }: { data: number[] }) {
  if (!data.length) return null;
  const max = Math.max(...data, 1);
  const w = 56;
  const h = 18;
  const points = data.map((v, i) => {
    const x = (i / Math.max(data.length - 1, 1)) * w;
    const y = h - (v / max) * (h - 2) - 1;
    return `${x},${y}`;
  });
  // Fill area
  const fillPoints = `0,${h} ${points.join(" ")} ${w},${h}`;
  return (
    <svg width={w} height={h} className="shrink-0">
      <defs>
        <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="currentColor" stopOpacity="0.3" />
          <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={fillPoints} fill="url(#spark-fill)" className="text-emerald-500 dark:text-emerald-400" />
      <polyline
        points={points.join(" ")}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
        className="text-emerald-600 dark:text-emerald-400"
      />
    </svg>
  );
}

/* ─── Divider ─────────────────────────────────────────── */
const Sep = () => <div className="w-px h-5 bg-border/40 dark:bg-white/[0.06] shrink-0" />;

/* ─── 3D Pill — glassmorphism wrapper ─────────────────── */
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
      className={`
        flex items-center gap-1.5 h-7 px-2.5 rounded-lg
        text-[10px] font-semibold tracking-wide shrink-0
        border backdrop-blur-sm
        shadow-sm
        transition-all duration-150
        ${className}
      `}
    >
      {children}
    </div>
  );
}

/* ─── Icon box — small 3D icon container ──────────────── */
function IconBox({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={`flex items-center justify-center w-4 h-4 rounded-[4px] shadow-sm ${className}`}>
      {children}
    </span>
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
      <Pill className="bg-red-50 dark:bg-red-500/10 border-red-200/60 dark:border-red-500/20 text-red-700 dark:text-red-300">
        <AlertTriangle className="h-3 w-3" /> Offline
      </Pill>
    );
  }
  if (!data) {
    return (
      <div className="flex items-center gap-1.5 animate-pulse">
        {[52, 60, 48, 52, 44].map((w, i) => (
          <div key={i} className="h-7 rounded-lg bg-muted/40 dark:bg-white/[0.04]" style={{ width: w }} />
        ))}
      </div>
    );
  }

  const isOk = data.status === "ok";
  const tl = threatLevel(data.avg_risk_score);
  const allUp = isOk && data.active_feeds > 0;

  return (
    <div className="flex items-center gap-1.5 overflow-x-auto scrollbar-none">
      {/* 1 ── System Health + Live ───────────────────── */}
      <div className="group relative">
        <Pill className={allUp
          ? "bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200/60 dark:border-emerald-500/20 text-emerald-700 dark:text-emerald-300 shadow-emerald-500/10 dark:shadow-emerald-500/5"
          : "bg-amber-50 dark:bg-amber-500/10 border-amber-200/60 dark:border-amber-500/20 text-amber-700 dark:text-amber-300 shadow-amber-500/10 dark:shadow-amber-500/5"
        }>
          <span className="relative flex h-2 w-2 shrink-0">
            {allUp && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-500 dark:bg-emerald-400 opacity-75" />
            )}
            <span className={`relative inline-flex rounded-full h-2 w-2 ${allUp ? "bg-emerald-500" : "bg-amber-500"}`} />
          </span>
          {allUp ? "Live" : "Degraded"}
        </Pill>
        {/* Tooltip */}
        <div className="absolute left-1/2 -translate-x-1/2 top-full mt-1.5 z-50 hidden group-hover:block">
          <div className="bg-white dark:bg-[hsl(222,47%,11%)] border border-gray-200 dark:border-white/10 rounded-lg shadow-xl px-3 py-2 text-[10px] whitespace-nowrap space-y-1.5">
            {[
              { ok: data.postgres, label: "Database" },
              { ok: data.redis, label: "Cache" },
              { ok: data.opensearch, label: "Search Index" },
            ].map((s) => (
              <div key={s.label} className="flex items-center gap-2">
                <span className={`inline-flex h-1.5 w-1.5 rounded-full ${s.ok ? "bg-emerald-500" : "bg-red-500"}`} />
                <span className="text-gray-600 dark:text-gray-400">{s.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <Sep />

      {/* 2 ── Threat Level Gauge ─────────────────────── */}
      <Pill className={`${tl.pillBg} ${tl.pillText} ${tl.glow}`} title={`Avg risk score: ${data.avg_risk_score}`}>
        <IconBox className={tl.iconBg}>
          <Gauge className={`h-2.5 w-2.5 ${tl.iconText}`} />
        </IconBox>
        {tl.label}
        <span className="opacity-60 font-normal">{data.avg_risk_score}</span>
      </Pill>

      <Sep />

      {/* 3 ── Total Intel + 24h delta ────────────────── */}
      <Pill className="bg-gray-50 dark:bg-white/[0.04] border-gray-200/60 dark:border-white/[0.06] text-gray-600 dark:text-gray-300" title="Total ingested intel items">
        <IconBox className="bg-blue-500/15 dark:bg-blue-500/20">
          <Database className="h-2.5 w-2.5 text-blue-600 dark:text-blue-400" />
        </IconBox>
        <span className="text-gray-900 dark:text-white font-bold tabular-nums">{data.total_intel.toLocaleString()}</span>
        {data.intel_24h > 0 && (
          <span className="text-emerald-600 dark:text-emerald-400 font-normal">+{data.intel_24h.toLocaleString()}</span>
        )}
      </Pill>

      <Sep />

      {/* 4 ── Crit/High threats ──────────────────────── */}
      {(data.critical_count + data.high_count) > 0 && (
        <>
          <Pill className="bg-red-50 dark:bg-red-500/10 border-red-200/60 dark:border-red-500/20 text-red-700 dark:text-red-300 shadow-red-500/10 dark:shadow-red-500/5">
            <IconBox className="bg-red-500/15 dark:bg-red-500/20">
              <Shield className="h-2.5 w-2.5 text-red-600 dark:text-red-400" />
            </IconBox>
            <span className="font-bold tabular-nums">{(data.critical_count + data.high_count).toLocaleString()}</span>
            <span className="text-red-500/70 dark:text-red-400/60 font-normal">Crit/High</span>
          </Pill>
          <Sep />
        </>
      )}

      {/* 5 ── Active CVEs / KEV ──────────────────────── */}
      {data.kev_count > 0 && (
        <>
          <Pill className="bg-orange-50 dark:bg-orange-500/10 border-orange-200/60 dark:border-orange-500/20 text-orange-700 dark:text-orange-300 shadow-orange-500/10 dark:shadow-orange-500/5" title="Known Exploited Vulnerabilities (CISA KEV)">
            <IconBox className="bg-orange-500/15 dark:bg-orange-500/20">
              <Flame className="h-2.5 w-2.5 text-orange-600 dark:text-orange-400" />
            </IconBox>
            <span className="font-bold tabular-nums">{data.kev_count}</span>
            <span className="font-normal opacity-60">KEV</span>
          </Pill>
          <Sep />
        </>
      )}

      {/* 6 ── Feed Sparkline ─────────────────────────── */}
      {data.sparkline && data.sparkline.length > 0 && (
        <>
          <div className="group relative flex items-center gap-1 h-7 px-2.5 rounded-lg bg-gray-50 dark:bg-white/[0.04] border border-gray-200/60 dark:border-white/[0.06] shadow-sm shrink-0">
            <MiniSparkline data={data.sparkline} />
            <div className="absolute left-1/2 -translate-x-1/2 top-full mt-1.5 z-50 hidden group-hover:block">
              <div className="bg-white dark:bg-[hsl(222,47%,11%)] border border-gray-200 dark:border-white/10 rounded-lg shadow-xl px-3 py-1.5 text-[10px] whitespace-nowrap text-gray-500 dark:text-gray-400">
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
          <Pill className="bg-gray-50 dark:bg-white/[0.04] border-gray-200/60 dark:border-white/[0.06] text-gray-500 dark:text-gray-400" title="Last successful feed ingestion">
            <IconBox className="bg-gray-500/10 dark:bg-white/10">
              <Clock className="h-2.5 w-2.5 text-gray-500 dark:text-gray-400" />
            </IconBox>
            <span className="text-gray-800 dark:text-gray-200 font-semibold">{timeAgo(data.last_feed_at)}</span>
          </Pill>
          <Sep />
        </>
      )}

      {/* 8 ── ATT&CK Coverage + Trend ────────────────── */}
      <Link href="/techniques" className="no-underline">
        <Pill className="bg-violet-50 dark:bg-violet-500/10 border-violet-200/60 dark:border-violet-500/20 text-violet-700 dark:text-violet-300 shadow-violet-500/10 dark:shadow-violet-500/5 hover:bg-violet-100 dark:hover:bg-violet-500/15 transition-colors cursor-pointer" title={`MITRE ATT&CK technique coverage${data.attack_coverage_prev_pct > 0 ? ` (was ${data.attack_coverage_prev_pct}% 7d ago)` : ""}`}>
          <IconBox className="bg-violet-500/15 dark:bg-violet-500/20">
            <Grid3X3 className="h-2.5 w-2.5 text-violet-600 dark:text-violet-400" />
          </IconBox>
          <span className="font-bold tabular-nums">{data.attack_coverage_pct}%</span>
          {data.attack_coverage_prev_pct > 0 && (() => {
            const diff = +(data.attack_coverage_pct - data.attack_coverage_prev_pct).toFixed(1);
            if (diff > 0) return <TrendingUp className="h-2.5 w-2.5 text-emerald-500" />;
            if (diff < 0) return <TrendingDown className="h-2.5 w-2.5 text-red-400" />;
            return <Minus className="h-2.5 w-2.5 opacity-40" />;
          })()}
        </Pill>
      </Link>

      {/* 9 ── Search Stats ───────────────────────────── */}
      {data.searches_today > 0 && (
        <>
          <Sep />
          <Pill className="bg-gray-50 dark:bg-white/[0.04] border-gray-200/60 dark:border-white/[0.06] text-gray-500 dark:text-gray-400" title="Searches performed today">
            <IconBox className="bg-gray-500/10 dark:bg-white/10">
              <Search className="h-2.5 w-2.5 text-gray-500 dark:text-gray-400" />
            </IconBox>
            <span className="text-gray-800 dark:text-gray-200 font-semibold tabular-nums">{data.searches_today}</span>
            <span className="font-normal">today</span>
          </Pill>
        </>
      )}
    </div>
  );
}
