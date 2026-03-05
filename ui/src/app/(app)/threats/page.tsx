"use client";

import React, { useEffect, useMemo, useState, useCallback, useRef } from "react";
import { useSearchParams } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { DonutChart } from "@/components/charts";
import { Pagination } from "@/components/Pagination";
import {
  AlertTriangle,
  Shield,
  Zap,
  Clock,
  ChevronRight,
  Package,
  Bug,
  Tag,
  Link2,
  ShieldCheck,
  ArrowUpDown,
  Crosshair,
  Telescope,
  Share2,
  Database,
  Calendar,
  TrendingUp,
  Globe,
  Sparkles,
  Search,
  Download,
  RefreshCw,
  MapPin,
  Building2,
  Flame,
  Target,
  ShieldAlert,
  BarChart3,
  FileText,
  Eye,
} from "lucide-react";
import { formatDate, severityBorder, riskColor, riskBg } from "@/lib/utils";
import { cn } from "@/lib/utils";
import Link from "next/link";
import * as api from "@/lib/api";
import type { IntelListResponse, IntelItem, IntelStatsResponse } from "@/types";

/* ─── Constants ───────────────────────────────────────── */

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
};

const SORT_OPTIONS = [
  { value: "ingested_at:desc", label: "Most Recent" },
  { value: "risk_score:desc", label: "Highest Risk" },
  { value: "published_at:desc", label: "Published Date" },
  { value: "risk_score:asc", label: "Lowest Risk" },
  { value: "severity:desc", label: "Severity" },
];

const FEED_TYPES = ["vulnerability", "ioc", "malware", "threat_actor", "campaign", "exploit", "advisory"];

const TLP_COLORS: Record<string, string> = {
  "TLP:RED": "bg-red-500/20 text-red-400 border-red-500/30",
  "TLP:AMBER": "bg-amber-500/20 text-amber-400 border-amber-500/30",
  "TLP:GREEN": "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  "TLP:CLEAR": "bg-slate-500/10 text-slate-400 border-slate-500/20",
  "TLP:WHITE": "bg-slate-500/10 text-slate-400 border-slate-500/20",
};

/* ─── Helpers ─────────────────────────────────────────── */

function freshnessColor(dateStr: string | null): string {
  if (!dateStr) return "bg-gray-500";
  const h = (Date.now() - new Date(dateStr).getTime()) / 3600000;
  if (h < 24) return "bg-emerald-500";
  if (h < 168) return "bg-amber-500";
  return "bg-gray-500";
}

function freshnessLabel(dateStr: string | null): string {
  if (!dateStr) return "Unknown age";
  const h = (Date.now() - new Date(dateStr).getTime()) / 3600000;
  if (h < 2) return "Just in";
  if (h < 24) return "Today";
  if (h < 168) return "This week";
  return "Older";
}

function isNewItem(dateStr: string): boolean {
  return (Date.now() - new Date(dateStr).getTime()) < 7200000; // 2 hours
}

/* ─── QuickStatsBar ───────────────────────────────────── */

function QuickStatsBar({ stats, onFilter }: {
  stats: IntelStatsResponse | null;
  onFilter?: (key: string, value: string) => void;
}) {
  if (!stats) return null;
  const items = [
    { label: "Total", value: stats.total, icon: Database, color: "text-blue-400", onClick: () => onFilter?.("clear", "") },
    { label: "24h", value: stats.today, icon: Calendar, color: "text-emerald-400" },
    { label: "Critical", value: stats.critical, icon: AlertTriangle, color: "text-red-400", onClick: () => onFilter?.("severity", "critical") },
    { label: "High", value: stats.high, icon: ShieldAlert, color: "text-orange-400", onClick: () => onFilter?.("severity", "high") },
    { label: "KEV", value: stats.kev_count, icon: Zap, color: "text-yellow-400", onClick: () => onFilter?.("kev", "true") },
    { label: "Exploits", value: stats.exploit_count, icon: Bug, color: "text-rose-400", onClick: () => onFilter?.("exploit", "true") },
    { label: "Avg Risk", value: stats.avg_risk, icon: TrendingUp, color: "text-purple-400" },
    { label: "Sources", value: stats.sources, icon: Globe, color: "text-cyan-400" },
    { label: "AI Enriched", value: stats.ai_enriched, icon: Sparkles, color: "text-violet-400" },
  ];
  return (
    <div className="flex items-center gap-1.5 flex-wrap py-1.5 px-3 bg-muted/30 rounded-lg border border-border/40">
      {items.map((s, i) => (
        <button
          key={s.label}
          onClick={s.onClick}
          className={cn(
            "flex items-center gap-1.5 px-2 py-1 rounded text-[11px] transition-colors",
            s.onClick ? "hover:bg-muted/60 cursor-pointer" : "cursor-default",
            i > 0 && "border-l border-border/30 pl-3"
          )}
        >
          <s.icon className={cn("h-3 w-3", s.color)} />
          <span className="text-muted-foreground">{s.label}</span>
          <span className="font-semibold tabular-nums">{typeof s.value === "number" ? s.value.toLocaleString() : s.value}</span>
        </button>
      ))}
    </div>
  );
}

/* ─── SeverityMiniBar ─────────────────────────────────── */

function SeverityMiniBar({ stats }: { stats: IntelStatsResponse }) {
  const total = stats.total || 1;
  const bars = [
    { key: "critical", count: stats.critical, color: "bg-red-500", label: "Critical" },
    { key: "high", count: stats.high, color: "bg-orange-500", label: "High" },
    { key: "medium", count: stats.medium, color: "bg-yellow-500", label: "Medium" },
    { key: "low", count: stats.low, color: "bg-green-500", label: "Low" },
    { key: "info", count: stats.info, color: "bg-blue-500", label: "Info" },
  ];
  return (
    <div className="space-y-1.5">
      {/* Stacked bar */}
      <div className="flex h-2.5 rounded-full overflow-hidden bg-muted/30">
        {bars.map((b) => (
          b.count > 0 && (
            <div
              key={b.key}
              className={cn(b.color, "transition-all")}
              style={{ width: `${(b.count / total) * 100}%` }}
              title={`${b.label}: ${b.count.toLocaleString()}`}
            />
          )
        ))}
      </div>
      {/* Legend */}
      <div className="flex flex-wrap gap-x-3 gap-y-0.5">
        {bars.map((b) => (
          <div key={b.key} className="flex items-center gap-1 text-[10px] text-muted-foreground">
            <div className={cn("h-1.5 w-1.5 rounded-full", b.color)} />
            <span>{b.label}</span>
            <span className="font-medium tabular-nums">{b.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── TopList (reusable ranked list) ──────────────────── */

function TopList({ title, icon: Icon, items, type = "text" }: {
  title: string;
  icon: React.ElementType;
  items: { label: string; value?: number }[];
  type?: "text" | "count";
}) {
  if (!items.length) return null;
  return (
    <Card>
      <CardHeader className="pb-1 pt-3 px-4">
        <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
          <Icon className="h-3 w-3 text-muted-foreground" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent className="px-4 pb-3">
        <div className="space-y-1">
          {items.slice(0, 8).map((item, i) => (
            <div key={item.label} className="flex items-center justify-between text-[11px]">
              <span className="text-muted-foreground truncate flex items-center gap-1.5">
                <span className="text-[9px] font-mono text-muted-foreground/50 w-3 text-right">{i + 1}</span>
                {item.label}
              </span>
              {item.value != null && (
                <span className="font-medium tabular-nums text-foreground/80 shrink-0 ml-2">
                  {item.value.toLocaleString()}
                </span>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

/* ─── FeedTypeDistribution ────────────────────────────── */

function FeedTypeGrid({ counts }: { counts: Record<string, number> }) {
  const icons: Record<string, React.ElementType> = {
    vulnerability: ShieldAlert,
    ioc: Target,
    malware: Bug,
    threat_actor: Flame,
    campaign: BarChart3,
    exploit: Zap,
    advisory: FileText,
  };
  const colors: Record<string, string> = {
    vulnerability: "text-red-400 bg-red-500/10",
    ioc: "text-blue-400 bg-blue-500/10",
    malware: "text-purple-400 bg-purple-500/10",
    threat_actor: "text-orange-400 bg-orange-500/10",
    campaign: "text-cyan-400 bg-cyan-500/10",
    exploit: "text-yellow-400 bg-yellow-500/10",
    advisory: "text-emerald-400 bg-emerald-500/10",
  };
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return null;
  return (
    <Card>
      <CardHeader className="pb-1 pt-3 px-4">
        <CardTitle className="text-xs font-semibold">Feed Types</CardTitle>
      </CardHeader>
      <CardContent className="px-4 pb-3">
        <div className="grid grid-cols-2 gap-1.5">
          {entries.map(([key, count]) => {
            const Icon = icons[key] || Shield;
            return (
              <div key={key} className={cn("flex items-center gap-1.5 rounded px-2 py-1.5 text-[10px]", colors[key] || "text-muted-foreground bg-muted/30")}>
                <Icon className="h-3 w-3 shrink-0" />
                <span className="capitalize truncate">{key.replace(/_/g, " ")}</span>
                <span className="ml-auto font-bold tabular-nums">{count.toLocaleString()}</span>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

/* ─── Main Page ───────────────────────────────────────── */

export default function ThreatsPage() {
  const searchParams = useSearchParams();
  const [data, setData] = useState<IntelListResponse | null>(null);
  const [stats, setStats] = useState<IntelStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [selectedSev, setSelectedSev] = useState<string | null>(searchParams.get("severity") || null);
  const [selectedFeedType, setSelectedFeedType] = useState<string | null>(searchParams.get("feed_type") || null);
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);
  const [kevOnly, setKevOnly] = useState(false);
  const [exploitOnly, setExploitOnly] = useState(false);
  const [sortKey, setSortKey] = useState("ingested_at:desc");
  const [searchQ, setSearchQ] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [stale, setStale] = useState(false);
  const lastFetchRef = useRef(Date.now());

  /* ─── Fetch data ─── */
  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [sortBy, sortOrder] = sortKey.split(":");
      const params: Record<string, string | number | boolean> = {
        page,
        page_size: 20,
        sort_by: sortBy,
        sort_order: sortOrder,
      };
      if (selectedSev) params.severity = selectedSev;
      if (selectedFeedType) params.feed_type = selectedFeedType;
      if (selectedAsset) params.asset_type = selectedAsset;
      if (kevOnly) params.is_kev = true;
      if (exploitOnly) params.exploit_available = true;
      if (searchQ) params.query = searchQ;
      const result = await api.getIntelItems(params as Record<string, string | number>);
      setData(result);
      lastFetchRef.current = Date.now();
      setStale(false);
    } catch {
      /* silent */
    }
    setLoading(false);
  }, [page, selectedSev, selectedFeedType, selectedAsset, kevOnly, exploitOnly, sortKey, searchQ]);

  const fetchStats = useCallback(async () => {
    try {
      const s = await api.getIntelStats();
      setStats(s);
    } catch { /* silent */ }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);
  useEffect(() => { fetchStats(); }, [fetchStats]);

  // Auto-refresh: stale indicator after 2 min, auto-fetch stats every 60s
  useEffect(() => {
    const staleTimer = setInterval(() => {
      if (Date.now() - lastFetchRef.current > 120_000) setStale(true);
    }, 30_000);
    const statsTimer = setInterval(fetchStats, 60_000);
    return () => { clearInterval(staleTimer); clearInterval(statsTimer); };
  }, [fetchStats]);

  /* ─── Donut from stats (global, not page-scoped) ─── */
  const assetDonut = useMemo(() => {
    const src = stats?.asset_type_counts || {};
    const colors = ["#3b82f6", "#ef4444", "#f97316", "#22c55e", "#a855f7", "#ec4899", "#14b8a6", "#6b7280"];
    return Object.entries(src)
      .sort((a, b) => b[1] - a[1])
      .map(([key, count], i) => ({
        name: key.toUpperCase().replace(/_/g, " "),
        value: count,
        color: colors[i % colors.length],
        rawKey: key,
      }));
  }, [stats]);

  /* ─── Filter handlers ─── */
  const handleSevFilter = (sev: string | null) => { setSelectedSev(sev); setPage(1); };
  const handleFeedTypeFilter = (ft: string | null) => { setSelectedFeedType(ft); setPage(1); };
  const handleAssetClick = (name: string) => {
    const match = assetDonut.find((d) => d.name === name);
    const rawKey = (match as any)?.rawKey || name.toLowerCase().replace(/ /g, "_");
    setSelectedAsset(selectedAsset === rawKey ? null : rawKey);
    setPage(1);
  };
  const handleStatsFilter = (key: string, value: string) => {
    if (key === "clear") { setSelectedSev(null); setKevOnly(false); setExploitOnly(false); }
    else if (key === "severity") { setSelectedSev(value); setKevOnly(false); setExploitOnly(false); }
    else if (key === "kev") { setKevOnly(true); setExploitOnly(false); setSelectedSev(null); }
    else if (key === "exploit") { setExploitOnly(true); setKevOnly(false); setSelectedSev(null); }
    setPage(1);
  };
  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchQ(searchInput.trim());
    setPage(1);
  };
  const clearSearch = () => { setSearchInput(""); setSearchQ(""); setPage(1); };

  const handleRefresh = () => { fetchData(); fetchStats(); };

  /* ─── Active filters count ─── */
  const activeFilters = [selectedSev, selectedFeedType, selectedAsset, kevOnly, exploitOnly, searchQ].filter(Boolean).length;

  if (loading && !data) return <Loading text="Loading threat feed..." />;

  const items = data?.items || [];

  return (
    <div className="p-4 lg:p-6 space-y-4">
      {/* ─── Header Row ─── */}
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-500" />
            Active Threats
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Real-time threat intelligence feed
            {data && (
              <span className="ml-2 text-muted-foreground/50">
                — {data.total.toLocaleString()} items
                {selectedSev && ` (${selectedSev})`}
                {selectedFeedType && ` · ${selectedFeedType.replace(/_/g, " ")}`}
                {selectedAsset && ` · ${selectedAsset.toUpperCase()}`}
                {kevOnly && " · KEV Only"}
                {exploitOnly && " · Exploitable"}
                {searchQ && ` · "${searchQ}"`}
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {stale && (
            <span className="flex items-center gap-1 text-[10px] text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-1 rounded">
              <AlertTriangle className="h-3 w-3" /> Stale
            </span>
          )}
          <button
            onClick={handleRefresh}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors border rounded-md px-2.5 py-1.5"
          >
            <RefreshCw className={cn("h-3 w-3", loading && "animate-spin")} /> Refresh
          </button>
          <a
            href={api.getExportUrl({ ...(selectedSev ? { severity: selectedSev } : {}), ...(selectedFeedType ? { feed_type: selectedFeedType } : {}) })}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors border rounded-md px-2.5 py-1.5"
            title="Export current filter to Excel"
          >
            <Download className="h-3 w-3" /> Export
          </a>
          <div className="flex items-center gap-1.5 border rounded-md px-2 py-1.5">
            <ArrowUpDown className="h-3 w-3 text-muted-foreground" />
            <select
              value={sortKey}
              onChange={(e) => { setSortKey(e.target.value); setPage(1); }}
              className="text-xs bg-transparent text-foreground focus:outline-none cursor-pointer [&>option]:bg-gray-900 [&>option]:text-foreground"
            >
              {SORT_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* ─── Stats Bar ─── */}
      <QuickStatsBar stats={stats} onFilter={handleStatsFilter} />

      {/* ─── Search + Filter Row ─── */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Search */}
        <form onSubmit={handleSearch} className="flex items-center gap-1 relative">
          <Search className="absolute left-2.5 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search threats..."
            className="text-xs bg-background border rounded-md pl-8 pr-2 py-1.5 w-52 text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary"
          />
          {searchQ && (
            <button type="button" onClick={clearSearch} className="text-[10px] text-muted-foreground hover:text-foreground ml-1">
              Clear
            </button>
          )}
        </form>

        {/* Quick toggles */}
        <Badge
          variant={kevOnly ? "destructive" : "outline"}
          className="cursor-pointer gap-1"
          onClick={() => { setKevOnly(!kevOnly); setPage(1); }}
        >
          <Zap className="h-2.5 w-2.5" /> KEV Only
        </Badge>
        <Badge
          variant={exploitOnly ? "destructive" : "outline"}
          className="cursor-pointer gap-1"
          onClick={() => { setExploitOnly(!exploitOnly); setPage(1); }}
        >
          <Bug className="h-2.5 w-2.5" /> Exploitable
        </Badge>

        {activeFilters > 0 && (
          <button
            onClick={() => {
              setSelectedSev(null); setSelectedFeedType(null); setSelectedAsset(null);
              setKevOnly(false); setExploitOnly(false); setSearchQ(""); setSearchInput(""); setPage(1);
            }}
            className="text-[10px] text-primary hover:underline"
          >
            Clear all filters ({activeFilters})
          </button>
        )}
      </div>

      {/* ─── Severity Filter Pills ─── */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] text-muted-foreground uppercase font-semibold tracking-wider mr-1">Severity</span>
        <Badge variant={selectedSev === null ? "default" : "outline"} className="cursor-pointer" onClick={() => handleSevFilter(null)}>All</Badge>
        {["critical", "high", "medium", "low", "info"].map((s) => (
          <Badge key={s} variant={selectedSev === s ? (s as any) : "outline"} className="cursor-pointer" onClick={() => handleSevFilter(selectedSev === s ? null : s)}>
            {s.charAt(0).toUpperCase() + s.slice(1)}
            {stats && (
              <span className="ml-1 opacity-60 tabular-nums">
                {(stats as any)[s === "info" ? "info" : s]?.toLocaleString() ?? ""}
              </span>
            )}
          </Badge>
        ))}
      </div>

      {/* ─── Feed Type Filter Pills ─── */}
      <div className="flex items-center gap-2 flex-wrap -mt-2">
        <span className="text-[10px] text-muted-foreground uppercase font-semibold tracking-wider mr-1">Type</span>
        <Badge variant={selectedFeedType === null ? "default" : "outline"} className="cursor-pointer" onClick={() => handleFeedTypeFilter(null)}>All</Badge>
        {FEED_TYPES.map((ft) => (
          <Badge key={ft} variant={selectedFeedType === ft ? "default" : "outline"} className="cursor-pointer" onClick={() => handleFeedTypeFilter(selectedFeedType === ft ? null : ft)}>
            {ft.charAt(0).toUpperCase() + ft.slice(1).replace(/_/g, " ")}
            {stats?.feed_type_counts?.[ft] != null && (
              <span className="ml-1 opacity-60 tabular-nums">{stats.feed_type_counts[ft].toLocaleString()}</span>
            )}
          </Badge>
        ))}
      </div>

      {/* ─── Main Grid ─── */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* ─── Threat List ─── */}
        <div className="lg:col-span-3 space-y-2">
          {loading && data ? (
            <div className="space-y-2">
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="h-24 rounded-lg bg-muted/20 animate-pulse" />
              ))}
            </div>
          ) : (
            <>
              {items.map((item) => (
                <Link
                  key={item.id}
                  href={`/intel/${item.id}`}
                  className={cn(
                    "block border-l-4 rounded-lg border bg-card p-3 hover:shadow-md transition-all group relative",
                    severityBorder(item.severity)
                  )}
                >
                  {/* New badge */}
                  {isNewItem(item.ingested_at) && (
                    <span className="absolute -top-1.5 -right-1.5 text-[8px] font-bold bg-emerald-500 text-white px-1.5 py-0.5 rounded-full uppercase tracking-wider shadow-sm">
                      New
                    </span>
                  )}

                  <div className="flex items-start gap-3">
                    {/* Risk score + freshness dot */}
                    <div className="flex flex-col items-center gap-1 shrink-0">
                      <div
                        className={cn(
                          "flex items-center justify-center h-10 w-12 rounded-md text-sm font-bold",
                          riskBg(item.risk_score),
                          riskColor(item.risk_score),
                          item.risk_score >= 80 && "ring-1 ring-red-500/30"
                        )}
                      >
                        {item.risk_score}
                      </div>
                      <div
                        className={cn("h-1.5 w-1.5 rounded-full", freshnessColor(item.published_at || item.ingested_at))}
                        title={freshnessLabel(item.published_at || item.ingested_at)}
                      />
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      {/* Row 1: Badges */}
                      <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
                        <Badge variant={item.severity as any} className="text-[10px] h-5">
                          {item.severity.toUpperCase()}
                        </Badge>
                        {item.is_kev && (
                          <Badge variant="destructive" className="text-[10px] h-5 gap-0.5">
                            <Zap className="h-2.5 w-2.5" /> KEV
                          </Badge>
                        )}
                        {item.exploit_available && (
                          <span className="inline-flex items-center gap-0.5 text-[9px] bg-red-500/15 text-red-400 border border-red-500/25 px-1.5 py-0.5 rounded font-medium">
                            <Bug className="h-2.5 w-2.5" /> Exploit
                          </span>
                        )}
                        <span className="text-[10px] text-muted-foreground capitalize">
                          {item.feed_type.replace(/_/g, " ")}
                        </span>
                        {/* TLP badge */}
                        {item.tlp && item.tlp !== "TLP:CLEAR" && (
                          <span className={cn("text-[8px] px-1 py-0.5 rounded border font-mono", TLP_COLORS[item.tlp] || TLP_COLORS["TLP:CLEAR"])}>
                            {item.tlp}
                          </span>
                        )}
                      </div>

                      {/* Row 2: Title */}
                      <h3 className="text-sm font-medium leading-tight group-hover:text-primary transition-colors line-clamp-1">
                        {item.title}
                      </h3>

                      {/* Row 3: AI Summary preview */}
                      {item.ai_summary && (
                        <p className="text-[11px] text-muted-foreground/70 line-clamp-1 mt-0.5 flex items-start gap-1">
                          <Sparkles className="h-3 w-3 text-violet-400 shrink-0 mt-0.5" />
                          <span>{item.ai_summary}</span>
                        </p>
                      )}

                      {/* Row 4: Metadata */}
                      <div className="flex items-center gap-3 mt-1 text-[11px] text-muted-foreground flex-wrap">
                        <span className="flex items-center gap-1">
                          <Shield className="h-3 w-3" /> {item.source_name}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" /> {formatDate(item.published_at || item.ingested_at, { relative: true })}
                        </span>
                        {/* CVE IDs — show up to 3 */}
                        {item.cve_ids?.length > 0 && (
                          <span className="flex items-center gap-1 font-mono">
                            {item.cve_ids.slice(0, 3).map((cve, i) => (
                              <span
                                key={cve}
                                className="text-primary hover:underline"
                                onClick={(e) => { e.preventDefault(); e.stopPropagation(); window.location.href = `/search?q=${cve}`; }}
                              >
                                {cve}{i < Math.min(item.cve_ids.length, 3) - 1 && ","}
                              </span>
                            ))}
                            {item.cve_ids.length > 3 && <span className="text-muted-foreground/50">+{item.cve_ids.length - 3}</span>}
                          </span>
                        )}
                        {item.confidence > 0 && (
                          <span className="flex items-center gap-1">
                            <ShieldCheck className="h-3 w-3" /> {item.confidence}%
                          </span>
                        )}
                        {item.related_ioc_count > 0 && (
                          <span className="flex items-center gap-1">
                            <Link2 className="h-3 w-3" /> {item.related_ioc_count} IOCs
                          </span>
                        )}
                        {item.exploitability_score != null && item.exploitability_score > 0 && (
                          <span className={cn(
                            "inline-flex items-center gap-0.5 text-[10px] px-1 py-0.5 rounded font-mono border",
                            item.exploitability_score >= 7 ? "bg-red-500/10 text-red-400 border-red-500/20" :
                            item.exploitability_score >= 4 ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                            "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                          )}>
                            CVSS {item.exploitability_score.toFixed(1)}
                          </span>
                        )}
                      </div>

                      {/* Row 5: Products, Geo, Industries, Tags */}
                      {(item.affected_products?.length > 0 || item.geo?.length > 0 || item.industries?.length > 0 || item.tags?.length > 0 || item.feed_type === "threat_actor") && (
                        <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                          {item.affected_products?.length > 0 && (
                            <span className="inline-flex items-center gap-1 text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-1.5 py-0.5 rounded">
                              <Package className="h-2.5 w-2.5" />
                              {item.affected_products.slice(0, 2).join(", ")}
                              {item.affected_products.length > 2 && ` +${item.affected_products.length - 2}`}
                            </span>
                          )}
                          {item.geo?.length > 0 && item.geo.slice(0, 3).map((g) => (
                            <span key={g} className="inline-flex items-center gap-0.5 text-[10px] bg-sky-500/10 text-sky-400 border border-sky-500/20 px-1.5 py-0.5 rounded">
                              <MapPin className="h-2 w-2" /> {g}
                            </span>
                          ))}
                          {item.industries?.length > 0 && item.industries.slice(0, 2).map((ind) => (
                            <span key={ind} className="inline-flex items-center gap-0.5 text-[10px] bg-teal-500/10 text-teal-400 border border-teal-500/20 px-1.5 py-0.5 rounded">
                              <Building2 className="h-2 w-2" /> {ind}
                            </span>
                          ))}
                          {item.feed_type === "threat_actor" && (
                            <span className="inline-flex items-center gap-0.5 text-[10px] bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded font-medium">
                              <Flame className="h-2.5 w-2.5" /> Threat Actor
                            </span>
                          )}
                          {item.tags?.length > 0 && item.tags.slice(0, 3).map((tag) => (
                            <span key={tag} className="inline-flex items-center gap-0.5 text-[10px] bg-muted/50 text-muted-foreground border border-border/40 px-1.5 py-0.5 rounded">
                              <Tag className="h-2 w-2" /> {tag}
                            </span>
                          ))}
                          {item.tags?.length > 3 && (
                            <span className="text-[9px] text-muted-foreground/50">+{item.tags.length - 3}</span>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Action buttons */}
                    <div className="flex flex-col items-center gap-1 shrink-0 mt-1">
                      <button
                        onClick={(e) => {
                          e.preventDefault(); e.stopPropagation();
                          window.location.href = `/search?q=${encodeURIComponent(item.source_ref || item.cve_ids?.[0] || item.title)}&hunt=1`;
                        }}
                        className="icon-btn-3d group/hunt"
                        title="Hunt — search local + internet"
                      >
                        <Crosshair className="h-3.5 w-3.5 text-blue-400 group-hover/hunt:text-blue-300 transition-colors" />
                      </button>
                      <button
                        onClick={(e) => {
                          e.preventDefault(); e.stopPropagation();
                          window.location.href = `/investigate?id=${encodeURIComponent(item.id)}&type=intel&depth=1`;
                        }}
                        className="icon-btn-3d group/inv"
                        title="Investigate — relationship graph"
                      >
                        <Telescope className="h-3.5 w-3.5 text-purple-400 group-hover/inv:text-purple-300 transition-colors" />
                      </button>
                      {item.ai_summary && (
                        <span className="icon-btn-3d" title="AI enriched">
                          <Sparkles className="h-3.5 w-3.5 text-violet-400" />
                        </span>
                      )}
                      <span
                        className="conn-badge-3d flex items-center gap-0.5 text-teal-400/70"
                        title={`${item.related_ioc_count || 0} related connections`}
                      >
                        <Share2 className="h-3 w-3" />
                        <span className="text-[10px] font-medium tabular-nums">{item.related_ioc_count || 0}</span>
                      </span>
                      <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-primary transition-colors" />
                    </div>
                  </div>
                </Link>
              ))}

              {items.length === 0 && (
                <div className="text-center py-16 text-muted-foreground text-sm">
                  No threats matching this filter
                </div>
              )}

              {data && data.pages > 1 && (
                <Pagination page={page} pages={data.pages} onPageChange={setPage} />
              )}
            </>
          )}
        </div>

        {/* ─── Right Sidebar ─── */}
        <div className="space-y-3">
          {/* Severity Breakdown */}
          {stats && (
            <Card>
              <CardHeader className="pb-1 pt-3 px-4">
                <CardTitle className="text-xs font-semibold">Severity Breakdown</CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3">
                <SeverityMiniBar stats={stats} />
              </CardContent>
            </Card>
          )}

          {/* Asset Types Donut */}
          <Card>
            <CardHeader className="pb-1 pt-3 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-semibold">Asset Types</CardTitle>
                {selectedAsset && (
                  <button onClick={() => { setSelectedAsset(null); setPage(1); }} className="text-[9px] text-primary hover:underline">Clear</button>
                )}
              </div>
              {selectedAsset && (
                <p className="text-[10px] text-primary/70 mt-0.5">Filtering: {selectedAsset.toUpperCase().replace(/_/g, " ")}</p>
              )}
            </CardHeader>
            <CardContent className="px-4 pb-3">
              <DonutChart
                data={assetDonut}
                centerValue={stats?.total || data?.total || 0}
                centerLabel="Items"
                height={150}
                innerRadius={38}
                outerRadius={56}
                onSegmentClick={handleAssetClick}
                activeSegment={selectedAsset ? selectedAsset.toUpperCase().replace(/_/g, " ") : null}
              />
            </CardContent>
          </Card>

          {/* Feed Type Grid */}
          {stats?.feed_type_counts && <FeedTypeGrid counts={stats.feed_type_counts} />}

          {/* Top Sources */}
          {stats?.top_sources && (
            <TopList
              title="Top Sources"
              icon={Globe}
              items={stats.top_sources.map((s) => ({ label: s.name, value: s.count }))}
            />
          )}

          {/* Top CVEs */}
          {stats?.top_cves && stats.top_cves.length > 0 && (
            <TopList
              title="Top CVEs"
              icon={ShieldAlert}
              items={stats.top_cves.map((c) => ({ label: c }))}
            />
          )}

          {/* Top Tags */}
          {stats?.top_tags && stats.top_tags.length > 0 && (
            <Card>
              <CardHeader className="pb-1 pt-3 px-4">
                <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
                  <Tag className="h-3 w-3 text-muted-foreground" />
                  Trending Tags
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3">
                <div className="flex flex-wrap gap-1">
                  {stats.top_tags.slice(0, 20).map((tag) => (
                    <button
                      key={tag}
                      onClick={() => { setSearchInput(tag); setSearchQ(tag); setPage(1); }}
                      className="text-[10px] bg-muted/50 hover:bg-muted text-muted-foreground border border-border/40 px-1.5 py-0.5 rounded transition-colors cursor-pointer"
                    >
                      {tag}
                    </button>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
