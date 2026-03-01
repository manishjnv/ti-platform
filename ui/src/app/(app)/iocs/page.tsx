"use client";

import React, { useEffect, useCallback, useState, useMemo } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { Pagination } from "@/components/Pagination";
import { DonutChart } from "@/components/charts";
import {
  Database,
  Search,
  Copy,
  Check,
  AlertTriangle,
  ChevronUp,
  ChevronDown,
  ArrowUpDown,
  Shield,
  Eye,
  Globe,
  X,
  Loader2,
  Zap,
  Server,
  ShieldAlert,
  Flame,
  Tag,
  MapPin,
  Clock,
  ChevronRight,
} from "lucide-react";
import {
  getIOCs,
  getIOCStats,
  enrichIOC,
  type IOCItem,
  type IOCListResponse,
  type IOCStatsResponse,
  type IOCEnrichmentResult,
} from "@/lib/api";

/* ─── Constants ─────────────────────────────────────────── */

const IOC_TYPE_COLORS: Record<string, string> = {
  ip: "#3b82f6",
  domain: "#a855f7",
  url: "#f97316",
  hash: "#ef4444",
  hash_md5: "#ef4444",
  hash_sha1: "#dc2626",
  hash_sha256: "#b91c1c",
  email: "#ec4899",
  cve: "#22c55e",
  file: "#6366f1",
  other: "#6b7280",
};

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

const RISK_BG: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  low: "bg-green-500/10 text-green-400 border-green-500/20",
};

const IOC_TYPE_ICONS: Record<string, React.ReactNode> = {
  ip: <Globe className="h-3 w-3" />,
  domain: <Globe className="h-3 w-3" />,
  url: <Globe className="h-3 w-3" />,
  hash: <Shield className="h-3 w-3" />,
  hash_md5: <Shield className="h-3 w-3" />,
  hash_sha1: <Shield className="h-3 w-3" />,
  hash_sha256: <Shield className="h-3 w-3" />,
  email: <Tag className="h-3 w-3" />,
  cve: <ShieldAlert className="h-3 w-3" />,
};

function riskLabel(score: number) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function timeAgo(iso: string | null) {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
}

/* ─── Mini Risk Gauge (SVG half-arc) ────────────────────── */

function RiskGauge({ score, size = 48 }: { score: number; size?: number }) {
  const r = (size - 6) / 2;
  const circ = Math.PI * r;
  const pct = Math.min(score, 100) / 100;
  const offset = circ * (1 - pct);
  const color = RISK_COLORS[riskLabel(score)];

  return (
    <svg width={size} height={size / 2 + 8} viewBox={`0 0 ${size} ${size / 2 + 8}`}>
      <path
        d={`M 3,${size / 2 + 4} A ${r},${r} 0 0,1 ${size - 3},${size / 2 + 4}`}
        fill="none"
        stroke="currentColor"
        className="text-muted/20"
        strokeWidth={5}
        strokeLinecap="round"
      />
      <path
        d={`M 3,${size / 2 + 4} A ${r},${r} 0 0,1 ${size - 3},${size / 2 + 4}`}
        fill="none"
        stroke={color}
        strokeWidth={5}
        strokeLinecap="round"
        strokeDasharray={circ}
        strokeDashoffset={offset}
        className="transition-all duration-1000"
      />
      <text
        x={size / 2}
        y={size / 2}
        textAnchor="middle"
        className="fill-current text-foreground"
        fontSize={size / 4}
        fontWeight="bold"
      >
        {score}
      </text>
    </svg>
  );
}

/* ─── Horizontal Risk Distribution Bar ──────────────────── */

function RiskDistBar({ dist }: { dist: Record<string, number> }) {
  const total = Object.values(dist).reduce((s, v) => s + v, 0);
  if (total === 0) return null;
  const order = ["critical", "high", "medium", "low"] as const;
  return (
    <div className="space-y-1">
      <div className="flex h-2.5 rounded-full overflow-hidden bg-muted/30">
        {order.map((k) => {
          const w = ((dist[k] || 0) / total) * 100;
          return w > 0 ? (
            <div
              key={k}
              className="h-full transition-all duration-700"
              style={{ width: `${w}%`, backgroundColor: RISK_COLORS[k] }}
            />
          ) : null;
        })}
      </div>
      <div className="flex gap-3 text-[9px]">
        {order.map((k) => (
          <span key={k} className="flex items-center gap-1">
            <span
              className="w-1.5 h-1.5 rounded-full inline-block"
              style={{ backgroundColor: RISK_COLORS[k] }}
            />
            <span className="text-muted-foreground capitalize">{k}</span>
            <span className="font-semibold">{(dist[k] || 0).toLocaleString()}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/* ─── Hot IOCs Strip ────────────────────────────────────── */

function HotIOCsStrip({
  items,
  onEnrich,
}: {
  items: IOCStatsResponse["top_risky"];
  onEnrich: (ioc: IOCItem) => void;
}) {
  if (!items || items.length === 0) return null;

  return (
    <Card className="border-red-500/10 bg-gradient-to-r from-red-500/[0.03] to-transparent">
      <CardContent className="py-2 px-3">
        <div className="flex items-center gap-2 mb-1.5">
          <Flame className="h-3.5 w-3.5 text-red-400" />
          <span className="text-[11px] font-semibold">Highest Risk IOCs</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2">
          {items.map((ioc) => {
            const rl = riskLabel(ioc.risk_score);
            return (
              <button
                key={ioc.id}
                onClick={() =>
                  onEnrich({
                    ...ioc,
                    first_seen: null,
                    geo: [],
                    context: {},
                  } as IOCItem)
                }
                className="flex items-center gap-2 px-2 py-1.5 rounded-md bg-muted/20 hover:bg-muted/40 transition-colors text-left group min-w-0"
              >
                <span
                  className="w-1.5 h-5 rounded-full shrink-0"
                  style={{ backgroundColor: RISK_COLORS[rl] }}
                />
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-[10px] truncate group-hover:text-primary transition-colors">
                    {ioc.value}
                  </div>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Badge
                      variant="secondary"
                      className="text-[8px] px-1 py-0 h-3.5"
                      style={{
                        background: (IOC_TYPE_COLORS[ioc.ioc_type] || "#6b7280") + "20",
                        color: IOC_TYPE_COLORS[ioc.ioc_type] || "#6b7280",
                      }}
                    >
                      {ioc.ioc_type}
                    </Badge>
                    <span className="text-[9px] font-bold" style={{ color: RISK_COLORS[rl] }}>
                      {ioc.risk_score}
                    </span>
                    {ioc.sighting_count > 1 && (
                      <span className="text-[8px] text-muted-foreground">×{ioc.sighting_count}</span>
                    )}
                  </div>
                </div>
                <ChevronRight className="h-3 w-3 text-muted-foreground/40 group-hover:text-primary shrink-0" />
              </button>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

/* ─── Main Page ─────────────────────────────────────────── */

export default function IOCDatabasePage() {
  const [data, setData] = useState<IOCListResponse | null>(null);
  const [stats, setStats] = useState<IOCStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [riskFilter, setRiskFilter] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState("last_seen");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [enrichTarget, setEnrichTarget] = useState<IOCItem | null>(null);
  const [enrichData, setEnrichData] = useState<IOCEnrichmentResult | null>(null);
  const [enrichLoading, setEnrichLoading] = useState(false);
  const pageSize = 50;

  /* Debounced search */
  const [debouncedSearch, setDebouncedSearch] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 400);
    return () => clearTimeout(t);
  }, [search]);

  /* Risk filter → min/max risk mapping */
  const riskRange = useMemo(() => {
    if (!riskFilter) return {};
    const map: Record<string, { min_risk: number; max_risk: number }> = {
      critical: { min_risk: 80, max_risk: 100 },
      high: { min_risk: 60, max_risk: 79 },
      medium: { min_risk: 40, max_risk: 59 },
      low: { min_risk: 0, max_risk: 39 },
    };
    return map[riskFilter] || {};
  }, [riskFilter]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, unknown> = {
        page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_dir: sortDir,
        ...riskRange,
      };
      if (debouncedSearch) params.search = debouncedSearch;
      if (typeFilter) params.ioc_type = typeFilter;

      const [iocs, iocStats] = await Promise.all([
        getIOCs(params as any),
        stats ? Promise.resolve(stats) : getIOCStats(),
      ]);
      setData(iocs);
      if (!stats) setStats(iocStats);
    } catch (err) {
      console.error("Failed to fetch IOCs", err);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, pageSize, sortBy, sortDir, debouncedSearch, typeFilter, riskRange]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    setPage(1);
  }, [debouncedSearch, typeFilter, riskFilter]);

  const handleCopy = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 1500);
  };

  const handleSort = (col: string) => {
    if (sortBy === col) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortBy(col);
      setSortDir("desc");
    }
  };

  const handleEnrich = async (ioc: IOCItem) => {
    setEnrichTarget(ioc);
    setEnrichData(null);
    setEnrichLoading(true);
    try {
      const result = await enrichIOC(ioc.value, ioc.ioc_type);
      setEnrichData(result);
    } catch {
      setEnrichData({ virustotal: null, shodan: null, errors: ["Failed to enrich IOC"] });
    } finally {
      setEnrichLoading(false);
    }
  };

  const SortIcon = ({ col }: { col: string }) => {
    if (sortBy !== col) return <ArrowUpDown className="h-3 w-3 ml-1 text-muted-foreground/40" />;
    return sortDir === "asc" ? (
      <ChevronUp className="h-3 w-3 ml-1 text-primary" />
    ) : (
      <ChevronDown className="h-3 w-3 ml-1 text-primary" />
    );
  };

  /* Chart data */
  const typeDistribution = (stats?.type_distribution || []).map((t) => ({
    name: t.name.charAt(0).toUpperCase() + t.name.slice(1).replace(/_/g, " "),
    value: t.count,
    color: IOC_TYPE_COLORS[t.name] || IOC_TYPE_COLORS.other,
  }));

  const riskDistribution = stats
    ? [
        { name: "Critical", value: stats.risk_distribution.critical || 0, color: "#ef4444" },
        { name: "High", value: stats.risk_distribution.high || 0, color: "#f97316" },
        { name: "Medium", value: stats.risk_distribution.medium || 0, color: "#eab308" },
        { name: "Low", value: stats.risk_distribution.low || 0, color: "#22c55e" },
      ]
    : [];

  const types = (stats?.type_distribution || []).map((t) => t.name);

  if (loading && !data) return <Loading text="Loading IOC database..." />;

  return (
    <div className="p-4 lg:p-6 space-y-4">
      {/* ── Header ─────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-tight flex items-center gap-2">
            <Database className="h-5 w-5 text-primary" />
            IOC Database
          </h1>
          <p className="text-[11px] text-muted-foreground mt-0.5">
            {(stats?.total_iocs ?? 0).toLocaleString()} indicators across{" "}
            {stats?.unique_sources ?? 0} sources
          </p>
        </div>
        {stats && stats.avg_risk_score > 0 && (
          <div className="hidden sm:flex items-center gap-4">
            <div className="text-center">
              <div className="text-[10px] text-muted-foreground">Avg Risk</div>
              <RiskGauge score={Math.round(stats.avg_risk_score)} size={44} />
            </div>
          </div>
        )}
      </div>

      {/* ── Stat Cards (compact) ───────────────────────── */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
          <Card className="bg-blue-500/[0.04] border-blue-500/10">
            <CardContent className="p-2.5 flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-blue-500/10">
                <Database className="h-3.5 w-3.5 text-blue-400" />
              </div>
              <div>
                <p className="text-base font-bold leading-none">{stats.total_iocs.toLocaleString()}</p>
                <p className="text-[9px] text-muted-foreground mt-0.5">Total IOCs</p>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-red-500/[0.04] border-red-500/10">
            <CardContent className="p-2.5 flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-red-500/10">
                <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
              </div>
              <div>
                <p className="text-base font-bold leading-none">{stats.high_risk_count.toLocaleString()}</p>
                <p className="text-[9px] text-muted-foreground mt-0.5">Critical + High</p>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-cyan-500/[0.04] border-cyan-500/10">
            <CardContent className="p-2.5 flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-cyan-500/10">
                <Clock className="h-3.5 w-3.5 text-cyan-400" />
              </div>
              <div>
                <p className="text-base font-bold leading-none">{stats.recent_24h.toLocaleString()}</p>
                <p className="text-[9px] text-muted-foreground mt-0.5">Active (24h)</p>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-purple-500/[0.04] border-purple-500/10">
            <CardContent className="p-2.5 flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-purple-500/10">
                <Eye className="h-3.5 w-3.5 text-purple-400" />
              </div>
              <div>
                <p className="text-base font-bold leading-none">{types.length}</p>
                <p className="text-[9px] text-muted-foreground mt-0.5">IOC Types</p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Risk Distribution Bar ──────────────────────── */}
      {stats && <RiskDistBar dist={stats.risk_distribution} />}

      {/* ── Visualization Row ──────────────────────────── */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Type donut */}
          <Card>
            <CardContent className="pt-3 pb-2 px-3">
              <p className="text-[10px] font-semibold text-muted-foreground mb-1">By Type</p>
              <DonutChart
                data={typeDistribution}
                centerValue={stats.total_iocs}
                centerLabel="IOCs"
                height={130}
                innerRadius={35}
                outerRadius={50}
              />
            </CardContent>
          </Card>

          {/* Risk donut */}
          <Card>
            <CardContent className="pt-3 pb-2 px-3">
              <p className="text-[10px] font-semibold text-muted-foreground mb-1">By Risk Level</p>
              <DonutChart
                data={riskDistribution}
                centerValue={stats.high_risk_count}
                centerLabel="High+"
                height={130}
                innerRadius={35}
                outerRadius={50}
              />
            </CardContent>
          </Card>

          {/* Tags + Geo + Sources compact */}
          <Card>
            <CardContent className="pt-3 pb-2 px-3 space-y-2.5">
              {/* Sources */}
              <div>
                <p className="text-[10px] font-semibold text-muted-foreground mb-1">
                  Sources ({stats.unique_sources})
                </p>
                <div className="flex flex-wrap gap-1">
                  {stats.source_distribution.slice(0, 6).map((s) => (
                    <Badge key={s.name} variant="secondary" className="text-[8px] px-1.5 py-0 h-4">
                      {s.name} <span className="ml-1 opacity-60">{s.count}</span>
                    </Badge>
                  ))}
                </div>
              </div>

              {/* Tags */}
              {stats.tag_distribution.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold text-muted-foreground mb-1">Top Tags</p>
                  <div className="flex flex-wrap gap-1">
                    {stats.tag_distribution.slice(0, 8).map((t) => (
                      <Badge key={t.name} variant="outline" className="text-[8px] px-1.5 py-0 h-4 border-primary/20">
                        {t.name} <span className="ml-1 opacity-50">{t.count}</span>
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Geo */}
              {stats.geo_distribution.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold text-muted-foreground mb-1 flex items-center gap-1">
                    <MapPin className="h-2.5 w-2.5" /> Geo
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {stats.geo_distribution.slice(0, 8).map((g) => (
                      <span key={g.name} className="text-[9px] text-muted-foreground">
                        {g.name} <span className="font-semibold text-foreground/70">{g.count}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Hot IOCs ───────────────────────────────────── */}
      {stats && <HotIOCsStrip items={stats.top_risky} onEnrich={handleEnrich} />}

      {/* ── Search + Filters ───────────────────────────── */}
      <div className="space-y-2">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search IOCs by value (IP, domain, URL, hash, CVE)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full h-9 pl-10 pr-4 rounded-lg bg-muted/40 border border-border/50 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
          />
          {search && (
            <button onClick={() => setSearch("")} className="absolute right-3 top-1/2 -translate-y-1/2">
              <X className="h-3.5 w-3.5 text-muted-foreground hover:text-foreground" />
            </button>
          )}
        </div>

        <div className="flex items-center gap-4 flex-wrap">
          {/* Type pills */}
          <div className="flex items-center gap-1 flex-wrap">
            <span className="text-[9px] text-muted-foreground mr-0.5">Type:</span>
            <button
              onClick={() => setTypeFilter(null)}
              className={`px-2 py-0.5 rounded-full text-[10px] transition-colors ${
                !typeFilter ? "bg-primary text-primary-foreground" : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
              }`}
            >
              All
            </button>
            {types.map((t) => (
              <button
                key={t}
                onClick={() => setTypeFilter(t === typeFilter ? null : t)}
                className={`px-2 py-0.5 rounded-full text-[10px] transition-colors flex items-center gap-1 ${
                  typeFilter === t ? "bg-primary text-primary-foreground" : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
                }`}
              >
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: IOC_TYPE_COLORS[t] || IOC_TYPE_COLORS.other }} />
                {t.charAt(0).toUpperCase() + t.slice(1).replace(/_/g, " ")}
              </button>
            ))}
          </div>

          {/* Risk pills */}
          <div className="flex items-center gap-1">
            <span className="text-[9px] text-muted-foreground mr-0.5">Risk:</span>
            {(["critical", "high", "medium", "low"] as const).map((level) => (
              <button
                key={level}
                onClick={() => setRiskFilter(riskFilter === level ? null : level)}
                className={`px-2 py-0.5 rounded-full text-[10px] capitalize transition-colors flex items-center gap-1 ${
                  riskFilter === level ? RISK_BG[level] + " border" : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
                }`}
              >
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: RISK_COLORS[level] }} />
                {level}
                {stats && (
                  <span className="opacity-50 ml-0.5">{(stats.risk_distribution[level] || 0).toLocaleString()}</span>
                )}
              </button>
            ))}
          </div>

          {/* Count */}
          <div className="text-[10px] text-muted-foreground ml-auto">
            <span className="font-semibold text-foreground">{data?.total ?? 0}</span> results
          </div>
        </div>
      </div>

      {/* ── IOC Table ──────────────────────────────────── */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border/40 bg-muted/20">
                  <th className="text-left py-2 px-3 text-muted-foreground font-medium w-[40%]">IOC Value</th>
                  <th className="text-left py-2 px-3 text-muted-foreground font-medium cursor-pointer select-none" onClick={() => handleSort("ioc_type")}>
                    <span className="flex items-center">Type<SortIcon col="ioc_type" /></span>
                  </th>
                  <th className="text-center py-2 px-3 text-muted-foreground font-medium cursor-pointer select-none" onClick={() => handleSort("risk_score")}>
                    <span className="flex items-center justify-center">Risk<SortIcon col="risk_score" /></span>
                  </th>
                  <th className="text-center py-2 px-3 text-muted-foreground font-medium cursor-pointer select-none" onClick={() => handleSort("sighting_count")}>
                    <span className="flex items-center justify-center">Seen<SortIcon col="sighting_count" /></span>
                  </th>
                  <th className="text-left py-2 px-3 text-muted-foreground font-medium hidden lg:table-cell">Tags / Geo</th>
                  <th className="text-left py-2 px-3 text-muted-foreground font-medium hidden md:table-cell">Sources</th>
                  <th className="text-left py-2 px-3 text-muted-foreground font-medium cursor-pointer select-none" onClick={() => handleSort("last_seen")}>
                    <span className="flex items-center">Last Seen<SortIcon col="last_seen" /></span>
                  </th>
                  <th className="py-2 px-3 w-16"></th>
                </tr>
              </thead>
              <tbody>
                {data?.items.map((ioc, idx) => {
                  const rl = riskLabel(ioc.risk_score);
                  const rCol = RISK_COLORS[rl];
                  const typeIcon = IOC_TYPE_ICONS[ioc.ioc_type] || <Database className="h-3 w-3" />;

                  return (
                    <tr key={ioc.id} className="border-b border-border/10 hover:bg-muted/15 transition-colors group">
                      {/* Value */}
                      <td className="py-1.5 px-3">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="shrink-0 opacity-50" style={{ color: IOC_TYPE_COLORS[ioc.ioc_type] || IOC_TYPE_COLORS.other }}>
                            {typeIcon}
                          </span>
                          <span className="font-mono text-[11px] truncate" title={ioc.value}>{ioc.value}</span>
                        </div>
                      </td>

                      {/* Type */}
                      <td className="py-1.5 px-3">
                        <Badge
                          variant="secondary"
                          className="text-[9px] px-1.5 py-0 h-4"
                          style={{
                            background: (IOC_TYPE_COLORS[ioc.ioc_type] || IOC_TYPE_COLORS.other) + "18",
                            color: IOC_TYPE_COLORS[ioc.ioc_type] || IOC_TYPE_COLORS.other,
                          }}
                        >
                          {ioc.ioc_type}
                        </Badge>
                      </td>

                      {/* Risk with inline bar */}
                      <td className="py-1.5 px-3">
                        <div className="flex flex-col items-center gap-0.5">
                          <span className="text-[11px] font-bold tabular-nums" style={{ color: rCol }}>
                            {ioc.risk_score}
                          </span>
                          <div className="w-10 h-1 rounded-full bg-muted/40 overflow-hidden">
                            <div
                              className="h-full rounded-full transition-all"
                              style={{ width: `${ioc.risk_score}%`, backgroundColor: rCol }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* Sightings */}
                      <td className="py-1.5 px-3 text-center">
                        <span className="font-medium tabular-nums">{ioc.sighting_count}</span>
                      </td>

                      {/* Tags + Geo */}
                      <td className="py-1.5 px-3 hidden lg:table-cell">
                        <div className="flex flex-wrap gap-0.5 max-w-[180px]">
                          {ioc.tags.slice(0, 3).map((t) => (
                            <Badge key={t} variant="outline" className="text-[8px] px-1 py-0 h-3.5 border-primary/15 text-muted-foreground">
                              {t}
                            </Badge>
                          ))}
                          {ioc.tags.length > 3 && (
                            <span className="text-[8px] text-muted-foreground/50">+{ioc.tags.length - 3}</span>
                          )}
                          {ioc.geo.length > 0 && (
                            <span className="text-[8px] text-muted-foreground/60 flex items-center gap-0.5">
                              <MapPin className="h-2 w-2" />{ioc.geo.slice(0, 2).join(", ")}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Sources */}
                      <td className="py-1.5 px-3 hidden md:table-cell">
                        <div className="flex flex-wrap gap-0.5 max-w-[140px]">
                          {ioc.source_names.slice(0, 2).map((s) => (
                            <span key={s} className="text-[9px] text-muted-foreground">{s}</span>
                          ))}
                          {ioc.source_names.length > 2 && (
                            <span className="text-[8px] text-muted-foreground/40">+{ioc.source_names.length - 2}</span>
                          )}
                        </div>
                      </td>

                      {/* Last Seen */}
                      <td className="py-1.5 px-3 text-muted-foreground text-[10px] whitespace-nowrap">
                        {timeAgo(ioc.last_seen)}
                      </td>

                      {/* Actions */}
                      <td className="py-1.5 px-3">
                        <div className="flex items-center gap-0.5">
                          <button
                            onClick={() => handleEnrich(ioc)}
                            className="p-1 rounded hover:bg-primary/10 transition-colors"
                            title="Enrich with VT/Shodan"
                          >
                            <Zap className={`h-3.5 w-3.5 ${enrichTarget?.id === ioc.id && enrichLoading ? "text-yellow-400 animate-pulse" : "text-yellow-500/50 hover:text-yellow-400"}`} />
                          </button>
                          <button
                            onClick={() => handleCopy(ioc.value, idx)}
                            className="p-1 rounded hover:bg-muted/40 transition-colors"
                            title="Copy IOC value"
                          >
                            {copiedIdx === idx ? (
                              <Check className="h-3.5 w-3.5 text-green-400" />
                            ) : (
                              <Copy className="h-3.5 w-3.5 text-muted-foreground/50 hover:text-muted-foreground" />
                            )}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {data?.items.length === 0 && (
              <div className="py-12 text-center text-xs text-muted-foreground/60">No IOCs match your filters</div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* ── Pagination ─────────────────────────────────── */}
      {data && data.pages > 1 && <Pagination page={data.page} pages={data.pages} onPageChange={setPage} />}

      {/* ── Enrichment Side Panel ──────────────────────── */}
      {enrichTarget && (
        <>
          <div className="fixed inset-0 bg-black/30 z-40" onClick={() => { setEnrichTarget(null); setEnrichData(null); }} />
          <div className="fixed inset-y-0 right-0 w-full max-w-md bg-background border-l border-border shadow-2xl z-50 flex flex-col animate-in slide-in-from-right duration-200">
            {/* Header */}
            <div className="flex items-center justify-between p-3 border-b border-border bg-muted/20">
              <div className="flex items-center gap-2 min-w-0">
                <Zap className="h-4 w-4 text-yellow-400 shrink-0" />
                <div className="min-w-0">
                  <span className="text-xs font-semibold block truncate">{enrichTarget.value}</span>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Badge
                      variant="secondary"
                      className="text-[8px] px-1 py-0 h-3.5"
                      style={{
                        background: (IOC_TYPE_COLORS[enrichTarget.ioc_type] || "#6b7280") + "20",
                        color: IOC_TYPE_COLORS[enrichTarget.ioc_type] || "#6b7280",
                      }}
                    >
                      {enrichTarget.ioc_type}
                    </Badge>
                    <span className="text-[10px] font-bold" style={{ color: RISK_COLORS[riskLabel(enrichTarget.risk_score)] }}>
                      Risk: {enrichTarget.risk_score}
                    </span>
                  </div>
                </div>
              </div>
              <button onClick={() => { setEnrichTarget(null); setEnrichData(null); }} className="p-1 rounded hover:bg-muted/40">
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3">
              {enrichLoading && (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="h-6 w-6 animate-spin text-primary" />
                  <span className="ml-2 text-sm text-muted-foreground">Querying VT & Shodan...</span>
                </div>
              )}

              {enrichData && !enrichLoading && (
                <>
                  {enrichData.errors.length > 0 && (
                    <div className="space-y-1">
                      {enrichData.errors.map((e, i) => (
                        <div key={i} className="text-xs text-yellow-400 bg-yellow-400/10 rounded px-2 py-1">{e}</div>
                      ))}
                    </div>
                  )}

                  {/* VirusTotal */}
                  <Card>
                    <CardContent className="pt-3 pb-2 px-3">
                      <div className="flex items-center gap-1.5 mb-2">
                        <ShieldAlert className="h-3.5 w-3.5 text-blue-400" />
                        <span className="text-[11px] font-semibold">VirusTotal</span>
                      </div>
                      {enrichData.virustotal ? (
                        <VTResultCard data={enrichData.virustotal as Record<string, any>} iocType={enrichTarget.ioc_type} />
                      ) : (
                        <p className="text-xs text-muted-foreground">No VirusTotal data available</p>
                      )}
                    </CardContent>
                  </Card>

                  {/* Shodan */}
                  {(enrichTarget.ioc_type === "ip" || enrichTarget.ioc_type === "domain") && (
                    <Card>
                      <CardContent className="pt-3 pb-2 px-3">
                        <div className="flex items-center gap-1.5 mb-2">
                          <Server className="h-3.5 w-3.5 text-orange-400" />
                          <span className="text-[11px] font-semibold">Shodan</span>
                        </div>
                        {enrichData.shodan && (enrichData.shodan as any).found ? (
                          <ShodanResultCard data={enrichData.shodan as Record<string, any>} />
                        ) : (
                          <p className="text-xs text-muted-foreground">No Shodan data available</p>
                        )}
                      </CardContent>
                    </Card>
                  )}
                </>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/* ── Enrichment sub-components ─────────────────────────── */

function VTResultCard({ data, iocType }: { data: Record<string, any>; iocType: string }) {
  if (data.found === false) {
    return <p className="text-xs text-muted-foreground">{data.message || "Not found in VirusTotal"}</p>;
  }

  const malicious = data.malicious || 0;
  const total = data.total_engines || 0;
  const pct = total ? Math.round((malicious / total) * 100) : 0;
  const barColor = malicious > 5 ? "#ef4444" : malicious > 0 ? "#f97316" : "#22c55e";

  return (
    <div className="space-y-2.5">
      <div>
        <div className="flex justify-between text-[10px] font-medium mb-1">
          <span>Detection</span>
          <span style={{ color: barColor }}>{malicious}/{total} engines ({pct}%)</span>
        </div>
        <div className="h-2 rounded-full bg-muted/40 overflow-hidden">
          <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: barColor }} />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px]">
        {data.reputation !== undefined && <DetailRow label="Reputation" value={String(data.reputation)} />}
        {data.country && <DetailRow label="Country" value={data.country} />}
        {data.as_owner && <DetailRow label="AS Owner" value={data.as_owner} />}
        {data.asn && <DetailRow label="ASN" value={String(data.asn)} />}
        {data.network && <DetailRow label="Network" value={data.network} />}
        {data.registrar && <DetailRow label="Registrar" value={data.registrar} />}
        {data.name && <DetailRow label="File Name" value={data.name} />}
        {data.type_description && <DetailRow label="File Type" value={data.type_description} />}
        {data.size && <DetailRow label="Size" value={`${(data.size / 1024).toFixed(1)} KB`} />}
        {data.suspicious > 0 && <DetailRow label="Suspicious" value={String(data.suspicious)} />}
        {data.harmless > 0 && <DetailRow label="Harmless" value={String(data.harmless)} />}
      </div>

      {data.tags && data.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {data.tags.slice(0, 10).map((t: string) => (
            <Badge key={t} variant="secondary" className="text-[9px]">{t}</Badge>
          ))}
        </div>
      )}
    </div>
  );
}

function ShodanResultCard({ data }: { data: Record<string, any> }) {
  return (
    <div className="space-y-2.5">
      {data.ports && data.ports.length > 0 && (
        <div>
          <p className="text-[10px] font-medium text-muted-foreground mb-1">Open Ports ({data.ports.length})</p>
          <div className="flex flex-wrap gap-1">
            {data.ports.slice(0, 20).map((p: number) => (
              <Badge key={p} variant="outline" className="text-[9px] font-mono">{p}</Badge>
            ))}
          </div>
        </div>
      )}

      {data.vulns && data.vulns.length > 0 && (
        <div>
          <p className="text-[10px] font-medium text-red-400 mb-1">Vulnerabilities ({data.vulns.length})</p>
          <div className="flex flex-wrap gap-1">
            {data.vulns.slice(0, 15).map((v: string) => (
              <Badge key={v} variant="destructive" className="text-[9px]">{v}</Badge>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px]">
        {data.org && <DetailRow label="Organization" value={data.org} />}
        {data.isp && <DetailRow label="ISP" value={data.isp} />}
        {data.country_name && <DetailRow label="Country" value={data.country_name} />}
        {data.city && <DetailRow label="City" value={data.city} />}
        {data.os && <DetailRow label="OS" value={data.os} />}
        {data.services_count > 0 && <DetailRow label="Services" value={String(data.services_count)} />}
      </div>

      {data.hostnames && data.hostnames.length > 0 && (
        <div>
          <p className="text-[10px] font-medium text-muted-foreground mb-1">Hostnames</p>
          <div className="text-[11px] text-muted-foreground font-mono space-y-0.5">
            {data.hostnames.slice(0, 5).map((h: string) => (
              <div key={h}>{h}</div>
            ))}
          </div>
        </div>
      )}

      {data.tags && data.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {data.tags.map((t: string) => (
            <Badge key={t} variant="secondary" className="text-[9px]">{t}</Badge>
          ))}
        </div>
      )}
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <>
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium truncate" title={value}>{value}</span>
    </>
  );
}
