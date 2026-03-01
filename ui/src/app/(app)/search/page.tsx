"use client";

import React, { useState, useCallback, useEffect, useRef } from "react";
import { useSearchParams } from "next/navigation";
import { useAppStore } from "@/store";
import { Pagination } from "@/components/Pagination";
import { DonutChart, HorizontalBarChart } from "@/components/charts";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import type { SearchFilters, IntelItem } from "@/types";
import {
  getSearchStats,
  enrichIOC,
  liveLookup,
  type SearchAggStats,
  type IOCEnrichmentResult,
  type LiveLookupResult,
  type LiveLookupResponse,
} from "@/lib/api";
import {
  Search as SearchIcon,
  Loader2,
  Target,
  Fingerprint,
  Globe,
  Link as LinkIcon,
  Mail,
  Hash,
  AlertCircle,
  ChevronUp,
  ChevronDown,
  ArrowUpDown,
  Copy,
  Check,
  ExternalLink,
  Database,
  Shield,
  Zap,
  X,
  Server,
  ShieldAlert,
  TrendingUp,
  Filter,
  BarChart3,
  Eye,
  Wifi,
  Sparkles,
  Radio,
  Calendar,
  User,
  Package,
  ChevronRight,
  FileText,
  Clock,
} from "lucide-react";

/* ── Constants ────────────────────────────────────────── */

const TYPE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  ip: Globe,
  domain: Globe,
  url: LinkIcon,
  email: Mail,
  cve: AlertCircle,
  hash_md5: Fingerprint,
  hash_sha1: Fingerprint,
  hash_sha256: Fingerprint,
  file: Hash,
  other: Target,
};

const TYPE_COLORS: Record<string, string> = {
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

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
  unknown: "#6b7280",
};

const SORT_FIELDS = [
  { key: "risk_score", label: "Risk" },
  { key: "published_at", label: "Published" },
  { key: "ingested_at", label: "Ingested" },
  { key: "severity", label: "Severity" },
  { key: "confidence", label: "Confidence" },
  { key: "source_reliability", label: "Reliability" },
  { key: "title", label: "Title" },
];

function severityLabel(score: number) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function timeAgo(dateStr: string | null) {
  if (!dateStr) return "\u2014";
  const d = new Date(dateStr);
  const now = new Date();
  const diff = now.getTime() - d.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
}

/* ── Main Component ───────────────────────────────────── */

export default function SearchPage() {
  const { searchResult, searchLoading, executeSearch } = useAppStore();
  const searchParams = useSearchParams();

  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState("risk_score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [feedFilter, setFeedFilter] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<string | null>(null);

  const [stats, setStats] = useState<SearchAggStats | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showCharts, setShowCharts] = useState(false);

  // Enrichment panel
  const [enrichTarget, setEnrichTarget] = useState<IntelItem | null>(null);
  const [enrichData, setEnrichData] = useState<IOCEnrichmentResult | null>(null);
  const [enrichLoading, setEnrichLoading] = useState(false);

  // Live internet lookup
  const [liveResult, setLiveResult] = useState<LiveLookupResponse | null>(null);
  const [liveLoading, setLiveLoading] = useState(false);
  const [liveDetailResult, setLiveDetailResult] = useState<LiveLookupResult | null>(null);

  // Debounced search
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => setDebouncedQuery(query), 400);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [query]);

  // Auto-search when debounced query, filters, or sort change
  useEffect(() => {
    if (!debouncedQuery.trim()) return;
    setPage(1);
    doSearch(1, debouncedQuery);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedQuery, feedFilter, severityFilter, typeFilter, sortBy, sortDir]);

  // Load stats on mount
  useEffect(() => {
    getSearchStats().then(setStats).catch(() => {});
  }, []);

  // Read ?q= from URL on mount (from header search)
  useEffect(() => {
    const q = searchParams.get("q");
    if (q && q.trim()) {
      setQuery(q.trim());
      setDebouncedQuery(q.trim());
      doSearch(1, q.trim());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const doSearch = useCallback(
    (p: number, q?: string) => {
      const searchQuery = (q ?? debouncedQuery).trim();
      if (!searchQuery) return;
      const filters: SearchFilters = {
        query: searchQuery,
        page: p,
        page_size: 20,
        sort_by: sortBy,
        sort_dir: sortDir,
      };
      if (feedFilter) filters.feed_type = feedFilter as any;
      if (severityFilter) filters.severity = severityFilter as any;
      if (typeFilter) filters.asset_type = typeFilter as any;
      executeSearch(filters);
    },
    [debouncedQuery, sortBy, sortDir, feedFilter, severityFilter, typeFilter, executeSearch]
  );

  const handlePageChange = (p: number) => {
    setPage(p);
    doSearch(p);
  };

  const handleSort = (col: string) => {
    if (sortBy === col) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortBy(col);
      setSortDir("desc");
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const handleEnrich = async (item: IntelItem) => {
    setEnrichTarget(item);
    setEnrichData(null);
    setEnrichLoading(true);
    try {
      const iocType = item.asset_type || "other";
      const iocValue = item.source_ref || item.title;
      const result = await enrichIOC(iocValue, iocType);
      setEnrichData(result);
    } catch {
      setEnrichData({ virustotal: null, shodan: null, errors: ["Enrichment failed"] });
    } finally {
      setEnrichLoading(false);
    }
  };

  const handleLiveLookup = async () => {
    const q = (debouncedQuery || query).trim();
    if (!q) return;
    setLiveLoading(true);
    setLiveResult(null);
    try {
      const data = await liveLookup(q);
      setLiveResult(data);
    } catch {
      setLiveResult({ query: q, detected_type: null, timestamp: new Date().toISOString(), sources_queried: [], results: [], ai_summary: null, errors: ["Live lookup failed. Try again later."] });
    } finally {
      setLiveLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      setDebouncedQuery(query);
      doSearch(1, query);
      setLiveResult(null);
    }
  };

  const clearFilters = () => {
    setFeedFilter(null);
    setSeverityFilter(null);
    setTypeFilter(null);
  };

  const hasFilters = !!(feedFilter || severityFilter || typeFilter);

  const DetectedIcon = searchResult?.detected_type
    ? TYPE_ICONS[searchResult.detected_type] || Target
    : Target;

  // Chart data
  const typeDistribution = (stats?.type_distribution || []).map((t) => ({
    name: t.name.charAt(0).toUpperCase() + t.name.slice(1).replace(/_/g, " "),
    value: t.count,
    color: TYPE_COLORS[t.name] || TYPE_COLORS.other,
  }));

  const SortIcon = ({ col }: { col: string }) => {
    if (sortBy !== col) return <ArrowUpDown className="h-3 w-3 ml-0.5 text-muted-foreground/40" />;
    return sortDir === "asc" ? (
      <ChevronUp className="h-3 w-3 ml-0.5 text-primary" />
    ) : (
      <ChevronDown className="h-3 w-3 ml-0.5 text-primary" />
    );
  };

  return (
    <div className="p-4 lg:p-6 space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <SearchIcon className="h-5 w-5 text-primary" />
            IOC Search &amp; Intelligence
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Search by CVE, IP, domain, URL, hash, keyword &mdash; auto-detected with enrichment
          </p>
        </div>
        {stats && (
          <div className="hidden lg:flex items-center gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Database className="h-3.5 w-3.5" />
              {stats.total.toLocaleString()} intel items
            </span>
            <span className="flex items-center gap-1">
              <TrendingUp className="h-3.5 w-3.5" />
              Avg risk: {stats.avg_risk}
            </span>
            <span className="flex items-center gap-1">
              <Shield className="h-3.5 w-3.5 text-red-400" />
              {stats.kev_count} KEVs
            </span>
          </div>
        )}
      </div>

      {/* Search bar + chart toggle + search button */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="CVE-2024-3094, 8.8.8.8, evil.com, SHA256 hash, ransomware..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="w-full h-10 pl-10 pr-4 rounded-lg bg-muted/40 border border-border/50 text-sm focus:outline-none focus:ring-2 focus:ring-primary/30 transition-all"
          />
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowCharts(!showCharts)}
          className={`h-10 px-3 ${showCharts ? "bg-primary/10 text-primary" : ""}`}
          title="Toggle charts"
        >
          <BarChart3 className="h-4 w-4" />
        </Button>
        <Button
          onClick={() => {
            setDebouncedQuery(query);
            doSearch(1, query);
          }}
          disabled={searchLoading || !query.trim()}
          className="h-10"
        >
          {searchLoading ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <SearchIcon className="h-4 w-4 mr-1" />
          )}
          Search
        </Button>
      </div>

      {/* Filter pills row */}
      {stats && (
        <div className="space-y-2">
          {/* Type pills */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider w-12">
              Type
            </span>
            <button
              onClick={() => setTypeFilter(null)}
              className={`px-2.5 py-1 rounded-full text-[11px] transition-colors ${
                !typeFilter
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
              }`}
            >
              All
            </button>
            {stats.type_distribution.map((t) => {
              const Icon = TYPE_ICONS[t.name] || Target;
              return (
                <button
                  key={t.name}
                  onClick={() => setTypeFilter(t.name === typeFilter ? null : t.name)}
                  className={`px-2.5 py-1 rounded-full text-[11px] transition-colors flex items-center gap-1 ${
                    typeFilter === t.name
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
                  }`}
                >
                  <Icon className="h-3 w-3" />
                  {t.name.replace(/_/g, " ")} <span className="opacity-60">({t.count})</span>
                </button>
              );
            })}
          </div>

          {/* Severity pills */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider w-12">
              Severity
            </span>
            <button
              onClick={() => setSeverityFilter(null)}
              className={`px-2.5 py-1 rounded-full text-[11px] transition-colors ${
                !severityFilter
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
              }`}
            >
              All
            </button>
            {stats.severity_distribution.map((s) => (
              <button
                key={s.name}
                onClick={() => setSeverityFilter(s.name === severityFilter ? null : s.name)}
                className={`px-2.5 py-1 rounded-full text-[11px] transition-colors ${
                  severityFilter === s.name
                    ? "text-white"
                    : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
                }`}
                style={
                  severityFilter === s.name
                    ? { background: SEVERITY_COLORS[s.name] || "#6b7280" }
                    : {}
                }
              >
                {s.name} <span className="opacity-60">({s.count})</span>
              </button>
            ))}
          </div>

          {/* Feed pills */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider w-12">
              Feed
            </span>
            <button
              onClick={() => setFeedFilter(null)}
              className={`px-2.5 py-1 rounded-full text-[11px] transition-colors ${
                !feedFilter
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
              }`}
            >
              All
            </button>
            {stats.feed_distribution.map((f) => (
              <button
                key={f.name}
                onClick={() => setFeedFilter(f.name === feedFilter ? null : f.name)}
                className={`px-2.5 py-1 rounded-full text-[11px] transition-colors ${
                  feedFilter === f.name
                    ? "bg-primary text-primary-foreground"
                    : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
                }`}
              >
                {f.name.replace(/_/g, " ")} <span className="opacity-60">({f.count})</span>
              </button>
            ))}
            {hasFilters && (
              <button
                onClick={clearFilters}
                className="ml-2 px-2 py-1 rounded-full text-[11px] text-red-400 bg-red-400/10 hover:bg-red-400/20 transition-colors flex items-center gap-1"
              >
                <X className="h-3 w-3" /> Clear filters
              </button>
            )}
          </div>
        </div>
      )}

      {/* Charts (collapsible) */}
      {showCharts && stats && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Card>
            <CardHeader className="pb-1 pt-3 px-4">
              <CardTitle className="text-xs font-semibold">Type Distribution</CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-3">
              <DonutChart
                data={typeDistribution}
                centerValue={stats.total}
                centerLabel="Items"
                height={180}
                innerRadius={45}
                outerRadius={65}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-1 pt-3 px-4">
              <CardTitle className="text-xs font-semibold">Source Distribution</CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-3">
              <HorizontalBarChart
                data={stats.source_distribution.map((s) => ({
                  name: s.name,
                  value: s.count,
                  color: "#3b82f6",
                }))}
                height={Math.max(140, stats.source_distribution.length * 32)}
              />
            </CardContent>
          </Card>
        </div>
      )}

      {/* Results */}
      {searchResult && (
        <div className="space-y-3">
          {/* Result info bar */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3 text-xs">
              <span className="text-muted-foreground">
                <span className="font-semibold text-foreground">
                  {searchResult.total.toLocaleString()}
                </span>{" "}
                results for{" "}
                <span className="font-medium text-foreground">
                  &quot;{searchResult.query}&quot;
                </span>
              </span>
              {searchResult.detected_type && (
                <Badge variant="secondary" className="gap-1 text-[10px]">
                  <DetectedIcon className="h-3 w-3" />
                  {searchResult.detected_type}
                </Badge>
              )}
            </div>
            {searchResult.results.length > 0 && (
              <Button
                onClick={handleLiveLookup}
                disabled={liveLoading}
                variant="outline"
                size="sm"
                className="gap-1.5 text-[11px] h-7"
              >
                {liveLoading ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Wifi className="h-3 w-3" />
                )}
                Search Internet
              </Button>
            )}
          </div>

          {/* Results Table */}
          {searchLoading ? (
            <Card>
              <CardContent className="py-12 flex items-center justify-center gap-2">
                <Loader2 className="h-5 w-5 animate-spin text-primary" />
                <span className="text-sm text-muted-foreground">Searching...</span>
              </CardContent>
            </Card>
          ) : searchResult.results.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <SearchIcon className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p className="text-lg">No results in local database</p>
                <p className="text-sm mb-4">
                  This IOC wasn&apos;t found in ingested feeds. Search the internet for live intelligence.
                </p>
                <Button
                  onClick={handleLiveLookup}
                  disabled={liveLoading}
                  className="gap-2"
                  variant="outline"
                >
                  {liveLoading ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Wifi className="h-4 w-4" />
                  )}
                  Search Internet (NVD, VT, Shodan, AbuseIPDB, OTX…)
                </Button>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border/40 bg-muted/20">
                        <th className="text-left py-2.5 px-3 text-muted-foreground font-medium w-[35%]">
                          Title / IOC
                        </th>
                        <th className="text-left py-2.5 px-2 text-muted-foreground font-medium">
                          Type
                        </th>
                        {SORT_FIELDS.slice(0, 5).map((sf) => (
                          <th
                            key={sf.key}
                            className="text-left py-2.5 px-2 text-muted-foreground font-medium cursor-pointer select-none hover:text-foreground transition-colors"
                            onClick={() => handleSort(sf.key)}
                          >
                            <span className="flex items-center whitespace-nowrap">
                              {sf.label}
                              <SortIcon col={sf.key} />
                            </span>
                          </th>
                        ))}
                        <th className="text-left py-2.5 px-2 text-muted-foreground font-medium">
                          Source
                        </th>
                        <th className="py-2.5 px-2 w-20"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {searchResult.results.map((item) => {
                        const rl = severityLabel(item.risk_score);
                        const rCol = SEVERITY_COLORS[rl];
                        const TypeIcon = TYPE_ICONS[item.asset_type] || Target;
                        return (
                          <tr
                            key={item.id}
                            className="border-b border-border/20 hover:bg-muted/20 transition-colors group"
                          >
                            {/* Title */}
                            <td className="py-2 px-3 max-w-[400px]">
                              <a
                                href={`/intel/${item.id}`}
                                className="font-medium text-foreground hover:text-primary transition-colors line-clamp-1"
                                title={item.title}
                              >
                                {item.title}
                              </a>
                              {item.source_ref && (
                                <div className="text-[10px] text-muted-foreground font-mono truncate mt-0.5">
                                  {item.source_ref}
                                </div>
                              )}
                            </td>
                            {/* Asset type */}
                            <td className="py-2 px-2">
                              <Badge
                                variant="secondary"
                                className="text-[10px] gap-0.5"
                                style={{
                                  background:
                                    (TYPE_COLORS[item.asset_type] || TYPE_COLORS.other) + "18",
                                  color: TYPE_COLORS[item.asset_type] || TYPE_COLORS.other,
                                }}
                              >
                                <TypeIcon className="h-2.5 w-2.5" />
                                {item.asset_type}
                              </Badge>
                            </td>
                            {/* Risk */}
                            <td className="py-2 px-2">
                              <div className="flex items-center gap-1">
                                <span className="font-bold tabular-nums" style={{ color: rCol }}>
                                  {item.risk_score}
                                </span>
                                <div className="w-8 h-1.5 rounded-full bg-muted/40 overflow-hidden">
                                  <div
                                    className="h-full rounded-full"
                                    style={{
                                      width: `${item.risk_score}%`,
                                      backgroundColor: rCol,
                                    }}
                                  />
                                </div>
                              </div>
                            </td>
                            {/* Published */}
                            <td className="py-2 px-2 text-muted-foreground whitespace-nowrap">
                              {timeAgo(item.published_at)}
                            </td>
                            {/* Ingested */}
                            <td className="py-2 px-2 text-muted-foreground whitespace-nowrap">
                              {timeAgo(item.ingested_at)}
                            </td>
                            {/* Severity */}
                            <td className="py-2 px-2">
                              <Badge
                                variant="outline"
                                className="text-[10px]"
                                style={{
                                  borderColor: SEVERITY_COLORS[item.severity] || "#6b7280",
                                  color: SEVERITY_COLORS[item.severity] || "#6b7280",
                                }}
                              >
                                {item.severity}
                              </Badge>
                            </td>
                            {/* Confidence */}
                            <td className="py-2 px-2 text-muted-foreground">
                              <span className="tabular-nums">{item.confidence}%</span>
                            </td>
                            {/* Source */}
                            <td
                              className="py-2 px-2 text-muted-foreground whitespace-nowrap truncate max-w-[120px]"
                              title={item.source_name}
                            >
                              {item.source_name}
                            </td>
                            {/* Actions */}
                            <td className="py-2 px-2">
                              <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                                <button
                                  onClick={() => handleEnrich(item)}
                                  className="p-1 rounded hover:bg-yellow-400/10 transition-colors"
                                  title="Enrich with VT/Shodan"
                                >
                                  <Zap
                                    className={`h-3.5 w-3.5 ${
                                      enrichTarget?.id === item.id && enrichLoading
                                        ? "text-yellow-400 animate-pulse"
                                        : "text-yellow-500/60 hover:text-yellow-400"
                                    }`}
                                  />
                                </button>
                                <button
                                  onClick={() =>
                                    handleCopy(item.source_ref || item.title, item.id)
                                  }
                                  className="p-1 rounded hover:bg-muted/40 transition-colors"
                                  title="Copy IOC value"
                                >
                                  {copiedId === item.id ? (
                                    <Check className="h-3.5 w-3.5 text-green-400" />
                                  ) : (
                                    <Copy className="h-3.5 w-3.5 text-muted-foreground" />
                                  )}
                                </button>
                                <a
                                  href={`/intel/${item.id}`}
                                  className="p-1 rounded hover:bg-muted/40 transition-colors"
                                  title="View details"
                                >
                                  <ExternalLink className="h-3.5 w-3.5 text-muted-foreground" />
                                </a>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Pagination */}
          {searchResult.pages > 1 && (
            <Pagination
              page={searchResult.page}
              pages={searchResult.pages}
              onPageChange={handlePageChange}
            />
          )}
        </div>
      )}

      {/* Live Internet Lookup Results */}
      {liveResult && !liveLoading && (
        <div className="space-y-3">
          {/* Live results header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Radio className="h-4 w-4 text-green-400" />
              <span className="text-sm font-semibold">Internet Intelligence</span>
              {liveResult.detected_type && (
                <Badge variant="secondary" className="text-[10px]">
                  {liveResult.detected_type}
                </Badge>
              )}
              <span className="text-[10px] text-muted-foreground">
                {liveResult.results.length} result{liveResult.results.length !== 1 ? "s" : ""} from{" "}
                {liveResult.sources_queried.length} source{liveResult.sources_queried.length !== 1 ? "s" : ""}
              </span>
            </div>
            <button
              onClick={() => setLiveResult(null)}
              className="p-1 rounded hover:bg-muted/40 transition-colors"
              title="Dismiss live results"
            >
              <X className="h-3.5 w-3.5 text-muted-foreground" />
            </button>
          </div>

          {/* Sources queried */}
          <div className="flex flex-wrap gap-1.5">
            {liveResult.sources_queried.map((src) => (
              <Badge key={src} variant="outline" className="text-[9px] gap-1">
                <Globe className="h-2.5 w-2.5" />
                {src}
              </Badge>
            ))}
          </div>

          {/* Errors */}
          {liveResult.errors.length > 0 && (
            <div className="space-y-1">
              {liveResult.errors.map((err, i) => (
                <div key={i} className="text-xs text-yellow-400 bg-yellow-400/10 rounded px-3 py-1.5 flex items-center gap-2">
                  <AlertCircle className="h-3 w-3 shrink-0" />
                  {err}
                </div>
              ))}
            </div>
          )}

          {/* AI Summary */}
          {liveResult.ai_summary && (
            <Card className="border-purple-500/30 bg-purple-500/5">
              <CardContent className="py-3 px-4">
                <div className="flex items-start gap-2">
                  <Sparkles className="h-4 w-4 text-purple-400 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-[11px] font-semibold text-purple-300 mb-1">AI Summary</p>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {liveResult.ai_summary}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Result cards */}
          {liveResult.results.length > 0 ? (
            <div className="space-y-2">
              {liveResult.results.map((r, idx) => {
                const sevColor = SEVERITY_COLORS[r.severity?.toLowerCase()] || SEVERITY_COLORS.unknown;
                const published = (r as any).published || (r as any).date_added || (r as any).created || (r as any).last_reported || "";
                const threatActor = (r as any).adversary || ((r as any).threat_classification?.suggested_threat_label) || "";
                const cveId = (r as any).cve_id || "";
                const products = (r as any).affected_products || ((r as any).product ? [(r as any).vendor ? `${(r as any).vendor}:${(r as any).product}` : (r as any).product] : []);
                return (
                  <Card
                    key={idx}
                    className="hover:border-primary/40 transition-colors cursor-pointer group"
                    onClick={() => setLiveDetailResult(r)}
                  >
                    <CardContent className="py-3 px-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0 flex-1 space-y-1.5">
                          {/* Title row */}
                          <div className="flex items-center gap-2 flex-wrap">
                            <Badge className="text-[9px] bg-blue-500/20 text-blue-400 border-blue-500/30">
                              {r.source}
                            </Badge>
                            <Badge className="text-[9px]" style={{ backgroundColor: `${sevColor}20`, color: sevColor, borderColor: `${sevColor}40` }}>
                              {r.severity}
                            </Badge>
                            {r.type && (
                              <Badge variant="outline" className="text-[9px]">
                                {r.type}
                              </Badge>
                            )}
                            <span className="text-sm font-medium truncate">{r.title}</span>
                          </div>

                          {/* Description */}
                          {r.description && (
                            <p className="text-xs text-muted-foreground line-clamp-2">
                              {r.description}
                            </p>
                          )}

                          {/* Key metadata row: Published / Threat Actor / CVE / Products */}
                          <div className="flex flex-wrap gap-x-4 gap-y-1.5 text-[10px]">
                            {published && (
                              <span className="flex items-center gap-1 text-muted-foreground">
                                <Calendar className="h-3 w-3" />
                                {new Date(published).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })}
                              </span>
                            )}
                            {threatActor && (
                              <span className="flex items-center gap-1 text-orange-400">
                                <User className="h-3 w-3" />
                                {threatActor}
                              </span>
                            )}
                            {cveId && (
                              <span className="flex items-center gap-1 text-red-400 font-mono">
                                <ShieldAlert className="h-3 w-3" />
                                {cveId}
                              </span>
                            )}
                            {products.length > 0 && (
                              <span className="flex items-center gap-1 text-muted-foreground">
                                <Package className="h-3 w-3" />
                                {products.slice(0, 3).join(", ")}{products.length > 3 ? ` +${products.length - 3}` : ""}
                              </span>
                            )}
                          </div>

                          {/* Tags / Ports / Vulns */}
                          {(((r as any).tags || []).length > 0 || ((r as any).ports || []).length > 0 || ((r as any).vulns || []).length > 0) && (
                            <div className="flex flex-wrap gap-1">
                              {((r as any).tags || []).slice(0, 6).map((t: string) => (
                                <Badge key={t} variant="secondary" className="text-[9px]">{t}</Badge>
                              ))}
                              {((r as any).ports || []).slice(0, 8).map((p: number) => (
                                <Badge key={p} variant="outline" className="text-[9px] font-mono">{p}</Badge>
                              ))}
                              {((r as any).vulns || []).slice(0, 4).map((v: string) => (
                                <Badge key={v} variant="destructive" className="text-[9px]">{v}</Badge>
                              ))}
                            </div>
                          )}

                          {/* Confidence bar at bottom */}
                          <div className="flex items-center gap-2 pt-1.5 border-t border-border/30">
                            <span className="text-[9px] text-muted-foreground w-16">Confidence</span>
                            <div className="flex-1 h-1.5 rounded-full bg-muted/40 overflow-hidden max-w-[150px]">
                              <div
                                className="h-full rounded-full transition-all"
                                style={{
                                  width: `${r.confidence}%`,
                                  backgroundColor: r.confidence >= 80 ? "#22c55e" : r.confidence >= 50 ? "#eab308" : "#6b7280",
                                }}
                              />
                            </div>
                            <span className="text-[9px] font-medium" style={{ color: r.confidence >= 80 ? "#22c55e" : r.confidence >= 50 ? "#eab308" : "#6b7280" }}>
                              {r.confidence}%
                            </span>
                          </div>
                        </div>

                        {/* Right side: risk score + click indicator */}
                        <div className="shrink-0 flex flex-col items-center gap-1">
                          {r.risk_score > 0 && (
                            <>
                              <div
                                className="w-11 h-11 rounded-full flex items-center justify-center text-xs font-bold border-2"
                                style={{ borderColor: sevColor, color: sevColor }}
                              >
                                {r.risk_score}
                              </div>
                              <span className="text-[9px] text-muted-foreground">risk</span>
                            </>
                          )}
                          <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-primary transition-colors mt-1" />
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          ) : liveResult.errors.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                <SearchIcon className="h-10 w-10 mx-auto mb-2 opacity-30" />
                <p className="text-sm">No live intelligence found for this query</p>
              </CardContent>
            </Card>
          ) : null}
        </div>
      )}

      {/* Live lookup loading state */}
      {liveLoading && (
        <Card>
          <CardContent className="py-10 flex flex-col items-center justify-center gap-3">
            <div className="relative">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <Wifi className="h-3.5 w-3.5 text-primary absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
            </div>
            <div className="text-center">
              <p className="text-sm font-medium">Searching the Internet…</p>
              <p className="text-xs text-muted-foreground mt-1">
                Querying NVD, VirusTotal, Shodan, AbuseIPDB, OTX, URLhaus…
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Empty state */}
      {!searchResult && !searchLoading && !liveResult && !liveLoading && (
        <Card>
          <CardContent className="py-16 text-center">
            <Target className="h-16 w-16 mx-auto mb-4 text-muted-foreground/20" />
            <p className="text-lg font-medium mb-2">Search Threat Intelligence</p>
            <p className="text-sm text-muted-foreground max-w-md mx-auto">
              Enter any indicator of compromise (IOC) &mdash; IP address, domain, URL, file hash,
              CVE ID, keyword &mdash; and the platform will auto-detect the type and search across
              all ingested intelligence with AI enrichment.
            </p>
            <div className="flex flex-wrap justify-center gap-2 mt-6">
              {[
                "CVE-2024-3094",
                "8.8.8.8",
                "evil.com",
                "ransomware",
                "d41d8cd98f00b204e9800998ecf8427e",
              ].map((example) => (
                <Badge
                  key={example}
                  variant="outline"
                  className="cursor-pointer hover:bg-accent transition-colors"
                  onClick={() => {
                    setQuery(example);
                    setDebouncedQuery(example);
                    doSearch(1, example);
                  }}
                >
                  {example}
                </Badge>
              ))}
            </div>
            {/* Quick feature highlights */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mt-8 max-w-2xl mx-auto text-left">
              <div className="p-3 rounded-lg bg-muted/30">
                <SearchIcon className="h-4 w-4 text-primary mb-1" />
                <p className="text-[11px] font-medium">Auto-Detect</p>
                <p className="text-[10px] text-muted-foreground">
                  CVE, IP, hash, domain auto-typed
                </p>
              </div>
              <div className="p-3 rounded-lg bg-muted/30">
                <Zap className="h-4 w-4 text-yellow-400 mb-1" />
                <p className="text-[11px] font-medium">VT + Shodan</p>
                <p className="text-[10px] text-muted-foreground">One-click enrichment panels</p>
              </div>
              <div className="p-3 rounded-lg bg-muted/30">
                <Filter className="h-4 w-4 text-purple-400 mb-1" />
                <p className="text-[11px] font-medium">Smart Filters</p>
                <p className="text-[10px] text-muted-foreground">Type, severity, feed pills</p>
              </div>
              <div className="p-3 rounded-lg bg-muted/30">
                <BarChart3 className="h-4 w-4 text-blue-400 mb-1" />
                <p className="text-[11px] font-medium">Analytics</p>
                <p className="text-[10px] text-muted-foreground">Distribution charts built-in</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Live Result Detail Slide-over */}
      {liveDetailResult && (
        <>
          <div
            className="fixed inset-0 bg-black/40 z-40"
            onClick={() => setLiveDetailResult(null)}
          />
          <div className="fixed inset-y-0 right-0 w-full max-w-lg bg-background border-l border-border shadow-2xl z-50 flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-border">
              <div className="flex items-center gap-2 min-w-0">
                <FileText className="h-4 w-4 text-primary shrink-0" />
                <div className="min-w-0">
                  <span className="text-sm font-semibold truncate block">{liveDetailResult.title}</span>
                  <span className="text-[10px] text-muted-foreground">
                    {liveDetailResult.source} &mdash; {liveDetailResult.type}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setLiveDetailResult(null)}
                className="p-1.5 rounded-lg hover:bg-muted/40 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {/* Severity + Risk Score header */}
              <div className="flex items-center gap-3">
                {(() => {
                  const sc = SEVERITY_COLORS[liveDetailResult.severity?.toLowerCase()] || SEVERITY_COLORS.unknown;
                  return (
                    <>
                      <div
                        className="w-14 h-14 rounded-full flex items-center justify-center text-lg font-bold border-2"
                        style={{ borderColor: sc, color: sc }}
                      >
                        {liveDetailResult.risk_score}
                      </div>
                      <div>
                        <Badge className="text-xs mb-0.5" style={{ backgroundColor: `${sc}20`, color: sc, borderColor: `${sc}40` }}>
                          {liveDetailResult.severity?.toUpperCase()}
                        </Badge>
                        <p className="text-[11px] text-muted-foreground">
                          Risk Score: {liveDetailResult.risk_score}/100
                        </p>
                      </div>
                    </>
                  );
                })()}
              </div>

              {/* Full Description */}
              <Card>
                <CardHeader className="pb-1 pt-3 px-4">
                  <CardTitle className="text-xs font-semibold">Description</CardTitle>
                </CardHeader>
                <CardContent className="px-4 pb-3">
                  <p className="text-xs text-muted-foreground leading-relaxed whitespace-pre-wrap">
                    {liveDetailResult.description || "No description available."}
                  </p>
                </CardContent>
              </Card>

              {/* Key Intelligence Fields */}
              <Card>
                <CardHeader className="pb-1 pt-3 px-4">
                  <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
                    <Database className="h-3.5 w-3.5 text-blue-400" />
                    Intelligence Details
                  </CardTitle>
                </CardHeader>
                <CardContent className="px-4 pb-3">
                  <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[11px]">
                    <DetailRow label="Source" value={liveDetailResult.source} />
                    <DetailRow label="Type" value={liveDetailResult.type} />
                    <DetailRow label="Severity" value={liveDetailResult.severity} />
                    <DetailRow label="Confidence" value={`${liveDetailResult.confidence}%`} />

                    {(liveDetailResult as any).cve_id && (
                      <DetailRow label="CVE ID" value={(liveDetailResult as any).cve_id} />
                    )}
                    {(liveDetailResult as any).cvss_score !== undefined && (liveDetailResult as any).cvss_score !== null && (
                      <DetailRow label="CVSS Score" value={`${(liveDetailResult as any).cvss_score} (${(liveDetailResult as any).cvss_severity || "N/A"})`} />
                    )}
                    {(liveDetailResult as any).exploitability_score !== undefined && (
                      <DetailRow label="Exploitability" value={String((liveDetailResult as any).exploitability_score)} />
                    )}
                    {(liveDetailResult as any).exploit_available && (
                      <DetailRow label="Exploit Available" value="Yes" />
                    )}

                    {/* Published date */}
                    {((liveDetailResult as any).published || (liveDetailResult as any).date_added || (liveDetailResult as any).created) && (
                      <DetailRow
                        label="Published"
                        value={new Date((liveDetailResult as any).published || (liveDetailResult as any).date_added || (liveDetailResult as any).created).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })}
                      />
                    )}
                    {(liveDetailResult as any).last_modified && (
                      <DetailRow
                        label="Last Modified"
                        value={new Date((liveDetailResult as any).last_modified).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })}
                      />
                    )}

                    {/* Threat Actor / Adversary */}
                    {((liveDetailResult as any).adversary || (liveDetailResult as any).threat_classification?.suggested_threat_label) && (
                      <DetailRow
                        label="Threat Actor"
                        value={(liveDetailResult as any).adversary || (liveDetailResult as any).threat_classification?.suggested_threat_label}
                      />
                    )}

                    {/* Products */}
                    {(liveDetailResult as any).vendor && (
                      <DetailRow label="Vendor" value={(liveDetailResult as any).vendor} />
                    )}
                    {(liveDetailResult as any).product && (
                      <DetailRow label="Product" value={(liveDetailResult as any).product} />
                    )}

                    {/* IP fields */}
                    {(liveDetailResult as any).abuse_score !== undefined && (
                      <DetailRow label="Abuse Score" value={`${(liveDetailResult as any).abuse_score}%`} />
                    )}
                    {(liveDetailResult as any).total_reports !== undefined && (
                      <DetailRow label="Total Reports" value={String((liveDetailResult as any).total_reports)} />
                    )}
                    {(liveDetailResult as any).isp && (
                      <DetailRow label="ISP" value={(liveDetailResult as any).isp} />
                    )}
                    {(liveDetailResult as any).country && (
                      <DetailRow label="Country" value={(liveDetailResult as any).country} />
                    )}
                    {(liveDetailResult as any).org && (
                      <DetailRow label="Organization" value={(liveDetailResult as any).org} />
                    )}
                    {(liveDetailResult as any).domain && (
                      <DetailRow label="Domain" value={(liveDetailResult as any).domain} />
                    )}
                    {(liveDetailResult as any).usage_type && (
                      <DetailRow label="Usage Type" value={(liveDetailResult as any).usage_type} />
                    )}

                    {/* VT fields */}
                    {(liveDetailResult as any).malicious !== undefined && (
                      <DetailRow label="Detection" value={`${(liveDetailResult as any).malicious}/${(liveDetailResult as any).total_engines || 0} engines`} />
                    )}
                    {(liveDetailResult as any).reputation !== undefined && (
                      <DetailRow label="Reputation" value={String((liveDetailResult as any).reputation)} />
                    )}

                    {/* Hash fields */}
                    {(liveDetailResult as any).file_name && (
                      <DetailRow label="File Name" value={(liveDetailResult as any).file_name} />
                    )}
                    {(liveDetailResult as any).file_type && (
                      <DetailRow label="File Type" value={(liveDetailResult as any).file_type} />
                    )}

                    {/* URLhaus */}
                    {(liveDetailResult as any).threat_type && (
                      <DetailRow label="Threat Type" value={(liveDetailResult as any).threat_type} />
                    )}
                    {(liveDetailResult as any).url_status && (
                      <DetailRow label="URL Status" value={(liveDetailResult as any).url_status} />
                    )}

                    {/* KEV */}
                    {(liveDetailResult as any).is_kev && (
                      <DetailRow label="Known Exploited" value="Yes — CISA KEV" />
                    )}
                    {(liveDetailResult as any).required_action && (
                      <DetailRow label="Required Action" value={(liveDetailResult as any).required_action} />
                    )}
                    {(liveDetailResult as any).due_date && (
                      <DetailRow label="Remediation Due" value={(liveDetailResult as any).due_date} />
                    )}
                    {(liveDetailResult as any).known_ransomware_use && (liveDetailResult as any).known_ransomware_use !== "Unknown" && (
                      <DetailRow label="Ransomware Use" value={(liveDetailResult as any).known_ransomware_use} />
                    )}

                    {/* Shodan */}
                    {(liveDetailResult as any).services_count > 0 && (
                      <DetailRow label="Services" value={String((liveDetailResult as any).services_count)} />
                    )}
                    {(liveDetailResult as any).city && (
                      <DetailRow label="City" value={(liveDetailResult as any).city} />
                    )}
                    {(liveDetailResult as any).os && (
                      <DetailRow label="OS" value={(liveDetailResult as any).os} />
                    )}

                    {/* OTX */}
                    {(liveDetailResult as any).ioc_count > 0 && (
                      <DetailRow label="IOC Count" value={String((liveDetailResult as any).ioc_count)} />
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Affected Products */}
              {((liveDetailResult as any).affected_products || []).length > 0 && (
                <Card>
                  <CardHeader className="pb-1 pt-3 px-4">
                    <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
                      <Package className="h-3.5 w-3.5 text-green-400" />
                      Affected Products
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="px-4 pb-3">
                    <div className="flex flex-wrap gap-1.5">
                      {((liveDetailResult as any).affected_products as string[]).map((p, i) => (
                        <Badge key={i} variant="outline" className="text-[10px] font-mono">
                          {p}
                        </Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Ports & Vulnerabilities */}
              {(((liveDetailResult as any).ports || []).length > 0 || ((liveDetailResult as any).vulns || []).length > 0) && (
                <Card>
                  <CardHeader className="pb-1 pt-3 px-4">
                    <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
                      <Server className="h-3.5 w-3.5 text-orange-400" />
                      Infrastructure
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="px-4 pb-3 space-y-3">
                    {((liveDetailResult as any).ports || []).length > 0 && (
                      <div>
                        <p className="text-[10px] font-medium text-muted-foreground mb-1">
                          Open Ports ({((liveDetailResult as any).ports as number[]).length})
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {((liveDetailResult as any).ports as number[]).map((p) => (
                            <Badge key={p} variant="outline" className="text-[9px] font-mono">{p}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {((liveDetailResult as any).vulns || []).length > 0 && (
                      <div>
                        <p className="text-[10px] font-medium text-red-400 mb-1">
                          Vulnerabilities ({((liveDetailResult as any).vulns as string[]).length})
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {((liveDetailResult as any).vulns as string[]).map((v) => (
                            <Badge key={v} variant="destructive" className="text-[9px]">{v}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {((liveDetailResult as any).hostnames || []).length > 0 && (
                      <div>
                        <p className="text-[10px] font-medium text-muted-foreground mb-1">Hostnames</p>
                        <div className="text-[11px] text-muted-foreground font-mono space-y-0.5">
                          {((liveDetailResult as any).hostnames as string[]).map((h) => (
                            <div key={h}>{h}</div>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Tags & Categories */}
              {(((liveDetailResult as any).tags || []).length > 0 || ((liveDetailResult as any).categories || []).length > 0) && (
                <Card>
                  <CardHeader className="pb-1 pt-3 px-4">
                    <CardTitle className="text-xs font-semibold">Tags &amp; Categories</CardTitle>
                  </CardHeader>
                  <CardContent className="px-4 pb-3">
                    <div className="flex flex-wrap gap-1.5">
                      {((liveDetailResult as any).tags || []).map((t: string) => (
                        <Badge key={t} variant="secondary" className="text-[9px]">{t}</Badge>
                      ))}
                      {(Array.isArray((liveDetailResult as any).categories)
                        ? (liveDetailResult as any).categories
                        : Object.values((liveDetailResult as any).categories || {})
                      ).map((c: string, i: number) => (
                        <Badge key={i} variant="outline" className="text-[9px]">{c}</Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* IOC Samples (OTX) */}
              {((liveDetailResult as any).iocs_sample || []).length > 0 && (
                <Card>
                  <CardHeader className="pb-1 pt-3 px-4">
                    <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
                      <Target className="h-3.5 w-3.5 text-red-400" />
                      IOC Samples
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="px-4 pb-3">
                    <div className="text-[11px] font-mono text-muted-foreground space-y-0.5">
                      {((liveDetailResult as any).iocs_sample as string[]).map((ioc, i) => (
                        <div key={i} className="truncate">{ioc}</div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Payloads (URLhaus) */}
              {((liveDetailResult as any).payloads || []).length > 0 && (
                <Card>
                  <CardHeader className="pb-1 pt-3 px-4">
                    <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
                      <AlertCircle className="h-3.5 w-3.5 text-red-400" />
                      Payloads
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="px-4 pb-3 space-y-2">
                    {((liveDetailResult as any).payloads as any[]).map((p, i) => (
                      <div key={i} className="text-[11px] p-2 rounded bg-muted/30 space-y-0.5">
                        {p.filename && <div><span className="text-muted-foreground">File:</span> <span className="font-mono">{p.filename}</span></div>}
                        {p.file_type && <div><span className="text-muted-foreground">Type:</span> {p.file_type}</div>}
                        {p.signature && <div><span className="text-muted-foreground">Signature:</span> <span className="text-red-400">{p.signature}</span></div>}
                        {p.virustotal_pct !== undefined && p.virustotal_pct !== null && <div><span className="text-muted-foreground">VT Detection:</span> {p.virustotal_pct}%</div>}
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}

              {/* References */}
              {((liveDetailResult as any).references || []).length > 0 && (
                <Card>
                  <CardHeader className="pb-1 pt-3 px-4">
                    <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
                      <ExternalLink className="h-3.5 w-3.5 text-blue-400" />
                      References
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="px-4 pb-3 space-y-1.5">
                    {((liveDetailResult as any).references as string[]).map((url, i) => (
                      <a
                        key={i}
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[11px] text-primary hover:underline flex items-center gap-1 truncate"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <ExternalLink className="h-3 w-3 shrink-0" />
                        {url.replace(/^https?:\/\//, "").slice(0, 80)}
                      </a>
                    ))}
                  </CardContent>
                </Card>
              )}

              {/* Single URL (web articles) */}
              {(liveDetailResult as any).url && !((liveDetailResult as any).references || []).length && (
                <Card>
                  <CardContent className="py-3 px-4">
                    <a
                      href={(liveDetailResult as any).url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-primary hover:underline flex items-center gap-1.5"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <ExternalLink className="h-3.5 w-3.5 shrink-0" />
                      Open source article
                    </a>
                  </CardContent>
                </Card>
              )}

              {/* Confidence bar */}
              <Card>
                <CardContent className="py-3 px-4">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[11px] font-medium">Confidence Level</span>
                    <span
                      className="text-[11px] font-bold"
                      style={{ color: liveDetailResult.confidence >= 80 ? "#22c55e" : liveDetailResult.confidence >= 50 ? "#eab308" : "#6b7280" }}
                    >
                      {liveDetailResult.confidence}%
                    </span>
                  </div>
                  <div className="h-2 rounded-full bg-muted/40 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${liveDetailResult.confidence}%`,
                        backgroundColor: liveDetailResult.confidence >= 80 ? "#22c55e" : liveDetailResult.confidence >= 50 ? "#eab308" : "#6b7280",
                      }}
                    />
                  </div>
                  <p className="text-[9px] text-muted-foreground mt-1">
                    {liveDetailResult.confidence >= 80
                      ? "High confidence — data from authoritative source"
                      : liveDetailResult.confidence >= 50
                        ? "Moderate confidence — cross-reference recommended"
                        : "Low confidence — unverified open source intelligence"}
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        </>
      )}

      {/* Enrichment Slide-over Panel with backdrop */}
      {enrichTarget && (
        <>
          <div
            className="fixed inset-0 bg-black/40 z-40"
            onClick={() => {
              setEnrichTarget(null);
              setEnrichData(null);
            }}
          />
          <div className="fixed inset-y-0 right-0 w-full max-w-md bg-background border-l border-border shadow-2xl z-50 flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-border">
              <div className="flex items-center gap-2 min-w-0">
                <Zap className="h-4 w-4 text-yellow-400 shrink-0" />
                <div className="min-w-0">
                  <span className="text-sm font-semibold truncate block">
                    {enrichTarget.source_ref || enrichTarget.title}
                  </span>
                  <span className="text-[10px] text-muted-foreground">
                    {enrichTarget.asset_type} &mdash; {enrichTarget.source_name}
                  </span>
                </div>
              </div>
              <button
                onClick={() => {
                  setEnrichTarget(null);
                  setEnrichData(null);
                }}
                className="p-1.5 rounded-lg hover:bg-muted/40 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {enrichLoading && (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="h-6 w-6 animate-spin text-primary" />
                  <span className="ml-2 text-sm text-muted-foreground">
                    Querying VT &amp; Shodan...
                  </span>
                </div>
              )}

              {enrichData && !enrichLoading && (
                <>
                  {enrichData.errors.length > 0 && (
                    <div className="space-y-1">
                      {enrichData.errors.map((e, i) => (
                        <div
                          key={i}
                          className="text-xs text-yellow-400 bg-yellow-400/10 rounded px-2 py-1"
                        >
                          {e}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* VirusTotal */}
                  <Card>
                    <CardHeader className="pb-1 pt-3 px-4">
                      <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
                        <ShieldAlert className="h-3.5 w-3.5 text-blue-400" />
                        VirusTotal
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="px-4 pb-3">
                      {enrichData.virustotal ? (
                        <VTResultCard data={enrichData.virustotal as Record<string, any>} />
                      ) : (
                        <p className="text-xs text-muted-foreground">
                          No VirusTotal data available
                        </p>
                      )}
                    </CardContent>
                  </Card>

                  {/* Shodan */}
                  {(enrichTarget.asset_type === "ip" ||
                    enrichTarget.asset_type === "domain") && (
                    <Card>
                      <CardHeader className="pb-1 pt-3 px-4">
                        <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
                          <Server className="h-3.5 w-3.5 text-orange-400" />
                          Shodan
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="px-4 pb-3">
                        {enrichData.shodan && (enrichData.shodan as any).found ? (
                          <ShodanResultCard data={enrichData.shodan as Record<string, any>} />
                        ) : (
                          <p className="text-xs text-muted-foreground">
                            No Shodan data available
                          </p>
                        )}
                      </CardContent>
                    </Card>
                  )}

                  {/* Intel Summary */}
                  <Card>
                    <CardHeader className="pb-1 pt-3 px-4">
                      <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
                        <Eye className="h-3.5 w-3.5 text-purple-400" />
                        Intel Summary
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="px-4 pb-3 space-y-2">
                      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[11px]">
                        <DetailRow label="Risk Score" value={`${enrichTarget.risk_score}/100`} />
                        <DetailRow label="Severity" value={enrichTarget.severity} />
                        <DetailRow label="Confidence" value={`${enrichTarget.confidence}%`} />
                        <DetailRow label="Feed" value={enrichTarget.feed_type} />
                        {enrichTarget.is_kev && (
                          <DetailRow label="KEV" value="Yes \u2014 Actively Exploited" />
                        )}
                      </div>
                      {enrichTarget.cve_ids.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {enrichTarget.cve_ids.map((c) => (
                            <Badge key={c} variant="destructive" className="text-[9px]">
                              {c}
                            </Badge>
                          ))}
                        </div>
                      )}
                      {enrichTarget.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {enrichTarget.tags.map((t) => (
                            <Badge key={t} variant="secondary" className="text-[9px]">
                              {t}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/* ── Enrichment Sub-components ─────────────────────────── */

function VTResultCard({ data }: { data: Record<string, any> }) {
  if (data.found === false) {
    return (
      <p className="text-xs text-muted-foreground">
        {data.message || "Not found in VirusTotal"}
      </p>
    );
  }

  const malicious = data.malicious || 0;
  const total = data.total_engines || 0;
  const pct = total ? Math.round((malicious / total) * 100) : 0;
  const barColor = malicious > 5 ? "#ef4444" : malicious > 0 ? "#f97316" : "#22c55e";

  return (
    <div className="space-y-3">
      {/* Detection bar */}
      <div>
        <div className="flex justify-between text-[10px] font-medium mb-1">
          <span>Detection</span>
          <span style={{ color: barColor }}>
            {malicious}/{total} engines ({pct}%)
          </span>
        </div>
        <div className="h-2 rounded-full bg-muted/40 overflow-hidden">
          <div
            className="h-full rounded-full transition-all"
            style={{ width: `${pct}%`, backgroundColor: barColor }}
          />
        </div>
      </div>

      {/* Key details */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[11px]">
        {data.reputation !== undefined && (
          <DetailRow label="Reputation" value={String(data.reputation)} />
        )}
        {data.country && <DetailRow label="Country" value={data.country} />}
        {data.as_owner && <DetailRow label="AS Owner" value={data.as_owner} />}
        {data.asn && <DetailRow label="ASN" value={String(data.asn)} />}
        {data.network && <DetailRow label="Network" value={data.network} />}
        {data.registrar && <DetailRow label="Registrar" value={data.registrar} />}
        {data.name && <DetailRow label="File Name" value={data.name} />}
        {data.type_description && <DetailRow label="File Type" value={data.type_description} />}
        {data.size && (
          <DetailRow label="Size" value={`${(data.size / 1024).toFixed(1)} KB`} />
        )}
        {data.suspicious > 0 && (
          <DetailRow label="Suspicious" value={String(data.suspicious)} />
        )}
        {data.harmless > 0 && <DetailRow label="Harmless" value={String(data.harmless)} />}
      </div>

      {/* Tags */}
      {data.tags && data.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {data.tags.slice(0, 10).map((t: string) => (
            <Badge key={t} variant="secondary" className="text-[9px]">
              {t}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}

function ShodanResultCard({ data }: { data: Record<string, any> }) {
  return (
    <div className="space-y-3">
      {/* Ports */}
      {data.ports && data.ports.length > 0 && (
        <div>
          <p className="text-[10px] font-medium text-muted-foreground mb-1">
            Open Ports ({data.ports.length})
          </p>
          <div className="flex flex-wrap gap-1">
            {data.ports.slice(0, 20).map((p: number) => (
              <Badge key={p} variant="outline" className="text-[9px] font-mono">
                {p}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {/* Vulns */}
      {data.vulns && data.vulns.length > 0 && (
        <div>
          <p className="text-[10px] font-medium text-red-400 mb-1">
            Vulnerabilities ({data.vulns.length})
          </p>
          <div className="flex flex-wrap gap-1">
            {data.vulns.slice(0, 15).map((v: string) => (
              <Badge key={v} variant="destructive" className="text-[9px]">
                {v}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {/* Details */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[11px]">
        {data.org && <DetailRow label="Organization" value={data.org} />}
        {data.isp && <DetailRow label="ISP" value={data.isp} />}
        {data.country_name && <DetailRow label="Country" value={data.country_name} />}
        {data.city && <DetailRow label="City" value={data.city} />}
        {data.os && <DetailRow label="OS" value={data.os} />}
        {data.services_count > 0 && (
          <DetailRow label="Services" value={String(data.services_count)} />
        )}
      </div>

      {/* Hostnames */}
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

      {/* CPEs / Tags */}
      {data.tags && data.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {data.tags.map((t: string) => (
            <Badge key={t} variant="secondary" className="text-[9px]">
              {t}
            </Badge>
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
      <span className="font-medium truncate" title={value}>
        {value}
      </span>
    </>
  );
}
