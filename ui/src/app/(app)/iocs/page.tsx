"use client";

import React, { useEffect, useCallback, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { Pagination } from "@/components/Pagination";
import { DonutChart, HorizontalBarChart } from "@/components/charts";
import {
  Database, Search, Filter, Copy, ExternalLink, Check, AlertTriangle,
  ChevronUp, ChevronDown, ArrowUpDown, Shield, Eye, Globe,
  X, Loader2, Zap, Server, ShieldAlert, ShieldCheck, Info,
} from "lucide-react";
import {
  getIOCs, getIOCStats, enrichIOC,
  type IOCItem, type IOCListResponse, type IOCStatsResponse, type IOCEnrichmentResult,
} from "@/lib/api";

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

function riskLabel(score: number) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

export default function IOCDatabasePage() {
  const [data, setData] = useState<IOCListResponse | null>(null);
  const [stats, setStats] = useState<IOCStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState("last_seen");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [enrichTarget, setEnrichTarget] = useState<IOCItem | null>(null);
  const [enrichData, setEnrichData] = useState<IOCEnrichmentResult | null>(null);
  const [enrichLoading, setEnrichLoading] = useState(false);
  const pageSize = 50;

  // Debounced search
  const [debouncedSearch, setDebouncedSearch] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 400);
    return () => clearTimeout(t);
  }, [search]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, unknown> = {
        page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_dir: sortDir,
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
  }, [page, pageSize, sortBy, sortDir, debouncedSearch, typeFilter, stats]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Reset page when filters change
  useEffect(() => {
    setPage(1);
  }, [debouncedSearch, typeFilter]);

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
    } catch (err) {
      setEnrichData({ virustotal: null, shodan: null, errors: ["Failed to enrich IOC"] });
    } finally {
      setEnrichLoading(false);
    }
  };

  const SortIcon = ({ col }: { col: string }) => {
    if (sortBy !== col) return <ArrowUpDown className="h-3 w-3 ml-1 text-muted-foreground/40" />;
    return sortDir === "asc"
      ? <ChevronUp className="h-3 w-3 ml-1 text-primary" />
      : <ChevronDown className="h-3 w-3 ml-1 text-primary" />;
  };

  // Build type distribution for donut
  const typeDistribution = (stats?.type_distribution || []).map((t) => ({
    name: t.name.charAt(0).toUpperCase() + t.name.slice(1).replace(/_/g, " "),
    value: t.count,
    color: IOC_TYPE_COLORS[t.name] || IOC_TYPE_COLORS.other,
  }));

  const types = (stats?.type_distribution || []).map((t) => t.name);

  if (loading && !data) return <Loading text="Loading IOC database..." />;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
          <Database className="h-5 w-5 text-primary" />
          IOC Database
        </h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Browse and search all ingested indicators of compromise
        </p>
      </div>

      {/* Stats cards */}
      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <Card>
            <CardContent className="p-3 flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Database className="h-4 w-4 text-blue-400" />
              </div>
              <div>
                <p className="text-lg font-bold">{stats.total_iocs.toLocaleString()}</p>
                <p className="text-[10px] text-muted-foreground">Total IOCs</p>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-3 flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/10">
                <AlertTriangle className="h-4 w-4 text-red-400" />
              </div>
              <div>
                <p className="text-lg font-bold">{(stats.risk_distribution.critical || 0).toLocaleString()}</p>
                <p className="text-[10px] text-muted-foreground">Critical Risk</p>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-3 flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Eye className="h-4 w-4 text-purple-400" />
              </div>
              <div>
                <p className="text-lg font-bold">{types.length}</p>
                <p className="text-[10px] text-muted-foreground">IOC Types</p>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-3 flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <Globe className="h-4 w-4 text-green-400" />
              </div>
              <div>
                <p className="text-lg font-bold">{stats.unique_sources}</p>
                <p className="text-[10px] text-muted-foreground">Sources</p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Top row: search + type pills + donut */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-3">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search IOCs by value (IP, domain, URL, hash)..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full h-10 pl-10 pr-4 rounded-lg bg-muted/40 border border-border/50 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>

          {/* Type filter pills */}
          <div className="flex flex-wrap gap-1.5">
            <button
              onClick={() => setTypeFilter(null)}
              className={`px-3 py-1 rounded-full text-xs transition-colors ${
                !typeFilter
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
              }`}
            >
              All
            </button>
            {types.map((t) => (
              <button
                key={t}
                onClick={() => setTypeFilter(t === typeFilter ? null : t)}
                className={`px-3 py-1 rounded-full text-xs transition-colors ${
                  typeFilter === t
                    ? "bg-primary text-primary-foreground"
                    : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
                }`}
              >
                {t.charAt(0).toUpperCase() + t.slice(1).replace(/_/g, " ")}
              </button>
            ))}
          </div>

          {/* Stats row */}
          <div className="flex gap-4">
            <div className="text-xs text-muted-foreground">
              Showing <span className="font-semibold text-foreground">{data?.items.length ?? 0}</span> of{" "}
              <span className="font-semibold text-foreground">{data?.total ?? 0}</span> IOCs
              {typeFilter && (
                <span className="ml-1">
                  (type: <span className="font-semibold text-foreground">{typeFilter}</span>)
                </span>
              )}
            </div>
          </div>
        </div>

        <Card>
          <CardHeader className="pb-1 pt-3 px-4">
            <CardTitle className="text-xs font-semibold">Type Distribution</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3">
            <DonutChart
              data={typeDistribution}
              centerValue={stats?.total_iocs ?? 0}
              centerLabel="IOCs"
              height={160}
              innerRadius={40}
              outerRadius={60}
            />
          </CardContent>
        </Card>
      </div>

      {/* Source distribution bar chart */}
      {stats && stats.source_distribution.length > 0 && (
        <Card>
          <CardHeader className="pb-1 pt-3 px-4">
            <CardTitle className="text-xs font-semibold">IOCs by Source</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3">
            <HorizontalBarChart
              data={stats.source_distribution.map((s) => ({
                name: s.name,
                value: s.count,
                color: "#3b82f6",
              }))}
              height={Math.max(120, stats.source_distribution.length * 32)}
            />
          </CardContent>
        </Card>
      )}

      {/* IOC Table */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border/40">
                  <th className="text-left py-2.5 px-4 text-muted-foreground font-medium">IOC Value</th>
                  <th
                    className="text-left py-2.5 px-4 text-muted-foreground font-medium cursor-pointer select-none"
                    onClick={() => handleSort("ioc_type")}
                  >
                    <span className="flex items-center">Type<SortIcon col="ioc_type" /></span>
                  </th>
                  <th
                    className="text-left py-2.5 px-4 text-muted-foreground font-medium cursor-pointer select-none"
                    onClick={() => handleSort("risk_score")}
                  >
                    <span className="flex items-center">Risk<SortIcon col="risk_score" /></span>
                  </th>
                  <th
                    className="text-left py-2.5 px-4 text-muted-foreground font-medium cursor-pointer select-none"
                    onClick={() => handleSort("sighting_count")}
                  >
                    <span className="flex items-center">Sightings<SortIcon col="sighting_count" /></span>
                  </th>
                  <th className="text-left py-2.5 px-4 text-muted-foreground font-medium">Sources</th>
                  <th
                    className="text-left py-2.5 px-4 text-muted-foreground font-medium cursor-pointer select-none"
                    onClick={() => handleSort("first_seen")}
                  >
                    <span className="flex items-center">First Seen<SortIcon col="first_seen" /></span>
                  </th>
                  <th
                    className="text-left py-2.5 px-4 text-muted-foreground font-medium cursor-pointer select-none"
                    onClick={() => handleSort("last_seen")}
                  >
                    <span className="flex items-center">Last Seen<SortIcon col="last_seen" /></span>
                  </th>
                  <th className="py-2.5 px-4"></th>
                </tr>
              </thead>
              <tbody>
                {data?.items.map((ioc, idx) => {
                  const rl = riskLabel(ioc.risk_score);
                  const rCol = RISK_COLORS[rl];
                  return (
                    <tr
                      key={ioc.id}
                      className="border-b border-border/20 hover:bg-muted/20 transition-colors"
                    >
                      <td className="py-2 px-4 font-mono max-w-[300px] truncate" title={ioc.value}>
                        {ioc.value}
                      </td>
                      <td className="py-2 px-4">
                        <Badge
                          variant="secondary"
                          className="text-[10px]"
                          style={{
                            background: (IOC_TYPE_COLORS[ioc.ioc_type] || IOC_TYPE_COLORS.other) + "20",
                            color: IOC_TYPE_COLORS[ioc.ioc_type] || IOC_TYPE_COLORS.other,
                          }}
                        >
                          {ioc.ioc_type}
                        </Badge>
                      </td>
                      <td className="py-2 px-4">
                        <div className="flex items-center gap-1.5">
                          <span className="font-semibold" style={{ color: rCol }}>
                            {ioc.risk_score}
                          </span>
                          <Badge
                            variant="outline"
                            className="text-[10px]"
                            style={{ borderColor: rCol, color: rCol }}
                          >
                            {rl}
                          </Badge>
                        </div>
                      </td>
                      <td className="py-2 px-4 text-center">
                        <span className="font-medium">{ioc.sighting_count}</span>
                      </td>
                      <td className="py-2 px-4 text-muted-foreground">
                        {ioc.source_names?.join(", ") || "—"}
                      </td>
                      <td className="py-2 px-4 text-muted-foreground">
                        {ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : "—"}
                      </td>
                      <td className="py-2 px-4 text-muted-foreground">
                        {ioc.last_seen ? new Date(ioc.last_seen).toLocaleDateString() : "—"}
                      </td>
                      <td className="py-2 px-4">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => handleEnrich(ioc)}
                            className="p-1 rounded hover:bg-primary/10 transition-colors"
                            title="Enrich with VT/Shodan"
                          >
                            <Zap className={`h-3.5 w-3.5 ${enrichTarget?.id === ioc.id && enrichLoading ? "text-yellow-400 animate-pulse" : "text-yellow-500/60 hover:text-yellow-400"}`} />
                          </button>
                          <button
                            onClick={() => handleCopy(ioc.value, idx)}
                            className="p-1 rounded hover:bg-muted/40 transition-colors"
                            title="Copy IOC"
                          >
                            {copiedIdx === idx ? (
                              <Check className="h-3.5 w-3.5 text-green-400" />
                            ) : (
                              <Copy className="h-3.5 w-3.5 text-muted-foreground" />
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
              <div className="py-12 text-center text-xs text-muted-foreground/60">
                No IOCs match your search
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Pagination */}
      {data && data.pages > 1 && (
        <Pagination page={data.page} pages={data.pages} onPageChange={setPage} />
      )}

      {/* Enrichment Panel */}
      {enrichTarget && (
        <div className="fixed inset-y-0 right-0 w-full max-w-md bg-background border-l border-border shadow-2xl z-50 flex flex-col">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-border">
            <div className="flex items-center gap-2 min-w-0">
              <Zap className="h-4 w-4 text-yellow-400 shrink-0" />
              <span className="text-sm font-semibold truncate">Enrich: {enrichTarget.value}</span>
            </div>
            <button
              onClick={() => { setEnrichTarget(null); setEnrichData(null); }}
              className="p-1 rounded hover:bg-muted/40"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {enrichLoading && (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="h-6 w-6 animate-spin text-primary" />
                <span className="ml-2 text-sm text-muted-foreground">Querying VT & Shodan...</span>
              </div>
            )}

            {enrichData && !enrichLoading && (
              <>
                {/* Errors */}
                {enrichData.errors.length > 0 && (
                  <div className="space-y-1">
                    {enrichData.errors.map((e, i) => (
                      <div key={i} className="text-xs text-yellow-400 bg-yellow-400/10 rounded px-2 py-1">
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
                      <VTResultCard data={enrichData.virustotal as Record<string, any>} iocType={enrichTarget.ioc_type} />
                    ) : (
                      <p className="text-xs text-muted-foreground">No VirusTotal data available</p>
                    )}
                  </CardContent>
                </Card>

                {/* Shodan */}
                {(enrichTarget.ioc_type === "ip" || enrichTarget.ioc_type === "domain") && (
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
                        <p className="text-xs text-muted-foreground">No Shodan data available</p>
                      )}
                    </CardContent>
                  </Card>
                )}
              </>
            )}
          </div>
        </div>
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
    <div className="space-y-3">
      {/* Detection bar */}
      <div>
        <div className="flex justify-between text-[10px] font-medium mb-1">
          <span>Detection</span>
          <span style={{ color: barColor }}>{malicious}/{total} engines ({pct}%)</span>
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
        {data.size && <DetailRow label="Size" value={`${(data.size / 1024).toFixed(1)} KB`} />}
        {data.suspicious > 0 && <DetailRow label="Suspicious" value={String(data.suspicious)} />}
        {data.harmless > 0 && <DetailRow label="Harmless" value={String(data.harmless)} />}
      </div>

      {/* Tags */}
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
    <div className="space-y-3">
      {/* Ports */}
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

      {/* Vulnerabilities */}
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

      {/* Key details */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[11px]">
        {data.org && <DetailRow label="Organization" value={data.org} />}
        {data.isp && <DetailRow label="ISP" value={data.isp} />}
        {data.country_name && <DetailRow label="Country" value={data.country_name} />}
        {data.city && <DetailRow label="City" value={data.city} />}
        {data.os && <DetailRow label="OS" value={data.os} />}
        {data.services_count > 0 && <DetailRow label="Services" value={String(data.services_count)} />}
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

      {/* Tags / CPEs */}
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
