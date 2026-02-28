"use client";

import React, { useEffect, useMemo, useState, useCallback } from "react";
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
} from "lucide-react";
import { formatDate, severityBorder, riskColor, riskBg } from "@/lib/utils";
import { cn } from "@/lib/utils";
import Link from "next/link";
import * as api from "@/lib/api";
import type { IntelListResponse, IntelItem } from "@/types";

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

export default function ThreatsPage() {
  const searchParams = useSearchParams();
  const [data, setData] = useState<IntelListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [selectedSev, setSelectedSev] = useState<string | null>(searchParams.get("severity") || null);
  const [selectedFeedType, setSelectedFeedType] = useState<string | null>(searchParams.get("feed_type") || null);
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState("ingested_at:desc");

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [sortBy, sortOrder] = sortKey.split(":");
      const params: Record<string, string | number> = {
        page,
        page_size: 20,
        sort_by: sortBy,
        sort_order: sortOrder,
      };
      if (selectedSev) params.severity = selectedSev;
      if (selectedFeedType) params.feed_type = selectedFeedType;
      if (selectedAsset) params.asset_type = selectedAsset;
      const result = await api.getIntelItems(params);
      setData(result);
    } catch {
      /* silent */
    }
    setLoading(false);
  }, [page, selectedSev, selectedFeedType, selectedAsset, sortKey]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Asset type distribution from current page items
  const assetDonut = useMemo(() => {
    if (!data?.items) return [];
    const grouped: Record<string, number> = {};
    data.items.forEach((item) => {
      const key = item.asset_type || "other";
      grouped[key] = (grouped[key] || 0) + 1;
    });
    const colors = ["#3b82f6", "#ef4444", "#f97316", "#22c55e", "#a855f7", "#ec4899", "#14b8a6", "#6b7280"];
    return Object.entries(grouped).map(([key, count], i) => ({
      name: key.toUpperCase().replace(/_/g, " "),
      value: count,
      color: colors[i % colors.length],
      rawKey: key,
    }));
  }, [data]);

  const handleSevFilter = (sev: string | null) => {
    setSelectedSev(sev);
    setPage(1);
  };

  const handleFeedTypeFilter = (ft: string | null) => {
    setSelectedFeedType(ft);
    setPage(1);
  };

  const handleAssetClick = (name: string) => {
    // Map display name back to raw key
    const match = assetDonut.find((d) => d.name === name);
    const rawKey = (match as any)?.rawKey || name.toLowerCase().replace(/ /g, "_");
    if (selectedAsset === rawKey) {
      setSelectedAsset(null);
    } else {
      setSelectedAsset(rawKey);
    }
    setPage(1);
  };

  if (loading && !data) return <Loading text="Loading threat feed..." />;

  const items = data?.items || [];

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
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
              </span>
            )}
          </p>
        </div>
        {/* Sort dropdown */}
        <div className="flex items-center gap-2">
          <ArrowUpDown className="h-3.5 w-3.5 text-muted-foreground" />
          <select
            value={sortKey}
            onChange={(e) => { setSortKey(e.target.value); setPage(1); }}
            className="text-xs bg-background border rounded-md px-2 py-1.5 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {SORT_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Severity Filter Pills */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] text-muted-foreground uppercase font-semibold tracking-wider mr-1">Severity</span>
        <Badge
          variant={selectedSev === null ? "default" : "outline"}
          className="cursor-pointer"
          onClick={() => handleSevFilter(null)}
        >
          All
        </Badge>
        {["critical", "high", "medium", "low", "info"].map((s) => (
          <Badge
            key={s}
            variant={selectedSev === s ? (s as any) : "outline"}
            className="cursor-pointer"
            onClick={() => handleSevFilter(selectedSev === s ? null : s)}
          >
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </Badge>
        ))}
      </div>

      {/* Feed Type Filter Pills */}
      <div className="flex items-center gap-2 flex-wrap -mt-2">
        <span className="text-[10px] text-muted-foreground uppercase font-semibold tracking-wider mr-1">Type</span>
        <Badge
          variant={selectedFeedType === null ? "default" : "outline"}
          className="cursor-pointer"
          onClick={() => handleFeedTypeFilter(null)}
        >
          All
        </Badge>
        {FEED_TYPES.map((ft) => (
          <Badge
            key={ft}
            variant={selectedFeedType === ft ? "default" : "outline"}
            className="cursor-pointer"
            onClick={() => handleFeedTypeFilter(selectedFeedType === ft ? null : ft)}
          >
            {ft.charAt(0).toUpperCase() + ft.slice(1).replace(/_/g, " ")}
          </Badge>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Main threat list */}
        <div className="lg:col-span-3 space-y-2">
          {loading && data ? (
            <div className="space-y-2">
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="h-20 rounded-lg bg-muted/20 animate-pulse" />
              ))}
            </div>
          ) : (
            <>
              {items.map((item) => (
                <Link
                  key={item.id}
                  href={`/intel/${item.id}`}
                  className={cn(
                    "block border-l-4 rounded-lg border bg-card p-3 hover:shadow-md transition-all group",
                    severityBorder(item.severity)
                  )}
                >
                  <div className="flex items-start gap-3">
                    <div
                      className={cn(
                        "flex items-center justify-center h-10 w-12 rounded-md text-sm font-bold shrink-0",
                        riskBg(item.risk_score),
                        riskColor(item.risk_score)
                      )}
                    >
                      {item.risk_score}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                        <Badge variant={item.severity as any} className="text-[10px] h-5">
                          {item.severity.toUpperCase()}
                        </Badge>
                        {item.is_kev && (
                          <Badge variant="destructive" className="text-[10px] h-5 gap-0.5">
                            <Zap className="h-2.5 w-2.5" /> KEV
                          </Badge>
                        )}
                        <span className="text-[10px] text-muted-foreground capitalize">
                          {item.feed_type.replace(/_/g, " ")}
                        </span>
                      </div>
                      <h3 className="text-sm font-medium leading-tight group-hover:text-primary transition-colors line-clamp-1">
                        {item.title}
                      </h3>
                      <div className="flex items-center gap-3 mt-1 text-[11px] text-muted-foreground flex-wrap">
                        <span className="flex items-center gap-1">
                          <Shield className="h-3 w-3" /> {item.source_name}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" /> {formatDate(item.published_at || item.ingested_at, { relative: true })}
                        </span>
                        {item.cve_ids?.length > 0 && (
                          <span
                            className="font-mono text-primary hover:underline"
                            onClick={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              window.location.href = `/search?q=${item.cve_ids[0]}`;
                            }}
                          >
                            {item.cve_ids[0]}
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
                      </div>
                      {/* Affected products & exploitability row */}
                      {(item.affected_products?.length > 0 || item.exploit_available || item.exploitability_score || item.tags?.length > 0) && (
                        <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                          {item.affected_products?.length > 0 && (
                            <span className="inline-flex items-center gap-1 text-[10px] bg-blue-500/10 text-blue-400 px-1.5 py-0.5 rounded">
                              <Package className="h-2.5 w-2.5" />
                              {item.affected_products.slice(0, 2).join(", ")}
                              {item.affected_products.length > 2 && ` +${item.affected_products.length - 2}`}
                            </span>
                          )}
                          {item.exploit_available && (
                            <span className="inline-flex items-center gap-1 text-[10px] bg-red-500/15 text-red-400 px-1.5 py-0.5 rounded font-medium">
                              <Bug className="h-2.5 w-2.5" /> Exploit Available
                            </span>
                          )}
                          {item.exploitability_score != null && item.exploitability_score > 0 && (
                            <span className={cn(
                              "inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded font-mono",
                              item.exploitability_score >= 7 ? "bg-red-500/15 text-red-400" :
                              item.exploitability_score >= 4 ? "bg-yellow-500/15 text-yellow-400" :
                              "bg-green-500/15 text-green-400"
                            )}>
                              Exploit: {item.exploitability_score.toFixed(1)}
                            </span>
                          )}
                          {item.tags?.length > 0 && item.tags.slice(0, 3).map((tag) => (
                            <span key={tag} className="inline-flex items-center gap-0.5 text-[10px] bg-muted text-muted-foreground px-1.5 py-0.5 rounded">
                              <Tag className="h-2 w-2" /> {tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-primary transition-colors shrink-0 mt-3" />
                  </div>
                </Link>
              ))}

              {items.length === 0 && (
                <div className="text-center py-16 text-muted-foreground text-sm">
                  No threats matching this filter
                </div>
              )}

              {/* Pagination */}
              {data && data.pages > 1 && (
                <Pagination page={page} pages={data.pages} onPageChange={setPage} />
              )}
            </>
          )}
        </div>

        {/* Right sidebar */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-1 pt-4 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-semibold">Asset Types</CardTitle>
                {selectedAsset && (
                  <button
                    onClick={() => { setSelectedAsset(null); setPage(1); }}
                    className="text-[9px] text-primary hover:underline"
                  >
                    Clear
                  </button>
                )}
              </div>
              {selectedAsset && (
                <p className="text-[10px] text-primary/70 mt-0.5">
                  Filtering: {selectedAsset.toUpperCase().replace(/_/g, " ")}
                </p>
              )}
            </CardHeader>
            <CardContent className="px-4 pb-4">
              <DonutChart
                data={assetDonut}
                centerValue={data?.total || 0}
                centerLabel="Items"
                height={160}
                innerRadius={40}
                outerRadius={60}
                onSegmentClick={handleAssetClick}
                activeSegment={selectedAsset ? selectedAsset.toUpperCase().replace(/_/g, " ") : null}
              />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
