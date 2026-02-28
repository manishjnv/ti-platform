"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useAppStore } from "@/store";
import { IntelCard } from "@/components/IntelCard";
import { Pagination } from "@/components/Pagination";
import { Loading, IntelCardSkeleton } from "@/components/Loading";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { getExportUrl } from "@/lib/api";
import {
  List,
  Download,
  Filter,
  RefreshCw,
  SlidersHorizontal,
  Search,
  AlertTriangle,
  Zap,
  X,
} from "lucide-react";

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];
const FEED_TYPE_OPTIONS = [
  "vulnerability",
  "ioc",
  "malware",
  "exploit",
  "advisory",
  "threat_actor",
  "campaign",
];
const ASSET_TYPE_OPTIONS = [
  "cve",
  "ip",
  "url",
  "domain",
  "hash_sha256",
  "hash_md5",
  "email",
  "file",
  "other",
];
const SORT_OPTIONS = [
  { value: "ingested_at:desc", label: "Newest First" },
  { value: "ingested_at:asc", label: "Oldest First" },
  { value: "risk_score:desc", label: "Highest Risk" },
  { value: "risk_score:asc", label: "Lowest Risk" },
  { value: "published_at:desc", label: "Recently Published" },
];

export default function IntelFeedPage() {
  const { intelData, intelLoading, intelPage, intelFilters, fetchIntel, setIntelPage, setIntelFilters } = useAppStore();
  const [showFilters, setShowFilters] = useState(false);
  const [localFilters, setLocalFilters] = useState<Record<string, string>>(intelFilters);
  const [searchInput, setSearchInput] = useState(intelFilters.query || "");

  useEffect(() => {
    fetchIntel(1);
    // Auto-refresh every 30 seconds
    const interval = setInterval(() => fetchIntel(), 30000);
    return () => clearInterval(interval);
  }, [fetchIntel]);

  const handlePageChange = useCallback(
    (page: number) => {
      setIntelPage(page);
      fetchIntel(page);
      window.scrollTo({ top: 0, behavior: "smooth" });
    },
    [fetchIntel, setIntelPage]
  );

  const applyFilters = () => {
    const cleaned: Record<string, string> = {};
    // Split combined sort value into sort_by + sort_order
    Object.entries(localFilters).forEach(([k, v]) => {
      if (v !== "") cleaned[k] = v;
    });
    if (searchInput.trim()) cleaned.query = searchInput.trim();
    else delete cleaned.query;
    setIntelFilters(cleaned);
    fetchIntel(1, cleaned);
  };

  const clearFilters = () => {
    setLocalFilters({});
    setSearchInput("");
    setIntelFilters({});
    fetchIntel(1, {});
  };

  const handleSearchKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") applyFilters();
  };

  const currentSort = `${localFilters.sort_by || "ingested_at"}:${localFilters.sort_order || "desc"}`;
  const activeFilterCount = Object.entries(intelFilters).filter(
    ([k, v]) => v && !["sort_by", "sort_order"].includes(k)
  ).length;

  const exportUrl = getExportUrl(intelFilters);

  return (
    <div className="p-6 space-y-4 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <List className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Intel Feed</h1>
            <p className="text-sm text-muted-foreground">
              {intelData
                ? `${intelData.total.toLocaleString()} items`
                : "Loading..."}
              {activeFilterCount > 0 && (
                <span className="ml-1 text-primary">
                  · {activeFilterCount} filter{activeFilterCount > 1 ? "s" : ""} active
                </span>
              )}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchIntel()}
            disabled={intelLoading}
          >
            <RefreshCw className={`h-4 w-4 mr-1 ${intelLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button variant="outline" size="sm" asChild>
            <a href={exportUrl} download>
              <Download className="h-4 w-4 mr-1" />
              Export
            </a>
          </Button>
          <Button
            variant={showFilters ? "default" : "outline"}
            size="sm"
            onClick={() => setShowFilters(!showFilters)}
          >
            <SlidersHorizontal className="h-4 w-4 mr-1" />
            Filters
            {activeFilterCount > 0 && (
              <Badge variant="secondary" className="ml-1 text-[9px] px-1 py-0 h-4">
                {activeFilterCount}
              </Badge>
            )}
          </Button>
        </div>
      </div>

      {/* Filters */}
      {showFilters && (
        <div className="border rounded-lg p-4 space-y-4 bg-card">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search titles & summaries..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={handleSearchKeyDown}
              className="pl-9"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Severity */}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Severity
              </label>
              <div className="flex flex-wrap gap-1">
                {SEVERITY_OPTIONS.map((sev) => (
                  <Badge
                    key={sev}
                    variant={localFilters.severity === sev ? (sev as any) : "outline"}
                    className="cursor-pointer capitalize"
                    onClick={() =>
                      setLocalFilters((f) => ({
                        ...f,
                        severity: f.severity === sev ? "" : sev,
                      }))
                    }
                  >
                    {sev}
                  </Badge>
                ))}
              </div>
            </div>

            {/* Feed Type */}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Feed Type
              </label>
              <div className="flex flex-wrap gap-1">
                {FEED_TYPE_OPTIONS.map((ft) => (
                  <Badge
                    key={ft}
                    variant={localFilters.feed_type === ft ? "default" : "outline"}
                    className="cursor-pointer capitalize"
                    onClick={() =>
                      setLocalFilters((f) => ({
                        ...f,
                        feed_type: f.feed_type === ft ? "" : ft,
                      }))
                    }
                  >
                    {ft.replace(/_/g, " ")}
                  </Badge>
                ))}
              </div>
            </div>

            {/* Sort */}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Sort By
              </label>
              <div className="flex flex-wrap gap-1">
                {SORT_OPTIONS.map((opt) => {
                  const [field, dir] = opt.value.split(":");
                  return (
                    <Badge
                      key={opt.value}
                      variant={currentSort === opt.value ? "default" : "outline"}
                      className="cursor-pointer"
                      onClick={() =>
                        setLocalFilters((f) => ({ ...f, sort_by: field, sort_order: dir }))
                      }
                    >
                      {opt.label}
                    </Badge>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Asset Type */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
              Asset Type
            </label>
            <div className="flex flex-wrap gap-1">
              {ASSET_TYPE_OPTIONS.map((at) => (
                <Badge
                  key={at}
                  variant={localFilters.asset_type === at ? "default" : "outline"}
                  className="cursor-pointer uppercase text-[10px]"
                  onClick={() =>
                    setLocalFilters((f) => ({
                      ...f,
                      asset_type: f.asset_type === at ? "" : at,
                    }))
                  }
                >
                  {at.replace(/_/g, " ")}
                </Badge>
              ))}
            </div>
          </div>

          {/* Quick Toggles */}
          <div className="flex items-center gap-3">
            <label className="text-xs font-medium text-muted-foreground">Quick Filters:</label>
            <Badge
              variant={localFilters.is_kev === "true" ? "destructive" : "outline"}
              className="cursor-pointer gap-1"
              onClick={() =>
                setLocalFilters((f) => ({
                  ...f,
                  is_kev: f.is_kev === "true" ? "" : "true",
                }))
              }
            >
              <AlertTriangle className="h-3 w-3" /> KEV Only
            </Badge>
            <Badge
              variant={localFilters.exploit_available === "true" ? "default" : "outline"}
              className="cursor-pointer gap-1 text-orange-500 border-orange-500/50"
              onClick={() =>
                setLocalFilters((f) => ({
                  ...f,
                  exploit_available: f.exploit_available === "true" ? "" : "true",
                }))
              }
            >
              <Zap className="h-3 w-3" /> Exploit Available
            </Badge>
          </div>

          <div className="flex gap-2 pt-1">
            <Button size="sm" onClick={applyFilters}>
              <Filter className="h-3 w-3 mr-1" /> Apply
            </Button>
            <Button size="sm" variant="outline" onClick={clearFilters}>
              <X className="h-3 w-3 mr-1" /> Clear All
            </Button>
          </div>
        </div>
      )}

      {/* Active filters summary (shown when panel closed) */}
      {!showFilters && activeFilterCount > 0 && (
        <div className="flex items-center gap-2 flex-wrap text-xs">
          <span className="text-muted-foreground">Active:</span>
          {intelFilters.severity && (
            <Badge variant={intelFilters.severity as any} className="text-[10px] capitalize">
              {intelFilters.severity}
            </Badge>
          )}
          {intelFilters.feed_type && (
            <Badge variant="outline" className="text-[10px] capitalize">
              {intelFilters.feed_type.replace(/_/g, " ")}
            </Badge>
          )}
          {intelFilters.asset_type && (
            <Badge variant="outline" className="text-[10px] uppercase">
              {intelFilters.asset_type.replace(/_/g, " ")}
            </Badge>
          )}
          {intelFilters.is_kev === "true" && (
            <Badge variant="destructive" className="text-[10px] gap-0.5">
              <AlertTriangle className="h-2.5 w-2.5" /> KEV
            </Badge>
          )}
          {intelFilters.exploit_available === "true" && (
            <Badge variant="outline" className="text-[10px] text-orange-500 gap-0.5">
              <Zap className="h-2.5 w-2.5" /> Exploit
            </Badge>
          )}
          {intelFilters.query && (
            <Badge variant="secondary" className="text-[10px]">
              &quot;{intelFilters.query}&quot;
            </Badge>
          )}
          <button
            onClick={clearFilters}
            className="text-[10px] text-primary hover:underline ml-1"
          >
            Clear all
          </button>
        </div>
      )}

      {/* Item List */}
      <div className="space-y-3">
        {intelLoading && !intelData ? (
          Array.from({ length: 5 }).map((_, i) => <IntelCardSkeleton key={i} />)
        ) : intelData?.items.length === 0 ? (
          <div className="text-center py-16 text-muted-foreground">
            <List className="h-12 w-12 mx-auto mb-3 opacity-30" />
            <p className="text-lg">No intel items found</p>
            <p className="text-sm">Adjust filters or wait for feeds to ingest data.</p>
          </div>
        ) : (
          intelData?.items.map((item) => <IntelCard key={item.id} item={item} />)
        )}
      </div>

      {/* Pagination */}
      {intelData && (
        <Pagination
          page={intelData.page}
          pages={intelData.pages}
          onPageChange={handlePageChange}
        />
      )}
    </div>
  );
}
