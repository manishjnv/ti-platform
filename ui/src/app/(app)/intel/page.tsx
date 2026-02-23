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
} from "lucide-react";

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];
const FEED_TYPE_OPTIONS = ["vulnerability", "ioc", "malware", "exploit", "advisory"];
const SORT_OPTIONS = [
  { value: "ingested_at", label: "Newest" },
  { value: "risk_score", label: "Highest Risk" },
  { value: "published_at", label: "Published Date" },
];

export default function IntelFeedPage() {
  const { intelData, intelLoading, intelPage, intelFilters, fetchIntel, setIntelPage, setIntelFilters } = useAppStore();
  const [showFilters, setShowFilters] = useState(false);
  const [localFilters, setLocalFilters] = useState<Record<string, string>>(intelFilters);

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
    const cleaned = Object.fromEntries(
      Object.entries(localFilters).filter(([_, v]) => v !== "")
    );
    setIntelFilters(cleaned);
    fetchIntel(1, cleaned);
  };

  const clearFilters = () => {
    setLocalFilters({});
    setIntelFilters({});
    fetchIntel(1, {});
  };

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
            variant="outline"
            size="sm"
            onClick={() => setShowFilters(!showFilters)}
          >
            <SlidersHorizontal className="h-4 w-4 mr-1" />
            Filters
          </Button>
        </div>
      </div>

      {/* Filters */}
      {showFilters && (
        <div className="border rounded-lg p-4 space-y-3 bg-card">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {/* Severity */}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">
                Severity
              </label>
              <div className="flex flex-wrap gap-1">
                {SEVERITY_OPTIONS.map((sev) => (
                  <Badge
                    key={sev}
                    variant={localFilters.severity === sev ? (sev as any) : "outline"}
                    className="cursor-pointer"
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
              <label className="text-xs font-medium text-muted-foreground mb-1 block">
                Feed Type
              </label>
              <div className="flex flex-wrap gap-1">
                {FEED_TYPE_OPTIONS.map((ft) => (
                  <Badge
                    key={ft}
                    variant={localFilters.feed_type === ft ? "default" : "outline"}
                    className="cursor-pointer"
                    onClick={() =>
                      setLocalFilters((f) => ({
                        ...f,
                        feed_type: f.feed_type === ft ? "" : ft,
                      }))
                    }
                  >
                    {ft}
                  </Badge>
                ))}
              </div>
            </div>

            {/* Sort */}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">
                Sort By
              </label>
              <div className="flex flex-wrap gap-1">
                {SORT_OPTIONS.map((opt) => (
                  <Badge
                    key={opt.value}
                    variant={
                      (localFilters.sort_by || "ingested_at") === opt.value
                        ? "default"
                        : "outline"
                    }
                    className="cursor-pointer"
                    onClick={() =>
                      setLocalFilters((f) => ({ ...f, sort_by: opt.value }))
                    }
                  >
                    {opt.label}
                  </Badge>
                ))}
              </div>
            </div>
          </div>

          <div className="flex gap-2">
            <Button size="sm" onClick={applyFilters}>
              <Filter className="h-3 w-3 mr-1" /> Apply
            </Button>
            <Button size="sm" variant="outline" onClick={clearFilters}>
              Clear
            </Button>
          </div>
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
