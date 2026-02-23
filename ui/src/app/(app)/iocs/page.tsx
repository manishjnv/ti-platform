"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useAppStore } from "@/store";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { DonutChart, HorizontalBarChart } from "@/components/charts";
import { Database, Search, Filter, Copy, ExternalLink, Check } from "lucide-react";

const IOC_TYPE_COLORS: Record<string, string> = {
  ip: "#3b82f6",
  domain: "#a855f7",
  url: "#f97316",
  hash: "#ef4444",
  email: "#ec4899",
  cve: "#22c55e",
  other: "#6b7280",
};

export default function IOCDatabasePage() {
  const { intelData, intelLoading, fetchIntel } = useAppStore();
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);

  useEffect(() => {
    fetchIntel(1, { page_size: "200" } as any);
  }, [fetchIntel]);

  // Derive IOC-like records
  const iocRecords = useMemo(() => {
    if (!intelData?.items) return [];
    return intelData.items
      .map((item) => ({
        id: item.id,
        value: item.source_ref || item.title,
        type: item.feed_type || "other",
        severity: item.severity,
        source: item.source_name,
        risk: item.risk_score,
        title: item.title,
        first_seen: item.ingested_at,
      }))
      .filter((ioc) => {
        const matchSearch = !search || ioc.value.toLowerCase().includes(search.toLowerCase()) || ioc.title.toLowerCase().includes(search.toLowerCase());
        const matchType = !typeFilter || ioc.type === typeFilter;
        return matchSearch && matchType;
      });
  }, [intelData, search, typeFilter]);

  // Type distribution donut
  const typeDistribution = useMemo(() => {
    if (!intelData?.items) return [];
    const map: Record<string, number> = {};
    intelData.items.forEach((item) => {
      const t = item.feed_type || "other";
      map[t] = (map[t] || 0) + 1;
    });
    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1).replace(/_/g, " "),
        value,
        color: IOC_TYPE_COLORS[name] || IOC_TYPE_COLORS.other,
      }));
  }, [intelData]);

  const types = useMemo(() => {
    if (!intelData?.items) return [];
    const set = new Set(intelData.items.map((i) => i.feed_type || "other"));
    return Array.from(set);
  }, [intelData]);

  const handleCopy = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 1500);
  };

  if (intelLoading && !intelData) return <Loading text="Loading IOC database..." />;

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

      {/* Top row: search + type pills + donut */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-3">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search IOCs by value or title..."
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
              Showing <span className="font-semibold text-foreground">{iocRecords.length}</span> of{" "}
              <span className="font-semibold text-foreground">{intelData?.total ?? 0}</span> IOCs
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
              centerValue={intelData?.total ?? 0}
              centerLabel="IOCs"
              height={160}
              innerRadius={40}
              outerRadius={60}
            />
          </CardContent>
        </Card>
      </div>

      {/* IOC Table */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border/40">
                  <th className="text-left py-2.5 px-4 text-muted-foreground font-medium">IOC Value</th>
                  <th className="text-left py-2.5 px-4 text-muted-foreground font-medium">Type</th>
                  <th className="text-left py-2.5 px-4 text-muted-foreground font-medium">Severity</th>
                  <th className="text-left py-2.5 px-4 text-muted-foreground font-medium">Risk</th>
                  <th className="text-left py-2.5 px-4 text-muted-foreground font-medium">Source</th>
                  <th className="text-left py-2.5 px-4 text-muted-foreground font-medium">First Seen</th>
                  <th className="py-2.5 px-4"></th>
                </tr>
              </thead>
              <tbody>
                {iocRecords.slice(0, 50).map((ioc, idx) => {
                  const sevCol =
                    ioc.severity === "critical" ? "#ef4444" :
                    ioc.severity === "high" ? "#f97316" :
                    ioc.severity === "medium" ? "#eab308" : "#22c55e";
                  return (
                    <tr
                      key={ioc.id || idx}
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
                            background: (IOC_TYPE_COLORS[ioc.type] || IOC_TYPE_COLORS.other) + "20",
                            color: IOC_TYPE_COLORS[ioc.type] || IOC_TYPE_COLORS.other,
                          }}
                        >
                          {ioc.type}
                        </Badge>
                      </td>
                      <td className="py-2 px-4">
                        <Badge
                          variant="outline"
                          className="text-[10px]"
                          style={{ borderColor: sevCol, color: sevCol }}
                        >
                          {ioc.severity}
                        </Badge>
                      </td>
                      <td className="py-2 px-4">
                        <span className="font-semibold" style={{ color: sevCol }}>
                          {ioc.risk}
                        </span>
                      </td>
                      <td className="py-2 px-4 text-muted-foreground">{ioc.source}</td>
                      <td className="py-2 px-4 text-muted-foreground">
                        {ioc.first_seen
                          ? new Date(ioc.first_seen).toLocaleDateString()
                          : "—"}
                      </td>
                      <td className="py-2 px-4">
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
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {iocRecords.length === 0 && (
              <div className="py-12 text-center text-xs text-muted-foreground/60">
                No IOCs match your search
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
