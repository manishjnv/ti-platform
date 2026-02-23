"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useAppStore } from "@/store";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { DonutChart } from "@/components/charts";
import { ThreatLevelBar } from "@/components/ThreatLevelBar";
import { RankedDataList } from "@/components/RankedDataList";
import {
  AlertTriangle,
  Shield,
  Zap,
  ExternalLink,
  Clock,
  ChevronRight,
} from "lucide-react";
import { formatDate, severityBorder, riskColor, riskBg } from "@/lib/utils";
import { cn } from "@/lib/utils";

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
};

export default function ThreatsPage() {
  const { intelData, intelLoading, fetchIntel, dashboard, fetchDashboard } = useAppStore();
  const [selectedSev, setSelectedSev] = useState<string | null>(null);

  useEffect(() => {
    fetchIntel(1, { sort_by: "risk_score" });
    fetchDashboard();
  }, [fetchIntel, fetchDashboard]);

  const filteredItems = useMemo(() => {
    if (!intelData?.items) return [];
    if (!selectedSev) return intelData.items;
    return intelData.items.filter((i) => i.severity === selectedSev);
  }, [intelData, selectedSev]);

  // Asset type distribution
  const assetDonut = useMemo(() => {
    if (!intelData?.items) return [];
    const grouped: Record<string, number> = {};
    intelData.items.forEach((item) => {
      grouped[item.asset_type] = (grouped[item.asset_type] || 0) + 1;
    });
    const colors = ["#3b82f6", "#ef4444", "#f97316", "#22c55e", "#a855f7", "#ec4899", "#14b8a6", "#6b7280"];
    return Object.entries(grouped).map(([key, count], i) => ({
      name: key.toUpperCase().replace(/_/g, " "),
      value: count,
      color: colors[i % colors.length],
    }));
  }, [intelData]);

  if (intelLoading && !intelData) return <Loading text="Loading threat feed..." />;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      <div>
        <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-amber-500" />
          Active Threats
        </h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Real-time threat intelligence feed sorted by risk
        </p>
      </div>

      {/* Severity Filter Pills */}
      <div className="flex items-center gap-2 flex-wrap">
        <Badge
          variant={selectedSev === null ? "default" : "outline"}
          className="cursor-pointer"
          onClick={() => setSelectedSev(null)}
        >
          All
        </Badge>
        {["critical", "high", "medium", "low", "info"].map((s) => (
          <Badge
            key={s}
            variant={selectedSev === s ? (s as any) : "outline"}
            className="cursor-pointer"
            onClick={() => setSelectedSev(selectedSev === s ? null : s)}
          >
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </Badge>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Main threat list */}
        <div className="lg:col-span-3 space-y-2">
          {filteredItems.map((item) => (
            <div
              key={item.id}
              className={cn(
                "border-l-4 rounded-lg border bg-card p-3 hover:shadow-md transition-all cursor-pointer group",
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
                  <div className="flex items-center gap-3 mt-1 text-[11px] text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Shield className="h-3 w-3" /> {item.source_name}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" /> {formatDate(item.published_at || item.ingested_at, { relative: true })}
                    </span>
                    {item.cve_ids?.length > 0 && (
                      <span className="font-mono text-primary">{item.cve_ids[0]}</span>
                    )}
                  </div>
                </div>
                <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-primary transition-colors shrink-0 mt-1" />
              </div>
            </div>
          ))}

          {filteredItems.length === 0 && (
            <div className="text-center py-16 text-muted-foreground text-sm">
              No threats matching this filter
            </div>
          )}
        </div>

        {/* Right sidebar */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-1 pt-4 px-4">
              <CardTitle className="text-xs font-semibold">Asset Types</CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4">
              <DonutChart
                data={assetDonut}
                centerValue={intelData?.total || 0}
                centerLabel="Items"
                height={160}
                innerRadius={40}
                outerRadius={60}
              />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
