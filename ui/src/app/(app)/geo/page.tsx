"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useAppStore } from "@/store";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { DonutChart, HorizontalBarChart } from "@/components/charts";
import { RankedDataList } from "@/components/RankedDataList";
import { Globe, MapPin, Shield, Filter } from "lucide-react";

const REGION_COLORS = [
  "#3b82f6", "#ef4444", "#f97316", "#a855f7", "#22c55e",
  "#ec4899", "#14b8a6", "#eab308", "#6366f1", "#f43f5e",
];

export default function GeoViewPage() {
  const { dashboard, dashboardLoading, fetchDashboard } = useAppStore();
  const [selectedRegion, setSelectedRegion] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  // Parse geo data from top_risks
  const geoAll = useMemo(() => {
    if (!dashboard?.top_risks) return [];
    const geoMap: Record<string, { count: number; sevMap: Record<string, number> }> = {};
    dashboard.top_risks.forEach((item) => {
      (item.geo || []).forEach((g) => {
        if (!geoMap[g]) geoMap[g] = { count: 0, sevMap: {} };
        geoMap[g].count += 1;
        geoMap[g].sevMap[item.severity] = (geoMap[g].sevMap[item.severity] || 0) + 1;
      });
    });
    return Object.entries(geoMap)
      .sort((a, b) => b[1].count - a[1].count)
      .map(([name, data], i) => ({
        name,
        count: data.count,
        sevMap: data.sevMap,
        color: REGION_COLORS[i % REGION_COLORS.length],
      }));
  }, [dashboard]);

  const regionDonut = useMemo(
    () => geoAll.map((g) => ({ name: g.name, value: g.count, color: g.color })),
    [geoAll]
  );

  const regionHBar = useMemo(
    () => geoAll.map((g) => ({ name: g.name, value: g.count, color: g.color })),
    [geoAll]
  );

  // Threats for selected region
  const regionThreats = useMemo(() => {
    if (!selectedRegion || !dashboard?.top_risks) return [];
    return dashboard.top_risks.filter((item) => item.geo?.includes(selectedRegion));
  }, [selectedRegion, dashboard]);

  if (dashboardLoading && !dashboard) return <Loading text="Loading geo data..." />;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
          <Globe className="h-5 w-5 text-primary" />
          Geographic Threat View
        </h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Threat distribution by targeted region
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card className="border-border/50">
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Regions Targeted</p>
            <p className="text-2xl font-bold mt-1">{geoAll.length}</p>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Total Geo Mentions</p>
            <p className="text-2xl font-bold mt-1">{geoAll.reduce((s, g) => s + g.count, 0)}</p>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Top Region</p>
            <p className="text-2xl font-bold mt-1 truncate">
              {geoAll[0]?.name ?? "N/A"}
            </p>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Selected Region</p>
            <p className="text-2xl font-bold mt-1 truncate text-primary">
              {selectedRegion ?? "None"}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Donut */}
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Region Distribution</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {regionDonut.length > 0 ? (
              <DonutChart
                data={regionDonut}
                centerValue={geoAll.length}
                centerLabel="Regions"
                height={220}
                innerRadius={55}
                outerRadius={80}
              />
            ) : (
              <EmptyGeo />
            )}
          </CardContent>
        </Card>

        {/* Horizontal Bar */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Threats by Region</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {regionHBar.length > 0 ? (
              <HorizontalBarChart data={regionHBar} />
            ) : (
              <EmptyGeo />
            )}
          </CardContent>
        </Card>
      </div>

      {/* Region Selector + Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Region list */}
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <div className="flex items-center gap-2">
              <MapPin className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm font-semibold">All Regions</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="px-3 pb-3 max-h-[360px] overflow-y-auto">
            {geoAll.length > 0 ? (
              <div className="space-y-1">
                {geoAll.map((g) => (
                  <button
                    key={g.name}
                    onClick={() => setSelectedRegion(g.name === selectedRegion ? null : g.name)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs transition-colors ${
                      selectedRegion === g.name
                        ? "bg-primary/20 text-primary"
                        : "hover:bg-muted/40"
                    }`}
                  >
                    <span className="flex items-center gap-2">
                      <span
                        className="w-2.5 h-2.5 rounded-full"
                        style={{ background: g.color }}
                      />
                      {g.name}
                    </span>
                    <Badge variant="secondary" className="text-[10px] h-5">
                      {g.count}
                    </Badge>
                  </button>
                ))}
              </div>
            ) : (
              <EmptyGeo />
            )}
          </CardContent>
        </Card>

        {/* Region detail */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">
              {selectedRegion ? `Threats targeting ${selectedRegion}` : "Select a region"}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-3 pb-3 max-h-[360px] overflow-y-auto">
            {selectedRegion ? (
              regionThreats.length > 0 ? (
                <div className="space-y-2">
                  {regionThreats.map((item, i) => {
                    const sevCol =
                      item.severity === "critical"
                        ? "#ef4444"
                        : item.severity === "high"
                        ? "#f97316"
                        : item.severity === "medium"
                        ? "#eab308"
                        : "#22c55e";
                    return (
                      <div
                        key={i}
                        className="flex items-center gap-3 px-3 py-2.5 rounded-md border border-border/40 bg-muted/20"
                      >
                        <div
                          className="w-1.5 h-8 rounded-full shrink-0"
                          style={{ background: sevCol }}
                        />
                        <div className="min-w-0 flex-1">
                          <p className="text-xs font-medium truncate">{item.title}</p>
                          <p className="text-[10px] text-muted-foreground">
                            {item.source_name} · Risk {item.risk_score}
                          </p>
                        </div>
                        <Badge
                          variant="outline"
                          className="text-[10px] shrink-0"
                          style={{ borderColor: sevCol, color: sevCol }}
                        >
                          {item.severity}
                        </Badge>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="h-[200px] flex items-center justify-center text-xs text-muted-foreground/60">
                  No threats for this region
                </div>
              )
            ) : (
              <div className="h-[200px] flex items-center justify-center text-xs text-muted-foreground/60">
                <Filter className="h-4 w-4 mr-2" />
                Click a region to see associated threats
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function EmptyGeo() {
  return (
    <div className="h-[180px] flex items-center justify-center text-xs text-muted-foreground/60">
      No geographic data available
    </div>
  );
}
