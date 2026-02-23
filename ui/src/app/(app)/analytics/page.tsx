"use client";

import React, { useEffect, useMemo } from "react";
import { useAppStore } from "@/store";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { StatCard } from "@/components/StatCard";
import { DonutChart, HorizontalBarChart, TrendLineChart } from "@/components/charts";
import { RankedDataList } from "@/components/RankedDataList";
import { ThreatLevelBar } from "@/components/ThreatLevelBar";
import {
  BarChart3,
  TrendingUp,
  Shield,
  AlertTriangle,
  Globe,
  Activity,
} from "lucide-react";

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
  unknown: "#6b7280",
};

export default function AnalyticsPage() {
  const { dashboard, dashboardLoading, fetchDashboard, intelData, fetchIntel } = useAppStore();

  useEffect(() => {
    fetchDashboard();
    fetchIntel(1, { page_size: "100" } as any);
  }, [fetchDashboard, fetchIntel]);

  // Severity distribution for horizontal bar
  const sevHBar = useMemo(() => {
    if (!dashboard) return [];
    const grouped: Record<string, number> = {};
    dashboard.severity_distribution.forEach((d) => {
      grouped[d.severity] = (grouped[d.severity] || 0) + d.count;
    });
    return Object.entries(grouped)
      .sort((a, b) => b[1] - a[1])
      .map(([sev, count]) => ({
        name: sev.charAt(0).toUpperCase() + sev.slice(1),
        value: count,
        color: SEV_COLORS[sev] || SEV_COLORS.unknown,
      }));
  }, [dashboard]);

  // Feed types bar
  const feedTypeBar = useMemo(() => {
    if (!dashboard) return [];
    const grouped: Record<string, number> = {};
    dashboard.severity_distribution.forEach((d) => {
      grouped[d.feed_type] = (grouped[d.feed_type] || 0) + d.count;
    });
    const colors = ["#ef4444", "#f97316", "#a855f7", "#3b82f6", "#22c55e", "#ec4899", "#14b8a6"];
    return Object.entries(grouped)
      .sort((a, b) => b[1] - a[1])
      .map(([ft, count], i) => ({
        name: ft.charAt(0).toUpperCase() + ft.slice(1).replace(/_/g, " "),
        value: count,
        color: colors[i % colors.length],
      }));
  }, [dashboard]);

  // Geo data from top risks
  const geoData = useMemo(() => {
    if (!dashboard?.top_risks) return [];
    const geoMap: Record<string, number> = {};
    dashboard.top_risks.forEach((item) => {
      item.geo?.forEach((g) => {
        geoMap[g] = (geoMap[g] || 0) + 1;
      });
    });
    return Object.entries(geoMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, value]) => ({ name, value, color: "#3b82f6" }));
  }, [dashboard]);

  // Industry data
  const industryData = useMemo(() => {
    if (!dashboard?.top_risks) return [];
    const indMap: Record<string, number> = {};
    dashboard.top_risks.forEach((item) => {
      item.industries?.forEach((ind) => {
        indMap[ind] = (indMap[ind] || 0) + 1;
      });
    });
    const colors = ["#a855f7", "#3b82f6", "#22c55e", "#f97316", "#ef4444", "#ec4899"];
    return Object.entries(indMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([label, value], i) => ({
        label,
        value,
        color: colors[i % colors.length],
      }));
  }, [dashboard]);

  // Source reliability breakdown
  const sourceReliability = useMemo(() => {
    if (!dashboard?.top_risks) return [];
    const srcMap: Record<string, { total: number; count: number }> = {};
    dashboard.top_risks.forEach((item) => {
      if (!srcMap[item.source_name]) srcMap[item.source_name] = { total: 0, count: 0 };
      srcMap[item.source_name].total += item.source_reliability;
      srcMap[item.source_name].count += 1;
    });
    return Object.entries(srcMap)
      .map(([name, { total, count }]) => ({
        name,
        value: Math.round(total / count),
        color: total / count >= 70 ? "#22c55e" : total / count >= 40 ? "#eab308" : "#ef4444",
      }))
      .sort((a, b) => b.value - a.value);
  }, [dashboard]);

  // Tag cloud data
  const topTags = useMemo(() => {
    if (!dashboard?.top_risks) return [];
    const tagMap: Record<string, number> = {};
    dashboard.top_risks.forEach((item) => {
      item.tags?.forEach((tag) => {
        tagMap[tag] = (tagMap[tag] || 0) + 1;
      });
    });
    const colors = ["#3b82f6", "#ef4444", "#22c55e", "#f97316", "#a855f7", "#ec4899", "#14b8a6", "#eab308"];
    return Object.entries(tagMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([label, value], i) => ({
        label,
        value,
        color: colors[i % colors.length],
      }));
  }, [dashboard]);

  // Exploit availability stats
  const exploitStats = useMemo(() => {
    if (!dashboard?.top_risks) return { total: 0, withExploit: 0, kev: 0 };
    const total = dashboard.top_risks.length;
    const withExploit = dashboard.top_risks.filter((i) => i.exploit_available).length;
    const kev = dashboard.top_risks.filter((i) => i.is_kev).length;
    return { total, withExploit, kev };
  }, [dashboard]);

  if (dashboardLoading && !dashboard) return <Loading text="Loading analytics..." />;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-primary" />
          Threat Analytics
        </h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Deep analysis across all ingested intelligence
        </p>
      </div>

      {/* Overview Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard
          title="Total Items"
          value={dashboard?.total_items ?? 0}
          icon={<Shield className="h-5 w-5" />}
        />
        <StatCard
          title="Avg Risk"
          value={Math.round(dashboard?.avg_risk_score ?? 0)}
          icon={<TrendingUp className="h-5 w-5" />}
          variant={(dashboard?.avg_risk_score ?? 0) >= 60 ? "danger" : "warning"}
        />
        <StatCard
          title="Exploits Available"
          value={exploitStats.withExploit}
          subtitle={`of ${exploitStats.total} high-risk items`}
          icon={<Activity className="h-5 w-5" />}
          variant="warning"
        />
        <StatCard
          title="KEV Count"
          value={dashboard?.kev_count ?? 0}
          icon={<AlertTriangle className="h-5 w-5" />}
          variant="danger"
        />
      </div>

      {/* Charts Row 1: Severity (horizontal) + Feed Types (donut) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {sevHBar.length > 0 ? (
              <HorizontalBarChart data={sevHBar} />
            ) : (
              <EmptyState />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Intel Categories</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {feedTypeBar.length > 0 ? (
              <DonutChart
                data={feedTypeBar}
                centerValue={dashboard?.total_items ?? 0}
                centerLabel="Total"
                height={200}
                innerRadius={55}
                outerRadius={78}
              />
            ) : (
              <EmptyState />
            )}
          </CardContent>
        </Card>
      </div>

      {/* Charts Row 2: Geo + Industries + Tags */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm font-semibold">Top Targeted Regions</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {geoData.length > 0 ? (
              <HorizontalBarChart data={geoData} barColor="#3b82f6" />
            ) : (
              <EmptyState text="No geo data available" />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Targeted Industries</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {industryData.length > 0 ? (
              <RankedDataList items={industryData} showIndex />
            ) : (
              <EmptyState text="No industry data" />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Top Tags</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {topTags.length > 0 ? (
              <RankedDataList items={topTags} showIndex />
            ) : (
              <EmptyState text="No tag data" />
            )}
          </CardContent>
        </Card>
      </div>

      {/* Source Reliability */}
      <Card>
        <CardHeader className="pb-2 pt-4 px-5">
          <CardTitle className="text-sm font-semibold">Source Reliability Scores</CardTitle>
        </CardHeader>
        <CardContent className="px-5 pb-4">
          {sourceReliability.length > 0 ? (
            <HorizontalBarChart data={sourceReliability} />
          ) : (
            <EmptyState text="No source data" />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function EmptyState({ text = "No data available" }: { text?: string }) {
  return (
    <div className="h-[180px] flex items-center justify-center text-xs text-muted-foreground/60">
      {text}
    </div>
  );
}
