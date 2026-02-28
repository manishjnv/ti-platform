"use client";

import React, { useEffect, useMemo } from "react";
import { useAppStore } from "@/store";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { StatCard } from "@/components/StatCard";
import { ThreatLevelBar } from "@/components/ThreatLevelBar";
import { FeedStatusPanel } from "@/components/FeedStatusPanel";
import { RankedDataList } from "@/components/RankedDataList";
import { DonutChart, TrendLineChart, HorizontalBarChart } from "@/components/charts";
import {
  Shield,
  AlertTriangle,
  TrendingUp,
  Clock,
  Loader2,
  Zap,
  BarChart3,
  Activity,
  Bell,
  FileText,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
  unknown: "#6b7280",
};

const FEED_TYPE_COLORS: Record<string, string> = {
  vulnerability: "#ef4444",
  ioc: "#f97316",
  malware: "#a855f7",
  exploit: "#ec4899",
  advisory: "#3b82f6",
  threat_actor: "#14b8a6",
  campaign: "#8b5cf6",
};

export default function DashboardPage() {
  const { dashboard, dashboardLoading, fetchDashboard, unreadCount, fetchUnreadCount, reportStats, fetchReportStats } = useAppStore();

  useEffect(() => {
    fetchDashboard();
    fetchUnreadCount();
    fetchReportStats();
    const interval = setInterval(fetchDashboard, 60000);
    const notifInterval = setInterval(fetchUnreadCount, 30000);
    return () => { clearInterval(interval); clearInterval(notifInterval); };
  }, [fetchDashboard, fetchUnreadCount, fetchReportStats]);

  // Severity distribution for donut chart
  const sevDonut = useMemo(() => {
    if (!dashboard) return [];
    const grouped: Record<string, number> = {};
    dashboard.severity_distribution.forEach((d) => {
      grouped[d.severity] = (grouped[d.severity] || 0) + d.count;
    });
    return Object.entries(grouped).map(([severity, count]) => ({
      name: severity.charAt(0).toUpperCase() + severity.slice(1),
      value: count,
      color: SEV_COLORS[severity] || SEV_COLORS.unknown,
    }));
  }, [dashboard]);

  // Feed type distribution for donut chart
  const feedTypeDonut = useMemo(() => {
    if (!dashboard) return [];
    const grouped: Record<string, number> = {};
    dashboard.severity_distribution.forEach((d) => {
      grouped[d.feed_type] = (grouped[d.feed_type] || 0) + d.count;
    });
    return Object.entries(grouped).map(([ft, count]) => ({
      name: ft.charAt(0).toUpperCase() + ft.slice(1).replace(/_/g, " "),
      value: count,
      color: FEED_TYPE_COLORS[ft] || "#6b7280",
    }));
  }, [dashboard]);

  // Severity bar chart data
  const sevBarData = useMemo(() => {
    if (!dashboard) return [];
    const grouped: Record<string, number> = {};
    dashboard.severity_distribution.forEach((d) => {
      grouped[d.severity] = (grouped[d.severity] || 0) + d.count;
    });
    return ["critical", "high", "medium", "low", "info"].map((sev) => ({
      severity: sev.charAt(0).toUpperCase() + sev.slice(1),
      count: grouped[sev] || 0,
      fill: SEV_COLORS[sev],
    }));
  }, [dashboard]);

  // Threat level bar (high/medium/low aggregation)
  const threatLevels = useMemo(() => {
    if (!dashboard) return [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    dashboard.severity_distribution.forEach((d) => {
      if (d.severity in counts) {
        counts[d.severity as keyof typeof counts] += d.count;
      }
    });
    const highCount = counts.critical + counts.high;
    const medCount = counts.medium;
    const lowCount = counts.low + counts.info;
    return [
      { label: "High", value: highCount, color: "#ef4444" },
      { label: "Medium", value: medCount, color: "#eab308" },
      { label: "Low", value: lowCount, color: "#22c55e" },
    ];
  }, [dashboard]);

  // Top sources ranked list
  const topSources = useMemo(() => {
    if (!dashboard?.top_risks) return [];
    const sourceMap: Record<string, number> = {};
    dashboard.top_risks.forEach((item) => {
      sourceMap[item.source_name] = (sourceMap[item.source_name] || 0) + 1;
    });
    return Object.entries(sourceMap)
      .sort((a, b) => b[1] - a[1])
      .map(([label, value], i) => ({
        label,
        value,
        color: Object.values(SEV_COLORS)[i % Object.values(SEV_COLORS).length],
      }));
  }, [dashboard]);

  // Top CVEs
  const topCVEs = useMemo(() => {
    if (!dashboard?.top_risks) return [];
    const cveMap: Record<string, number> = {};
    dashboard.top_risks.forEach((item) => {
      item.cve_ids?.forEach((cve) => {
        cveMap[cve] = (cveMap[cve] || 0) + 1;
      });
    });
    return Object.entries(cveMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([label, value]) => ({ label, value, color: "#ef4444" }));
  }, [dashboard]);

  // Top risk items for table
  const topRiskItems = useMemo(() => {
    if (!dashboard?.top_risks) return [];
    return [...dashboard.top_risks]
      .sort((a, b) => b.risk_score - a.risk_score)
      .slice(0, 8);
  }, [dashboard]);

  if (dashboardLoading && !dashboard) return <Loading text="Loading dashboard..." />;

  const totalItems = dashboard?.total_items ?? 0;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      {/* Header Bar */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight">Threat Intelligence Dashboard</h1>
            {dashboardLoading && (
              <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            Real-time overview · Last updated {new Date().toLocaleTimeString()}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="gap-1.5 text-xs">
            <Activity className="h-3 w-3 text-emerald-500" />
            Live
          </Badge>
        </div>
      </div>

      {/* KPI Stats Row */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
        <StatCard
          title="Total Intel"
          value={totalItems}
          subtitle="All ingested items"
          icon={<Shield className="h-5 w-5" />}
        />
        <StatCard
          title="Last 24 Hours"
          value={dashboard?.items_last_24h ?? 0}
          subtitle="New items today"
          icon={<Clock className="h-5 w-5" />}
          variant="default"
        />
        <StatCard
          title="Avg Risk Score"
          value={Math.round(dashboard?.avg_risk_score ?? 0)}
          subtitle="Across all intel"
          icon={<TrendingUp className="h-5 w-5" />}
          variant={(dashboard?.avg_risk_score ?? 0) >= 60 ? "danger" : (dashboard?.avg_risk_score ?? 0) >= 40 ? "warning" : "success"}
        />
        <StatCard
          title="KEV Listed"
          value={dashboard?.kev_count ?? 0}
          subtitle="Known Exploited Vulns"
          icon={<AlertTriangle className="h-5 w-5" />}
          variant="danger"
        />
        <StatCard
          title="Reports"
          value={reportStats?.total_reports ?? 0}
          subtitle={`${reportStats?.by_status?.published ?? 0} published`}
          icon={<FileText className="h-5 w-5" />}
        />
        <StatCard
          title="Alerts"
          value={unreadCount}
          subtitle="Unread notifications"
          icon={<Bell className="h-5 w-5" />}
          variant={unreadCount > 0 ? "warning" : "success"}
        />
      </div>

      {/* Threat Level Bar (like Payment Fraud ref img) */}
      {threatLevels.length > 0 && (
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Threat Level Distribution</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            <ThreatLevelBar levels={threatLevels} />
          </CardContent>
        </Card>
      )}

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Severity Donut */}
        <Card>
          <CardHeader className="pb-1 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Severity Breakdown</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {sevDonut.length > 0 ? (
              <DonutChart
                data={sevDonut}
                centerValue={totalItems}
                centerLabel="Total"
                height={180}
                innerRadius={50}
                outerRadius={72}
              />
            ) : (
              <EmptyState />
            )}
          </CardContent>
        </Card>

        {/* Feed Type Donut */}
        <Card>
          <CardHeader className="pb-1 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Intel by Category</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {feedTypeDonut.length > 0 ? (
              <DonutChart
                data={feedTypeDonut}
                centerValue={feedTypeDonut.length}
                centerLabel="Types"
                height={180}
                innerRadius={50}
                outerRadius={72}
              />
            ) : (
              <EmptyState />
            )}
          </CardContent>
        </Card>

        {/* Severity Bar Chart */}
        <Card>
          <CardHeader className="pb-1 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Severity Counts</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {sevBarData.some((d) => d.count > 0) ? (
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={sevBarData} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                  <XAxis
                    dataKey="severity"
                    tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }}
                    tickLine={false}
                    axisLine={{ stroke: "hsl(var(--border))" }}
                  />
                  <YAxis
                    tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }}
                    tickLine={false}
                    axisLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]} barSize={32}>
                    {sevBarData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState />
            )}
          </CardContent>
        </Card>
      </div>

      {/* Middle Row: Sources & CVEs & Feed Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Top Sources */}
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Top Sources</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {topSources.length > 0 ? (
              <RankedDataList items={topSources} showIndex maxItems={6} />
            ) : (
              <EmptyState text="No source data" />
            )}
          </CardContent>
        </Card>

        {/* Top CVEs */}
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Top CVEs Referenced</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {topCVEs.length > 0 ? (
              <RankedDataList items={topCVEs} showIndex maxItems={8} />
            ) : (
              <EmptyState text="No CVE data" />
            )}
          </CardContent>
        </Card>

        {/* Feed Status */}
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Feed Connectors</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {dashboard?.feed_status && dashboard.feed_status.length > 0 ? (
              <FeedStatusPanel feeds={dashboard.feed_status} />
            ) : (
              <EmptyState text="No feeds configured" />
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top Risks Table */}
      <Card>
        <CardHeader className="pb-2 pt-4 px-5">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold">Highest Risk Items</CardTitle>
            <Badge variant="outline" className="text-xs">
              Top {topRiskItems.length}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="px-5 pb-4">
          {topRiskItems.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/50">
                    <th className="text-left py-2 px-2 font-semibold text-muted-foreground uppercase tracking-wider">Risk</th>
                    <th className="text-left py-2 px-2 font-semibold text-muted-foreground uppercase tracking-wider">Severity</th>
                    <th className="text-left py-2 px-2 font-semibold text-muted-foreground uppercase tracking-wider">Title</th>
                    <th className="text-left py-2 px-2 font-semibold text-muted-foreground uppercase tracking-wider">Source</th>
                    <th className="text-left py-2 px-2 font-semibold text-muted-foreground uppercase tracking-wider">Type</th>
                    <th className="text-left py-2 px-2 font-semibold text-muted-foreground uppercase tracking-wider">CVEs</th>
                    <th className="text-left py-2 px-2 font-semibold text-muted-foreground uppercase tracking-wider">KEV</th>
                  </tr>
                </thead>
                <tbody>
                  {topRiskItems.map((item) => (
                    <tr
                      key={item.id}
                      className="border-b border-border/30 hover:bg-accent/30 transition-colors cursor-pointer"
                    >
                      <td className="py-2.5 px-2">
                        <span
                          className={`inline-flex items-center justify-center h-7 w-10 rounded-md text-xs font-bold ${
                            item.risk_score >= 80
                              ? "bg-red-500/15 text-red-500"
                              : item.risk_score >= 60
                              ? "bg-orange-500/15 text-orange-500"
                              : item.risk_score >= 40
                              ? "bg-yellow-500/15 text-yellow-500"
                              : "bg-green-500/15 text-green-500"
                          }`}
                        >
                          {item.risk_score}
                        </span>
                      </td>
                      <td className="py-2.5 px-2">
                        <Badge variant={item.severity as any} className="text-[10px] px-1.5 py-0">
                          {item.severity.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="py-2.5 px-2 max-w-xs">
                        <span className="font-medium text-foreground line-clamp-1">{item.title}</span>
                      </td>
                      <td className="py-2.5 px-2 text-muted-foreground">{item.source_name}</td>
                      <td className="py-2.5 px-2">
                        <span className="text-muted-foreground capitalize">{item.feed_type.replace(/_/g, " ")}</span>
                      </td>
                      <td className="py-2.5 px-2">
                        {item.cve_ids?.length > 0 ? (
                          <span className="font-mono text-primary">{item.cve_ids[0]}</span>
                        ) : (
                          <span className="text-muted-foreground/40">—</span>
                        )}
                        {(item.cve_ids?.length ?? 0) > 1 && (
                          <span className="text-muted-foreground ml-1">+{item.cve_ids.length - 1}</span>
                        )}
                      </td>
                      <td className="py-2.5 px-2">
                        {item.is_kev ? (
                          <span className="text-red-500 font-semibold flex items-center gap-1">
                            <Zap className="h-3 w-3" /> Yes
                          </span>
                        ) : (
                          <span className="text-muted-foreground/40">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Shield className="h-10 w-10 mb-3 opacity-20" />
              <p className="text-sm">No threat intel data yet.</p>
              <p className="text-xs mt-1">Feed ingestion will populate this automatically.</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function EmptyState({ text = "No data yet" }: { text?: string }) {
  return (
    <div className="h-[180px] flex items-center justify-center text-xs text-muted-foreground/60">
      {text}
    </div>
  );
}
