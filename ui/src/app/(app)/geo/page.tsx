"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useAppStore } from "@/store";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { DonutChart, HorizontalBarChart } from "@/components/charts";
import {
  Globe,
  MapPin,
  Shield,
  Filter,
  Server,
  AlertTriangle,
  Activity,
  ChevronRight,
  Building2,
  Layers,
} from "lucide-react";
import { getDashboardInsights, getIOCStats, type IOCStatsResponse } from "@/lib/api";
import type { DashboardInsights } from "@/types";

/* ─── Constants ─────────────────────────────────────────── */

const REGION_COLORS = [
  "#3b82f6", "#ef4444", "#f97316", "#a855f7", "#22c55e",
  "#ec4899", "#14b8a6", "#eab308", "#6366f1", "#f43f5e",
  "#06b6d4", "#84cc16", "#d946ef", "#f59e0b", "#10b981",
];

const CONTINENT_EMOJI: Record<string, string> = {
  NA: "🌎", SA: "🌎", EU: "🌍", AF: "🌍", AS: "🌏", OC: "🌏", AN: "🏔️",
};

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

/* ─── Main Page ─────────────────────────────────────────── */

export default function GeoViewPage() {
  const { dashboard, dashboardLoading, fetchDashboard } = useAppStore();
  const [insights, setInsights] = useState<DashboardInsights | null>(null);
  const [iocStats, setIOCStats] = useState<IOCStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedCountry, setSelectedCountry] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"countries" | "continents" | "networks" | "industries" | "intel">("countries");

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const [ins, stats] = await Promise.all([
          getDashboardInsights(),
          getIOCStats(),
        ]);
        setInsights(ins);
        setIOCStats(stats);
      } catch (e) {
        console.error("Failed to load geo data:", e);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  /* ── Derived data ────────────────────────────────────── */

  const countries = useMemo(() => {
    return (iocStats?.country_distribution || []).map((c, i) => ({
      ...c,
      color: REGION_COLORS[i % REGION_COLORS.length],
    }));
  }, [iocStats]);

  const continents = useMemo(() => {
    return (iocStats?.continent_distribution || []).map((c, i) => ({
      ...c,
      color: REGION_COLORS[i % REGION_COLORS.length],
    }));
  }, [iocStats]);

  const networks = useMemo(() => {
    return (iocStats?.asn_distribution || []).map((a, i) => ({
      ...a,
      color: REGION_COLORS[i % REGION_COLORS.length],
    }));
  }, [iocStats]);

  const threatGeo = useMemo(() => {
    return (insights?.threat_geography || []).sort((a, b) => b.count - a.count);
  }, [insights]);

  const industries = useMemo(() => {
    return (insights?.target_industries || []).sort((a, b) => b.count - a.count);
  }, [insights]);

  const intelGeo = useMemo(() => {
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

  const regionThreats = useMemo(() => {
    if (!selectedCountry || !dashboard?.top_risks) return [];
    return dashboard.top_risks.filter((item) => item.geo?.includes(selectedCountry));
  }, [selectedCountry, dashboard]);

  const totalCountries = countries.length;
  const totalIOCsWithGeo = countries.reduce((s, c) => s + c.count, 0);
  const totalContinents = continents.length;
  const totalThreatRegions = threatGeo.length;
  const enrichmentPct = iocStats?.enrichment_coverage
    ? Math.round((iocStats.enrichment_coverage.enriched / Math.max(iocStats.enrichment_coverage.total_ips, 1)) * 100)
    : 0;

  const countryDonut = useMemo(
    () => countries.slice(0, 10).map((c) => ({ name: `${c.code} ${c.name}`, value: c.count, color: c.color })),
    [countries]
  );

  const continentDonut = useMemo(
    () => continents.map((c) => ({ name: c.name || c.code, value: c.count, color: c.color })),
    [continents]
  );

  if ((dashboardLoading || loading) && !dashboard && !iocStats) return <Loading text="Loading geographic data..." />;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      {/* ── Header ─────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-tight flex items-center gap-2">
            <Globe className="h-5 w-5 text-primary" />
            Geographic Threat View
          </h1>
          <p className="text-[11px] text-muted-foreground mt-0.5">
            Threat distribution by country, continent, network & industry
          </p>
        </div>
        {iocStats?.enrichment_coverage && (
          <div className="hidden sm:flex items-center gap-2 text-[10px] text-muted-foreground">
            <Activity className="h-3 w-3" />
            {iocStats.enrichment_coverage.enriched}/{iocStats.enrichment_coverage.total_ips} IPs enriched ({enrichmentPct}%)
          </div>
        )}
      </div>

      {/* ── Stats Row ──────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
        <StatMini icon={<Globe className="h-3.5 w-3.5 text-blue-400" />} label="Countries" value={totalCountries} bgClass="bg-blue-500/[0.04] border-blue-500/10" iconBg="bg-blue-500/10" />
        <StatMini icon={<Layers className="h-3.5 w-3.5 text-purple-400" />} label="Continents" value={totalContinents} bgClass="bg-purple-500/[0.04] border-purple-500/10" iconBg="bg-purple-500/10" />
        <StatMini icon={<MapPin className="h-3.5 w-3.5 text-cyan-400" />} label="IOCs with Geo" value={totalIOCsWithGeo} bgClass="bg-cyan-500/[0.04] border-cyan-500/10" iconBg="bg-cyan-500/10" />
        <StatMini icon={<AlertTriangle className="h-3.5 w-3.5 text-red-400" />} label="Threat Regions" value={totalThreatRegions} bgClass="bg-red-500/[0.04] border-red-500/10" iconBg="bg-red-500/10" />
        <StatMini icon={<Building2 className="h-3.5 w-3.5 text-orange-400" />} label="Industries" value={industries.length} bgClass="bg-orange-500/[0.04] border-orange-500/10" iconBg="bg-orange-500/10" />
      </div>

      {/* ── Tab Navigation ─────────────────────────────── */}
      <div className="flex items-center gap-1 border-b border-border/40 pb-0">
        {([
          { key: "countries" as const, label: "Countries", icon: Globe, count: totalCountries },
          { key: "continents" as const, label: "Continents", icon: Layers, count: totalContinents },
          { key: "networks" as const, label: "Networks", icon: Server, count: networks.length },
          { key: "industries" as const, label: "Industries", icon: Building2, count: industries.length },
          { key: "intel" as const, label: "Intel Geo", icon: MapPin, count: intelGeo.length },
        ]).map((tab) => (
          <button
            key={tab.key}
            onClick={() => { setActiveTab(tab.key); setSelectedCountry(null); }}
            className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors border-b-2 -mb-[1px] ${
              activeTab === tab.key
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            <tab.icon className="h-3 w-3" />
            {tab.label}
            <Badge variant="secondary" className="text-[8px] px-1.5 py-0 h-4 ml-0.5">
              {tab.count}
            </Badge>
          </button>
        ))}
      </div>

      {/* ── Countries Tab ──────────────────────────────── */}
      {activeTab === "countries" && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Card>
              <CardHeader className="pb-2 pt-4 px-5">
                <CardTitle className="text-sm font-semibold">Top 10 Countries</CardTitle>
              </CardHeader>
              <CardContent className="px-5 pb-4">
                {countryDonut.length > 0 ? (
                  <DonutChart data={countryDonut} centerValue={totalCountries} centerLabel="Countries" height={220} innerRadius={55} outerRadius={80} />
                ) : <EmptyState />}
              </CardContent>
            </Card>

            <Card className="lg:col-span-2">
              <CardHeader className="pb-2 pt-4 px-5">
                <CardTitle className="text-sm font-semibold">IOC Distribution by Country</CardTitle>
              </CardHeader>
              <CardContent className="px-3 pb-3 max-h-[400px] overflow-y-auto">
                {countries.length > 0 ? (
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {countries.map((c) => (
                      <button
                        key={c.code}
                        onClick={() => setSelectedCountry(selectedCountry === c.name ? null : c.name)}
                        className={`flex items-center gap-2.5 px-3 py-2 rounded-lg border text-left transition-all ${
                          selectedCountry === c.name
                            ? "border-primary/40 bg-primary/5 ring-1 ring-primary/20"
                            : "border-border/30 hover:border-border/60 hover:bg-muted/20"
                        }`}
                      >
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img
                          src={`https://flagcdn.com/24x18/${c.code.toLowerCase()}.png`}
                          alt={c.code}
                          className="h-3.5 shrink-0 rounded-[1px]"
                          onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-medium truncate">{c.name}</div>
                          <div className="text-[9px] text-muted-foreground">{c.code}</div>
                        </div>
                        <div className="text-right">
                          <div className="text-sm font-bold tabular-nums" style={{ color: c.color }}>{c.count}</div>
                          <div className="text-[8px] text-muted-foreground">IOCs</div>
                        </div>
                      </button>
                    ))}
                  </div>
                ) : <EmptyState />}
              </CardContent>
            </Card>
          </div>

          {threatGeo.length > 0 && (
            <Card>
              <CardHeader className="pb-2 pt-4 px-5">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-400" />
                  <CardTitle className="text-sm font-semibold">Threat Geography (AI-Enriched)</CardTitle>
                  <Badge variant="outline" className="text-[8px] ml-auto">From intel analysis</Badge>
                </div>
              </CardHeader>
              <CardContent className="px-3 pb-3">
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
                  {threatGeo.map((g) => {
                    const riskColor = g.avg_risk >= 80 ? "#ef4444" : g.avg_risk >= 60 ? "#f97316" : g.avg_risk >= 40 ? "#eab308" : "#22c55e";
                    return (
                      <div key={g.name} className="rounded-lg border border-border/30 p-2.5 bg-muted/10 hover:bg-muted/20 transition-colors">
                        <div className="text-xs font-semibold truncate" title={g.name}>{g.name}</div>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-lg font-bold tabular-nums">{g.count}</span>
                          <span className="text-[9px] text-muted-foreground">mentions</span>
                        </div>
                        <div className="flex items-center gap-1 mt-1">
                          <span className="text-[9px] text-muted-foreground">Avg Risk:</span>
                          <span className="text-[10px] font-bold" style={{ color: riskColor }}>{Math.round(g.avg_risk)}</span>
                          <div className="flex-1 h-1 rounded-full bg-muted/40 overflow-hidden ml-1">
                            <div className="h-full rounded-full" style={{ width: `${Math.min(g.avg_risk, 100)}%`, backgroundColor: riskColor }} />
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* ── Continents Tab ─────────────────────────────── */}
      {activeTab === "continents" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <CardTitle className="text-sm font-semibold">Continental Distribution</CardTitle>
            </CardHeader>
            <CardContent className="px-5 pb-4">
              {continentDonut.length > 0 ? (
                <DonutChart data={continentDonut} centerValue={totalIOCsWithGeo} centerLabel="IOCs" height={220} innerRadius={55} outerRadius={80} />
              ) : <EmptyState />}
            </CardContent>
          </Card>

          <Card className="lg:col-span-2">
            <CardHeader className="pb-2 pt-4 px-5">
              <CardTitle className="text-sm font-semibold">IOCs by Continent</CardTitle>
            </CardHeader>
            <CardContent className="px-3 pb-3">
              {continents.length > 0 ? (
                <div className="space-y-2">
                  {continents.map((c) => {
                    const pct = totalIOCsWithGeo > 0 ? Math.round((c.count / totalIOCsWithGeo) * 100) : 0;
                    return (
                      <div key={c.code} className="rounded-lg border border-border/30 p-3 hover:bg-muted/10 transition-colors">
                        <div className="flex items-center gap-3">
                          <span className="text-xl">{CONTINENT_EMOJI[c.code] || "🌐"}</span>
                          <div className="flex-1">
                            <div className="flex items-center justify-between">
                              <span className="text-sm font-semibold">{c.name || c.code}</span>
                              <span className="text-sm font-bold" style={{ color: c.color }}>{c.count.toLocaleString()}</span>
                            </div>
                            <div className="h-2 rounded-full bg-muted/30 overflow-hidden mt-1.5">
                              <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: c.color }} />
                            </div>
                            <div className="text-[9px] text-muted-foreground mt-0.5">{pct}% of geo-enriched IOCs</div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : <EmptyState />}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Networks Tab ───────────────────────────────── */}
      {activeTab === "networks" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Card className="lg:col-span-2">
            <CardHeader className="pb-2 pt-4 px-5">
              <CardTitle className="text-sm font-semibold">Top Autonomous Systems</CardTitle>
            </CardHeader>
            <CardContent className="px-5 pb-4">
              {networks.length > 0 ? (
                <HorizontalBarChart data={networks.slice(0, 15).map((n) => ({ name: n.name || n.asn, value: n.count, color: n.color }))} />
              ) : <EmptyState />}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-sm font-semibold">All Networks ({networks.length})</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="px-3 pb-3 max-h-[400px] overflow-y-auto">
              {networks.length > 0 ? (
                <div className="space-y-1">
                  {networks.map((n) => (
                    <div key={n.asn} className="flex items-center justify-between px-3 py-2 rounded-md hover:bg-muted/20 transition-colors">
                      <div className="min-w-0 flex-1">
                        <div className="text-[11px] font-medium truncate">{n.name || "Unknown"}</div>
                        <div className="text-[9px] text-muted-foreground font-mono">{n.asn}</div>
                      </div>
                      <Badge variant="secondary" className="text-[10px] h-5 shrink-0 ml-2">{n.count} IOCs</Badge>
                    </div>
                  ))}
                </div>
              ) : <EmptyState />}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Industries Tab ─────────────────────────────── */}
      {activeTab === "industries" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Card className="lg:col-span-2">
            <CardHeader className="pb-2 pt-4 px-5">
              <CardTitle className="text-sm font-semibold">Targeted Industries (AI-Enriched)</CardTitle>
            </CardHeader>
            <CardContent className="px-5 pb-4">
              {industries.length > 0 ? (
                <HorizontalBarChart data={industries.slice(0, 15).map((ind, i) => ({ name: ind.name, value: ind.count, color: REGION_COLORS[i % REGION_COLORS.length] }))} />
              ) : <EmptyState />}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <div className="flex items-center gap-2">
                <Building2 className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-sm font-semibold">Industry Risk</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="px-3 pb-3 max-h-[400px] overflow-y-auto">
              {industries.length > 0 ? (
                <div className="space-y-2">
                  {industries.map((ind) => {
                    const rCol = ind.avg_risk >= 80 ? "#ef4444" : ind.avg_risk >= 60 ? "#f97316" : ind.avg_risk >= 40 ? "#eab308" : "#22c55e";
                    return (
                      <div key={ind.name} className="rounded-md border border-border/30 p-2.5 hover:bg-muted/10 transition-colors">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium truncate">{ind.name}</span>
                          <span className="text-[10px] font-bold" style={{ color: rCol }}>{Math.round(ind.avg_risk)}</span>
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-[9px] text-muted-foreground">{ind.count} mentions</span>
                          <div className="flex-1 h-1 rounded-full bg-muted/40 overflow-hidden">
                            <div className="h-full rounded-full" style={{ width: `${Math.min(ind.avg_risk, 100)}%`, backgroundColor: rCol }} />
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : <EmptyState />}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Intel Geo Tab ──────────────────────────────── */}
      {activeTab === "intel" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <CardTitle className="text-sm font-semibold">Region Distribution</CardTitle>
            </CardHeader>
            <CardContent className="px-5 pb-4">
              {intelGeo.length > 0 ? (
                <DonutChart data={intelGeo.slice(0, 10).map((g) => ({ name: g.name, value: g.count, color: g.color }))} centerValue={intelGeo.length} centerLabel="Regions" height={220} innerRadius={55} outerRadius={80} />
              ) : <EmptyState />}
            </CardContent>
          </Card>

          <Card className="lg:col-span-2">
            <CardHeader className="pb-2 pt-4 px-5">
              <CardTitle className="text-sm font-semibold">Threats by Region</CardTitle>
            </CardHeader>
            <CardContent className="px-5 pb-4">
              {intelGeo.length > 0 ? (
                <HorizontalBarChart data={intelGeo.slice(0, 15).map((g) => ({ name: g.name, value: g.count, color: g.color }))} />
              ) : <EmptyState />}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <div className="flex items-center gap-2">
                <MapPin className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-sm font-semibold">All Regions</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="px-3 pb-3 max-h-[360px] overflow-y-auto">
              {intelGeo.length > 0 ? (
                <div className="space-y-1">
                  {intelGeo.map((g) => (
                    <button
                      key={g.name}
                      onClick={() => setSelectedCountry(g.name === selectedCountry ? null : g.name)}
                      className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs transition-colors ${
                        selectedCountry === g.name ? "bg-primary/20 text-primary" : "hover:bg-muted/40"
                      }`}
                    >
                      <span className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ background: g.color }} />
                        {g.name}
                      </span>
                      <div className="flex items-center gap-2">
                        {Object.entries(g.sevMap).sort(([, a], [, b]) => b - a).slice(0, 3).map(([sev, count]) => (
                          <span key={sev} className="text-[8px] px-1 py-0 rounded" style={{ backgroundColor: (RISK_COLORS[sev] || "#666") + "20", color: RISK_COLORS[sev] || "#666" }}>
                            {count}
                          </span>
                        ))}
                        <Badge variant="secondary" className="text-[10px] h-5">{g.count}</Badge>
                      </div>
                    </button>
                  ))}
                </div>
              ) : <EmptyState />}
            </CardContent>
          </Card>

          <Card className="lg:col-span-2">
            <CardHeader className="pb-2 pt-4 px-5">
              <CardTitle className="text-sm font-semibold">
                {selectedCountry ? `Threats targeting ${selectedCountry}` : "Select a region"}
              </CardTitle>
            </CardHeader>
            <CardContent className="px-3 pb-3 max-h-[360px] overflow-y-auto">
              {selectedCountry ? (
                regionThreats.length > 0 ? (
                  <div className="space-y-2">
                    {regionThreats.map((item, i) => {
                      const sevCol = RISK_COLORS[item.severity] || "#666";
                      return (
                        <a key={i} href={`/intel/${item.id}`} className="flex items-center gap-3 px-3 py-2.5 rounded-md border border-border/40 bg-muted/20 hover:bg-muted/30 transition-colors">
                          <div className="w-1.5 h-8 rounded-full shrink-0" style={{ background: sevCol }} />
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-medium truncate">{item.title}</p>
                            <p className="text-[10px] text-muted-foreground">{item.source_name} · Risk {item.risk_score}</p>
                          </div>
                          <Badge variant="outline" className="text-[10px] shrink-0" style={{ borderColor: sevCol, color: sevCol }}>{item.severity}</Badge>
                          <ChevronRight className="h-3 w-3 text-muted-foreground/30" />
                        </a>
                      );
                    })}
                  </div>
                ) : (
                  <div className="h-[200px] flex items-center justify-center text-xs text-muted-foreground/60">No threats for this region</div>
                )
              ) : (
                <div className="h-[200px] flex items-center justify-center text-xs text-muted-foreground/60">
                  <Filter className="h-4 w-4 mr-2" />Click a region to see associated threats
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

/* ── Helper Components ─────────────────────────────────── */

function StatMini({ icon, label, value, bgClass, iconBg }: { icon: React.ReactNode; label: string; value: number; bgClass: string; iconBg: string }) {
  return (
    <Card className={bgClass}>
      <CardContent className="p-2.5 flex items-center gap-2.5">
        <div className={`p-1.5 rounded-lg ${iconBg}`}>{icon}</div>
        <div>
          <p className="text-base font-bold leading-none">{value.toLocaleString()}</p>
          <p className="text-[9px] text-muted-foreground mt-0.5">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function EmptyState() {
  return (
    <div className="h-[180px] flex items-center justify-center text-xs text-muted-foreground/60">
      No geographic data available
    </div>
  );
}
