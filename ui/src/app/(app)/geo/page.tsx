"use client";

import React, { useEffect, useMemo, useState, useCallback } from "react";
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
  X,
  ExternalLink,
  Bug,
  Hash,
} from "lucide-react";
import { getDashboardInsights, getIOCStats, getIOCs, type IOCStatsResponse, type IOCListResponse } from "@/lib/api";
import type { DashboardInsights } from "@/types";
import Link from "next/link";

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

  // Drill-down state
  const [drillDown, setDrillDown] = useState<{
    type: "country_iocs" | "continent_countries" | "network_iocs" | "industry_intel" | "threat_geo_intel" | "stat_overview";
    label: string;
    filter: string;
    data?: any;
  } | null>(null);
  const [drillLoading, setDrillLoading] = useState(false);
  const [drillIOCs, setDrillIOCs] = useState<IOCListResponse | null>(null);

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

  // Drill-down handlers
  const handleDrillCountry = useCallback(async (name: string, code: string, count: number) => {
    if (drillDown?.type === "country_iocs" && drillDown.filter === code) {
      setDrillDown(null); setDrillIOCs(null); return;
    }
    setDrillDown({ type: "country_iocs", label: `${name} (${code})`, filter: code });
    setDrillLoading(true);
    try {
      const res = await getIOCs({ country_code: code, page_size: 20, sort_by: "risk_score", sort_dir: "desc" });
      setDrillIOCs(res);
    } catch { setDrillIOCs(null); }
    setDrillLoading(false);
  }, [drillDown]);

  const handleDrillContinent = useCallback((name: string, code: string) => {
    if (drillDown?.type === "continent_countries" && drillDown.filter === code) {
      setDrillDown(null); return;
    }
    const matching = countries.filter(c => {
      // Map country codes to continents (simplified)
      const continentMap: Record<string, string[]> = {
        EU: ["DE","FR","GB","NL","IT","ES","PL","SE","NO","FI","DK","BE","AT","CH","CZ","PT","IE","RO","BG","HR","HU","SK","SI","LT","LV","EE","LU","MT","CY","GR","UA","BY","RU","RS","BA","ME","MK","AL","MD","IS","XK"],
        NA: ["US","CA","MX","CU","JM","HT","DO","PR","TT","BZ","GT","HN","SV","NI","CR","PA","BS","BB","AG","KN","LC","VC","GD","DM"],
        SA: ["BR","AR","CO","CL","PE","VE","EC","BO","PY","UY","GY","SR","GF"],
        AS: ["CN","JP","IN","KR","SG","ID","TH","VN","MY","PH","TW","HK","BD","PK","LK","NP","MM","KH","LA","MN","KZ","UZ","KG","TJ","TM","AZ","GE","AM","AF","IQ","IR","SA","AE","IL","JO","LB","SY","OM","QA","BH","KW","YE"],
        AF: ["ZA","NG","KE","EG","MA","DZ","TN","GH","SN","CI","CM","ET","TZ","UG","SD","LY","AO","MZ","MG","ZW","MW","ZM","BW","NA","RW","BF","ML","NE","TD","SO","ER","DJ","GA","CG","CD","MU","SC","CV"],
        OC: ["AU","NZ","FJ","PG","NC","PF","GU","WS","TO","VU","SB","FM","KI","MH","PW","NR","TV","CK"],
      };
      return (continentMap[code] || []).includes(c.code);
    });
    setDrillDown({ type: "continent_countries", label: name, filter: code, data: matching });
  }, [drillDown, countries]);

  const handleDrillNetwork = useCallback(async (asn: string, name: string, count: number) => {
    if (drillDown?.type === "network_iocs" && drillDown.filter === asn) {
      setDrillDown(null); setDrillIOCs(null); return;
    }
    setDrillDown({ type: "network_iocs", label: `${name} (${asn})`, filter: asn });
    setDrillLoading(true);
    try {
      const res = await getIOCs({ asn, page_size: 20, sort_by: "risk_score", sort_dir: "desc" });
      setDrillIOCs(res);
    } catch { setDrillIOCs(null); }
    setDrillLoading(false);
  }, [drillDown]);

  const handleDrillIndustry = useCallback((name: string) => {
    if (drillDown?.type === "industry_intel" && drillDown.filter === name) {
      setDrillDown(null); return;
    }
    const matching = (dashboard?.top_risks || []).filter(item =>
      item.targeted_sectors?.some(s => s.toLowerCase().includes(name.toLowerCase()))
    );
    setDrillDown({ type: "industry_intel", label: name, filter: name, data: matching });
  }, [drillDown, dashboard]);

  const handleDrillThreatGeo = useCallback((name: string) => {
    if (drillDown?.type === "threat_geo_intel" && drillDown.filter === name) {
      setDrillDown(null); return;
    }
    const matching = (dashboard?.top_risks || []).filter(item => item.geo?.includes(name));
    setDrillDown({ type: "threat_geo_intel", label: name, filter: name, data: matching });
  }, [drillDown, dashboard]);

  const handleStatClick = useCallback((tab: typeof activeTab) => {
    setActiveTab(tab);
    setDrillDown(null);
    setDrillIOCs(null);
    setSelectedCountry(null);
  }, []);

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
        <StatMini icon={<Globe className="h-3.5 w-3.5 text-blue-400" />} label="Countries" value={totalCountries} bgClass="bg-blue-500/[0.04] border-blue-500/10" iconBg="bg-blue-500/10" onClick={() => handleStatClick("countries")} />
        <StatMini icon={<Layers className="h-3.5 w-3.5 text-purple-400" />} label="Continents" value={totalContinents} bgClass="bg-purple-500/[0.04] border-purple-500/10" iconBg="bg-purple-500/10" onClick={() => handleStatClick("continents")} />
        <StatMini icon={<MapPin className="h-3.5 w-3.5 text-cyan-400" />} label="IOCs with Geo" value={totalIOCsWithGeo} bgClass="bg-cyan-500/[0.04] border-cyan-500/10" iconBg="bg-cyan-500/10" onClick={() => handleStatClick("countries")} />
        <StatMini icon={<AlertTriangle className="h-3.5 w-3.5 text-red-400" />} label="Threat Regions" value={totalThreatRegions} bgClass="bg-red-500/[0.04] border-red-500/10" iconBg="bg-red-500/10" onClick={() => handleStatClick("intel")} />
        <StatMini icon={<Building2 className="h-3.5 w-3.5 text-orange-400" />} label="Industries" value={industries.length} bgClass="bg-orange-500/[0.04] border-orange-500/10" iconBg="bg-orange-500/10" onClick={() => handleStatClick("industries")} />
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
            onClick={() => { setActiveTab(tab.key); setSelectedCountry(null); setDrillDown(null); setDrillIOCs(null); }}
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
                          <button
                            onClick={(e) => { e.stopPropagation(); handleDrillCountry(c.name, c.code, c.count); }}
                            className="text-sm font-bold tabular-nums hover:underline cursor-pointer transition-colors"
                            style={{ color: c.color }}
                            title={`View ${c.count} IOCs from ${c.name}`}
                          >
                            {c.count}
                          </button>
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
                          <button
                            onClick={() => handleDrillThreatGeo(g.name)}
                            className="text-lg font-bold tabular-nums hover:underline cursor-pointer transition-colors"
                            title={`View threats targeting ${g.name}`}
                          >
                            {g.count}
                          </button>
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
          {drillDown && (drillDown.type === "country_iocs" || drillDown.type === "threat_geo_intel") && (
            <DrillDownPanel drillDown={drillDown} drillIOCs={drillIOCs} drillLoading={drillLoading} onClose={() => { setDrillDown(null); setDrillIOCs(null); }} />
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
                              <button
                                onClick={() => handleDrillContinent(c.name || c.code, c.code)}
                                className="text-sm font-bold hover:underline cursor-pointer transition-colors"
                                style={{ color: c.color }}
                                title={`View countries in ${c.name || c.code}`}
                              >
                                {c.count.toLocaleString()}
                              </button>
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
          {drillDown?.type === "continent_countries" && (
            <DrillDownPanel drillDown={drillDown} drillIOCs={drillIOCs} drillLoading={drillLoading} onClose={() => { setDrillDown(null); setDrillIOCs(null); }} />
          )}
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
                      <button
                        onClick={() => handleDrillNetwork(n.asn, n.name || "Unknown", n.count)}
                        className="text-[10px] h-5 shrink-0 ml-2 px-2 rounded-full bg-secondary text-secondary-foreground font-medium hover:bg-primary/20 hover:text-primary cursor-pointer transition-colors"
                        title={`View ${n.count} IOCs from ${n.name || n.asn}`}
                      >
                        {n.count} IOCs
                      </button>
                    </div>
                  ))}
                </div>
              ) : <EmptyState />}
            </CardContent>
          </Card>
          {drillDown?.type === "network_iocs" && (
            <DrillDownPanel drillDown={drillDown} drillIOCs={drillIOCs} drillLoading={drillLoading} onClose={() => { setDrillDown(null); setDrillIOCs(null); }} className="lg:col-span-3" />
          )}
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
                          <button
                            onClick={() => handleDrillIndustry(ind.name)}
                            className="text-[10px] font-bold hover:underline cursor-pointer transition-colors"
                            style={{ color: rCol }}
                            title={`View intel targeting ${ind.name}`}
                          >
                            {Math.round(ind.avg_risk)}
                          </button>
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          <button
                            onClick={() => handleDrillIndustry(ind.name)}
                            className="text-[9px] text-muted-foreground hover:text-primary hover:underline cursor-pointer transition-colors"
                            title={`View ${ind.count} intel items targeting ${ind.name}`}
                          >
                            {ind.count} mentions
                          </button>
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
          {drillDown?.type === "industry_intel" && (
            <DrillDownPanel drillDown={drillDown} drillIOCs={drillIOCs} drillLoading={drillLoading} onClose={() => { setDrillDown(null); setDrillIOCs(null); }} className="lg:col-span-3" />
          )}
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
                        <Badge variant="secondary" className="text-[10px] h-5 cursor-pointer hover:bg-primary/20 hover:text-primary transition-colors">{g.count}</Badge>
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

function StatMini({ icon, label, value, bgClass, iconBg, onClick }: { icon: React.ReactNode; label: string; value: number; bgClass: string; iconBg: string; onClick?: () => void }) {
  return (
    <Card className={`${bgClass} ${onClick ? "cursor-pointer hover:ring-1 hover:ring-primary/30 transition-all" : ""}`} onClick={onClick}>
      <CardContent className="p-2.5 flex items-center gap-2.5">
        <div className={`p-1.5 rounded-lg ${iconBg}`}>{icon}</div>
        <div>
          <p className={`text-base font-bold leading-none ${onClick ? "hover:text-primary" : ""}`}>{value.toLocaleString()}</p>
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

/* ── Drill-Down Panel ──────────────────────────────────── */

const RISK_COLOR_MAP: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
};

function DrillDownPanel({
  drillDown,
  drillIOCs,
  drillLoading,
  onClose,
  className,
}: {
  drillDown: { type: string; label: string; filter: string; data?: any };
  drillIOCs: IOCListResponse | null;
  drillLoading: boolean;
  onClose: () => void;
  className?: string;
}) {
  const isIOCDrill = drillDown.type === "country_iocs" || drillDown.type === "network_iocs";
  const isIntelDrill = drillDown.type === "industry_intel" || drillDown.type === "threat_geo_intel";
  const isContinentDrill = drillDown.type === "continent_countries";

  return (
    <Card className={`border-primary/20 bg-primary/[0.02] animate-in fade-in slide-in-from-top-2 duration-200 ${className || ""}`}>
      <CardHeader className="pb-2 pt-3 px-4">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            {isIOCDrill && <Bug className="h-4 w-4 text-primary" />}
            {isIntelDrill && <AlertTriangle className="h-4 w-4 text-red-400" />}
            {isContinentDrill && <Globe className="h-4 w-4 text-purple-400" />}
            <span>{drillDown.label}</span>
            <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-primary/30 text-primary">
              {isIOCDrill && `${drillIOCs?.total || 0} IOCs`}
              {isIntelDrill && `${drillDown.data?.length || 0} intel items`}
              {isContinentDrill && `${drillDown.data?.length || 0} countries`}
            </Badge>
          </CardTitle>
          <button onClick={onClose} className="p-1 rounded-md hover:bg-muted/50 text-muted-foreground hover:text-foreground transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>
      </CardHeader>
      <CardContent className="px-4 pb-3 max-h-[350px] overflow-y-auto">
        {drillLoading ? (
          <div className="flex items-center justify-center py-8 text-xs text-muted-foreground">
            <Activity className="h-4 w-4 animate-spin mr-2" />Loading...
          </div>
        ) : isIOCDrill && drillIOCs ? (
          <div className="space-y-1.5">
            {drillIOCs.items.length > 0 ? drillIOCs.items.map((ioc) => {
              const riskCol = ioc.risk_score >= 80 ? "#ef4444" : ioc.risk_score >= 60 ? "#f97316" : ioc.risk_score >= 40 ? "#eab308" : "#22c55e";
              return (
                <Link key={ioc.id} href={`/iocs?search=${encodeURIComponent(ioc.value)}`}
                  className="flex items-center gap-3 px-3 py-2 rounded-md border border-border/30 hover:bg-muted/20 transition-colors group"
                >
                  <div className="w-1.5 h-7 rounded-full shrink-0" style={{ background: riskCol }} />
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-mono font-medium truncate group-hover:text-primary transition-colors">{ioc.value}</p>
                    <p className="text-[9px] text-muted-foreground flex items-center gap-2">
                      <span>{ioc.ioc_type}</span>
                      <span>·</span>
                      <span>Risk: {ioc.risk_score}</span>
                      {ioc.country && <><span>·</span><span>{ioc.country}</span></>}
                      {ioc.as_name && <><span>·</span><span className="truncate max-w-[120px]">{ioc.as_name}</span></>}
                    </p>
                  </div>
                  <Badge variant="outline" className="text-[9px] shrink-0" style={{ borderColor: riskCol, color: riskCol }}>{ioc.risk_score}</Badge>
                  <ChevronRight className="h-3 w-3 text-muted-foreground/30 group-hover:text-primary transition-colors" />
                </Link>
              );
            }) : (
              <div className="text-xs text-muted-foreground/60 text-center py-6">No IOCs found</div>
            )}
          </div>
        ) : isIntelDrill && drillDown.data ? (
          <div className="space-y-1.5">
            {drillDown.data.length > 0 ? drillDown.data.map((item: any, i: number) => {
              const sevCol = RISK_COLOR_MAP[item.severity] || "#666";
              return (
                <Link key={i} href={`/intel/${item.id}`}
                  className="flex items-center gap-3 px-3 py-2 rounded-md border border-border/30 hover:bg-muted/20 transition-colors group"
                >
                  <div className="w-1.5 h-7 rounded-full shrink-0" style={{ background: sevCol }} />
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-medium truncate group-hover:text-primary transition-colors">{item.title}</p>
                    <p className="text-[9px] text-muted-foreground">
                      {item.source_name} · Risk {item.risk_score}
                      {item.geo?.length > 0 && ` · ${item.geo.slice(0, 3).join(", ")}`}
                    </p>
                  </div>
                  <Badge variant="outline" className="text-[9px] shrink-0" style={{ borderColor: sevCol, color: sevCol }}>{item.severity}</Badge>
                  <ChevronRight className="h-3 w-3 text-muted-foreground/30 group-hover:text-primary transition-colors" />
                </Link>
              );
            }) : (
              <div className="text-xs text-muted-foreground/60 text-center py-6">No intel items found</div>
            )}
          </div>
        ) : isContinentDrill && drillDown.data ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
            {drillDown.data.length > 0 ? drillDown.data.map((c: any) => (
              <div key={c.code} className="flex items-center gap-2 px-3 py-2 rounded-md border border-border/30 hover:bg-muted/20 transition-colors">
                <img
                  src={`https://flagcdn.com/24x18/${c.code.toLowerCase()}.png`}
                  alt={c.code}
                  className="h-3.5 shrink-0 rounded-[1px]"
                  onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }}
                />
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-medium truncate">{c.name}</div>
                  <div className="text-[9px] text-muted-foreground">{c.code}</div>
                </div>
                <span className="text-xs font-bold tabular-nums" style={{ color: c.color }}>{c.count}</span>
              </div>
            )) : (
              <div className="col-span-full text-xs text-muted-foreground/60 text-center py-6">No countries found</div>
            )}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
