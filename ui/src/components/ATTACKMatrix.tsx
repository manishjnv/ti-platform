"use client";

import React, { useState, useEffect, useCallback } from "react";
import { cn } from "@/lib/utils";
import type { AttackMatrixResponse, AttackMatrixCell, IntelItem } from "@/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, ExternalLink, X, Loader2, ChevronRight, AlertTriangle, Zap } from "lucide-react";
import * as api from "@/lib/api";
import Link from "next/link";

interface ATTACKMatrixProps {
  data: AttackMatrixResponse;
}

type HeatmapFilter = "all" | "none" | "low" | "medium" | "high" | "critical";

function riskLevel(count: number, maxRisk: number): HeatmapFilter {
  if (count === 0) return "none";
  if (maxRisk >= 80) return "critical";
  if (maxRisk >= 60) return "high";
  if (maxRisk >= 40) return "medium";
  return "low";
}

function cellColor(count: number, maxRisk: number): string {
  if (count === 0) return "bg-muted/20 hover:bg-muted/30";
  if (maxRisk >= 80) return "bg-red-500/30 hover:bg-red-500/40 border-red-500/30";
  if (maxRisk >= 60) return "bg-orange-500/25 hover:bg-orange-500/35 border-orange-500/30";
  if (maxRisk >= 40) return "bg-yellow-500/20 hover:bg-yellow-500/30 border-yellow-500/30";
  return "bg-blue-500/15 hover:bg-blue-500/25 border-blue-500/30";
}

function cellTextColor(count: number, maxRisk: number): string {
  if (count === 0) return "text-muted-foreground/50";
  if (maxRisk >= 80) return "text-red-400";
  if (maxRisk >= 60) return "text-orange-400";
  if (maxRisk >= 40) return "text-yellow-400";
  return "text-blue-400";
}

const RISK_BG = (score: number) =>
  score >= 80 ? "bg-red-500/15 text-red-400" :
  score >= 60 ? "bg-orange-500/15 text-orange-400" :
  score >= 40 ? "bg-yellow-500/15 text-yellow-400" :
  "bg-green-500/15 text-green-400";

export function ATTACKMatrix({ data }: ATTACKMatrixProps) {
  const [selectedCell, setSelectedCell] = useState<AttackMatrixCell | null>(null);
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [heatmapFilter, setHeatmapFilter] = useState<HeatmapFilter>("all");
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailTech, setDetailTech] = useState<AttackMatrixCell | null>(null);
  const [detailData, setDetailData] = useState<{
    technique: any;
    intel_items: IntelItem[];
    subtechniques: any[];
    intel_count: number;
  } | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const openTechniqueDetail = useCallback(async (tech: AttackMatrixCell) => {
    setDetailTech(tech);
    setDetailOpen(true);
    setDetailLoading(true);
    setDetailData(null);
    try {
      const data = await api.getAttackTechniqueDetail(tech.id);
      setDetailData(data);
    } catch (e) {
      console.error("Failed to fetch technique detail:", e);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const closeDetail = useCallback(() => {
    setDetailOpen(false);
    setDetailTech(null);
    setDetailData(null);
  }, []);

  // Filter tactics/techniques by heatmap level
  const filteredTactics = data.tactics.map((tactic) => ({
    ...tactic,
    techniques: tactic.techniques.filter((tech) => {
      if (heatmapFilter === "all") return true;
      return riskLevel(tech.count, tech.max_risk) === heatmapFilter;
    }),
  })).filter((tactic) => heatmapFilter === "all" || tactic.techniques.length > 0);

  return (
    <div className="space-y-4">
      {/* Summary stats */}
      <div className="flex items-center gap-6 text-sm">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-primary" />
          <span className="text-muted-foreground">
            <span className="font-semibold text-foreground">{data.total_techniques}</span> techniques loaded
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">
            <span className="font-semibold text-foreground">{data.total_mapped}</span> with intel mappings
          </span>
        </div>
      </div>

      {/* Legend — clickable heatmap filter */}
      <div className="flex items-center gap-2 text-xs">
        <span className="text-muted-foreground">Heatmap filter:</span>
        {[
          { key: "all" as HeatmapFilter, label: "All", bg: "bg-primary/20 border-primary/30", ring: "ring-primary" },
          { key: "none" as HeatmapFilter, label: "None", bg: "bg-muted/20 border-border/30", ring: "ring-muted-foreground" },
          { key: "low" as HeatmapFilter, label: "Low", bg: "bg-blue-500/15 border-blue-500/30", ring: "ring-blue-500" },
          { key: "medium" as HeatmapFilter, label: "Medium", bg: "bg-yellow-500/20 border-yellow-500/30", ring: "ring-yellow-500" },
          { key: "high" as HeatmapFilter, label: "High", bg: "bg-orange-500/25 border-orange-500/30", ring: "ring-orange-500" },
          { key: "critical" as HeatmapFilter, label: "Critical", bg: "bg-red-500/30 border-red-500/30", ring: "ring-red-500" },
        ].map(({ key, label, bg, ring }) => (
          <button
            key={key}
            onClick={() => setHeatmapFilter(heatmapFilter === key ? "all" : key)}
            className={cn(
              "flex items-center gap-1.5 px-2 py-1 rounded-md border transition-colors cursor-pointer",
              heatmapFilter === key
                ? `${bg} ${ring} ring-1 font-semibold`
                : "border-border/30 text-muted-foreground hover:bg-muted/20"
            )}
          >
            <div className={cn("w-3 h-3 rounded border", bg)} />
            {label}
          </button>
        ))}
        {heatmapFilter !== "all" && (
          <button
            onClick={() => setHeatmapFilter("all")}
            className="text-[10px] text-muted-foreground hover:text-primary ml-1"
          >
            Clear filter
          </button>
        )}
      </div>

      {/* Matrix Grid */}
      <div className="overflow-x-auto pb-4">
        <div className="flex gap-1 min-w-max">
          {filteredTactics.map((tactic) => (
            <div key={tactic.tactic} className="flex flex-col w-[140px] shrink-0">
              {/* Tactic header */}
              <div
                className={cn(
                  "px-2 py-2 text-center text-[10px] font-semibold uppercase tracking-wider rounded-t-md border border-border/30 cursor-pointer transition-colors",
                  selectedTactic === tactic.tactic
                    ? "bg-primary/20 text-primary border-primary/40"
                    : "bg-card text-muted-foreground hover:bg-muted/30"
                )}
                onClick={() =>
                  setSelectedTactic(
                    selectedTactic === tactic.tactic ? null : tactic.tactic
                  )
                }
              >
                {tactic.label}
                <div className="text-[9px] font-normal mt-0.5 opacity-70">
                  {tactic.techniques.length} techniques
                </div>
              </div>

              {/* Technique cells */}
              <div className="flex flex-col gap-0.5 mt-0.5">
                {tactic.techniques.map((tech) => (
                  <div
                    key={`${tactic.tactic}-${tech.id}`}
                    className={cn(
                      "px-1.5 py-1 text-[10px] leading-tight rounded border border-transparent cursor-pointer transition-all duration-150",
                      cellColor(tech.count, tech.max_risk),
                      selectedCell?.id === tech.id &&
                        "ring-1 ring-primary border-primary/50"
                    )}
                    onClick={() => openTechniqueDetail(tech)}
                    title={`${tech.id}: ${tech.name} — ${tech.count} intel items mapped (max risk: ${tech.max_risk}). Click for details.`}
                  >
                    <div className="font-mono text-[9px] opacity-60">{tech.id}</div>
                    <div className="truncate">{tech.name}</div>
                    {tech.count > 0 && (
                      <div className={cn("text-[9px] font-semibold mt-0.5", cellTextColor(tech.count, tech.max_risk))}>
                        {tech.count} hit{tech.count !== 1 ? "s" : ""}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ═══ Technique Detail Modal (slide-over) ═══ */}
      {detailOpen && (
        <div className="fixed inset-0 z-50 flex justify-end">
          {/* Backdrop */}
          <div className="absolute inset-0 bg-black/50" onClick={closeDetail} />
          {/* Panel */}
          <div className="relative w-full max-w-xl bg-background border-l border-border shadow-2xl overflow-y-auto animate-in slide-in-from-right-full duration-200">
            {/* Header */}
            <div className="sticky top-0 bg-background/95 backdrop-blur border-b border-border z-10 px-5 py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 min-w-0">
                  <Badge variant="outline" className="font-mono text-xs shrink-0">
                    {detailTech?.id}
                  </Badge>
                  <h2 className="text-sm font-semibold truncate">{detailTech?.name}</h2>
                </div>
                <button
                  onClick={closeDetail}
                  className="p-1.5 rounded-md hover:bg-muted transition-colors shrink-0"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              {detailTech && (
                <div className="flex items-center gap-3 mt-2">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] text-muted-foreground">Intel Hits:</span>
                    <Badge variant={detailTech.count > 0 ? "default" : "secondary"} className="text-[10px]">
                      {detailTech.count}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] text-muted-foreground">Max Risk:</span>
                    <Badge
                      variant={detailTech.max_risk >= 80 ? "destructive" : detailTech.max_risk >= 60 ? "default" : "secondary"}
                      className="text-[10px]"
                    >
                      {detailTech.max_risk}
                    </Badge>
                  </div>
                  <a
                    href={`https://attack.mitre.org/techniques/${detailTech.id.replace(".", "/")}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline inline-flex items-center gap-1 text-[10px] ml-auto"
                  >
                    <ExternalLink className="h-3 w-3" /> MITRE ATT&CK
                  </a>
                </div>
              )}
            </div>

            {/* Content */}
            <div className="px-5 py-4 space-y-5">
              {detailLoading ? (
                <div className="flex items-center justify-center py-16">
                  <Loader2 className="h-6 w-6 animate-spin text-primary" />
                  <span className="ml-2 text-sm text-muted-foreground">Loading technique data...</span>
                </div>
              ) : detailData ? (
                <>
                  {/* Technique description */}
                  {detailData.technique?.description && (
                    <div>
                      <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Description</h3>
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        {detailData.technique.description.slice(0, 500)}
                        {detailData.technique.description.length > 500 && "..."}
                      </p>
                    </div>
                  )}

                  {/* Platforms & Data Sources */}
                  <div className="grid grid-cols-2 gap-4">
                    {detailData.technique?.platforms?.length > 0 && (
                      <div>
                        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Platforms</h3>
                        <div className="flex flex-wrap gap-1">
                          {detailData.technique.platforms.map((p: string) => (
                            <Badge key={p} variant="outline" className="text-[10px]">{p}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {detailData.technique?.data_sources?.length > 0 && (
                      <div>
                        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Data Sources</h3>
                        <div className="flex flex-wrap gap-1">
                          {detailData.technique.data_sources.slice(0, 6).map((ds: string) => (
                            <Badge key={ds} variant="secondary" className="text-[10px]">{ds}</Badge>
                          ))}
                          {detailData.technique.data_sources.length > 6 && (
                            <span className="text-[10px] text-muted-foreground">+{detailData.technique.data_sources.length - 6}</span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Detection */}
                  {detailData.technique?.detection && (
                    <div>
                      <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Detection</h3>
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        {detailData.technique.detection.slice(0, 400)}
                        {detailData.technique.detection.length > 400 && "..."}
                      </p>
                    </div>
                  )}

                  {/* Sub-techniques */}
                  {detailData.subtechniques?.length > 0 && (
                    <div>
                      <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">
                        Sub-techniques ({detailData.subtechniques.length})
                      </h3>
                      <div className="space-y-1">
                        {detailData.subtechniques.map((sub: any) => (
                          <button
                            key={sub.id}
                            onClick={() => openTechniqueDetail({ id: sub.id, name: sub.name, count: sub.intel_count || 0, max_risk: 0 })}
                            className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded border border-border/30 hover:bg-muted/20 text-left transition-colors group"
                          >
                            <Badge variant="outline" className="font-mono text-[9px] shrink-0">{sub.id}</Badge>
                            <span className="text-xs truncate group-hover:text-primary transition-colors">{sub.name}</span>
                            {sub.intel_count > 0 && (
                              <Badge variant="default" className="text-[9px] ml-auto shrink-0">
                                {sub.intel_count} hit{sub.intel_count !== 1 ? "s" : ""}
                              </Badge>
                            )}
                            <ChevronRight className="h-3 w-3 text-muted-foreground/30 group-hover:text-primary shrink-0" />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Linked Intel Items */}
                  <div>
                    <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                      Linked Intel Items ({detailData.intel_count})
                    </h3>
                    {detailData.intel_items.length > 0 ? (
                      <div className="space-y-1.5">
                        {detailData.intel_items.map((item: IntelItem) => (
                          <Link
                            key={item.id}
                            href={`/intel/${item.id}`}
                            className="block p-2.5 rounded-lg border border-border/30 hover:bg-muted/20 hover:border-primary/30 transition-all group"
                          >
                            <div className="flex items-center gap-2 mb-1">
                              <span className={cn("inline-flex items-center justify-center h-6 w-8 rounded text-[10px] font-bold", RISK_BG(item.risk_score))}>
                                {item.risk_score}
                              </span>
                              <Badge variant={item.severity as any} className="text-[9px] px-1 py-0">
                                {item.severity?.toUpperCase()}
                              </Badge>
                              {item.is_kev && (
                                <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/15 text-red-400 font-semibold">KEV</span>
                              )}
                              {item.exploit_available && (
                                <span className="text-[9px] px-1 py-0.5 rounded bg-orange-500/15 text-orange-400 font-semibold">
                                  <Zap className="h-2.5 w-2.5 inline" /> Exploit
                                </span>
                              )}
                              <span className="text-[10px] text-muted-foreground ml-auto shrink-0">
                                {item.source_name}
                              </span>
                            </div>
                            <p className="text-xs font-medium line-clamp-2 group-hover:text-primary transition-colors">
                              {item.title}
                            </p>
                            <div className="flex items-center gap-2 mt-1">
                              <span className="text-[10px] text-muted-foreground capitalize">{item.feed_type?.replace(/_/g, " ")}</span>
                              {item.cve_ids?.length > 0 && (
                                <span className="text-[10px] font-mono text-primary">{item.cve_ids[0]}</span>
                              )}
                              {(item.cve_ids?.length ?? 0) > 1 && (
                                <span className="text-[10px] text-muted-foreground">+{item.cve_ids.length - 1}</span>
                              )}
                              {item.published_at && (
                                <span className="text-[10px] text-muted-foreground ml-auto">
                                  {new Date(item.published_at).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                                </span>
                              )}
                            </div>
                          </Link>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-8 text-muted-foreground">
                        <Shield className="h-8 w-8 mx-auto mb-2 opacity-20" />
                        <p className="text-xs">No intel items linked to this technique yet.</p>
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <div className="text-center py-16 text-muted-foreground">
                  <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-30" />
                  <p className="text-xs">Failed to load technique details.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
