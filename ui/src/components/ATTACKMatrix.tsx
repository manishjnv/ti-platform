"use client";

import React, { useState, useMemo, useCallback } from "react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import type { AttackMatrixResponse, AttackMatrixCell } from "@/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, ExternalLink, Eye, Filter, X, Download } from "lucide-react";

interface ATTACKMatrixProps {
  data: AttackMatrixResponse;
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

/* ─── Severity micro-bar (rich tooltip content) ─────── */
function SeverityMicroBar({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return null;
  const segments = [
    { key: "critical", color: "bg-red-500", label: "Critical" },
    { key: "high", color: "bg-orange-500", label: "High" },
    { key: "medium", color: "bg-yellow-500", label: "Medium" },
    { key: "low", color: "bg-blue-500", label: "Low" },
  ];
  return (
    <div className="space-y-1.5 min-w-[140px]">
      <div className="flex h-1.5 rounded-full overflow-hidden bg-muted/30">
        {segments.map(
          (s) =>
            (counts[s.key] || 0) > 0 && (
              <div
                key={s.key}
                className={cn("h-full", s.color)}
                style={{ width: `${((counts[s.key] || 0) / total) * 100}%` }}
              />
            )
        )}
      </div>
      <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
        {segments.map(
          (s) =>
            (counts[s.key] || 0) > 0 && (
              <div key={s.key} className="flex items-center gap-1.5 text-[9px]">
                <span className={cn("w-1.5 h-1.5 rounded-full", s.color)} />
                <span className="text-muted-foreground">{s.label}</span>
                <span className="font-semibold ml-auto">{counts[s.key]}</span>
              </div>
            )
        )}
      </div>
    </div>
  );
}

/* ─── ATT&CK Navigator JSON export ────────────────────── */
function exportNavigatorLayer(data: AttackMatrixResponse) {
  const techniques = data.tactics.flatMap((tactic) =>
    tactic.techniques
      .filter((t) => t.count > 0)
      .map((t) => ({
        techniqueID: t.id,
        tactic: tactic.tactic.replace(/-/g, "_"),  // Navigator uses underscores
        score: Math.min(t.count, 100),
        color: t.max_risk >= 80 ? "#ff6666" : t.max_risk >= 60 ? "#ff9933" : t.max_risk >= 40 ? "#ffcc00" : "#6699ff",
        comment: `${t.count} intel hit${t.count !== 1 ? "s" : ""}, max risk: ${t.max_risk}`,
        enabled: true,
        metadata: [],
        links: [],
        showSubtechniques: false,
      }))
  );

  const layer = {
    name: "IntelWatch Coverage",
    versions: { attack: "15", navigator: "5.1", layer: "4.5" },
    domain: "enterprise-attack",
    description: `IntelWatch threat intelligence coverage layer — ${data.total_mapped}/${data.total_techniques} techniques mapped. Exported ${new Date().toISOString().slice(0, 10)}.`,
    filters: { platforms: ["Windows", "Linux", "macOS", "Network", "Cloud"] },
    sorting: 3,
    layout: { layout: "side", aggregateFunction: "average", showID: true, showName: true, showAggregateScores: false, countUnscored: false, expandedSubtechniques: "none" },
    hideDisabled: false,
    techniques,
    gradient: { colors: ["#6699ff", "#ffcc00", "#ff9933", "#ff6666"], minValue: 0, maxValue: 100 },
    legendItems: [
      { label: "Low Risk", color: "#6699ff" },
      { label: "Medium Risk", color: "#ffcc00" },
      { label: "High Risk", color: "#ff9933" },
      { label: "Critical Risk", color: "#ff6666" },
    ],
    metadata: [],
    links: [],
    showTacticRowBackground: true,
    tacticRowBackground: "#205b8f",
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  };

  const json = JSON.stringify(layer, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `intelwatch-attack-layer-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function ATTACKMatrix({ data }: ATTACKMatrixProps) {
  const [selectedCell, setSelectedCell] = useState<AttackMatrixCell | null>(null);
  const [hoveredCell, setHoveredCell] = useState<AttackMatrixCell | null>(null);
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [filterWithHits, setFilterWithHits] = useState(false);

  // Filtered tactics based on selected tactic and hits filter
  const filteredTactics = useMemo(() => {
    let tactics = data.tactics;
    if (selectedTactic) {
      tactics = tactics.filter((t) => t.tactic === selectedTactic);
    }
    if (filterWithHits) {
      tactics = tactics
        .map((t) => ({
          ...t,
          techniques: t.techniques.filter((tech) => tech.count > 0),
        }))
        .filter((t) => t.techniques.length > 0);
    }
    return tactics;
  }, [data.tactics, selectedTactic, filterWithHits]);

  const handleExport = useCallback(() => exportNavigatorLayer(data), [data]);

  return (
    <div className="space-y-4">
      {/* Filter bar + Export */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 text-xs">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-muted-foreground">Filter:</span>
        </div>
        <button
          onClick={() => {
            setSelectedTactic(null);
            setFilterWithHits(false);
          }}
          className={cn(
            "text-[10px] px-2 py-1 rounded-full border transition-colors",
            !selectedTactic && !filterWithHits
              ? "bg-primary text-primary-foreground border-primary"
              : "border-border/40 text-muted-foreground hover:bg-muted/30"
          )}
        >
          All
        </button>
        <button
          onClick={() => setFilterWithHits(!filterWithHits)}
          className={cn(
            "text-[10px] px-2 py-1 rounded-full border transition-colors",
            filterWithHits
              ? "bg-primary text-primary-foreground border-primary"
              : "border-border/40 text-muted-foreground hover:bg-muted/30"
          )}
        >
          With Intel Hits Only
        </button>
        <div className="h-4 w-px bg-border/40" />
        {data.tactics.map((t) => (
          <button
            key={t.tactic}
            onClick={() =>
              setSelectedTactic(selectedTactic === t.tactic ? null : t.tactic)
            }
            className={cn(
              "text-[10px] px-2 py-1 rounded-full border transition-colors",
              selectedTactic === t.tactic
                ? "bg-primary text-primary-foreground border-primary"
                : "border-border/40 text-muted-foreground hover:bg-muted/30"
            )}
          >
            {t.label}
            {t.mapped > 0 && (
              <span className="ml-1 opacity-70">({t.mapped})</span>
            )}
          </button>
        ))}
        {(selectedTactic || filterWithHits) && (
          <button
            onClick={() => {
              setSelectedTactic(null);
              setFilterWithHits(false);
            }}
            className="text-[10px] px-2 py-1 rounded-full border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-colors flex items-center gap-1"
          >
            <X className="h-2.5 w-2.5" /> Clear
          </button>
        )}

        {/* Navigator Export */}
        <div className="ml-auto">
          <button
            onClick={handleExport}
            className="text-[10px] px-2.5 py-1 rounded-full border border-primary/30 text-primary hover:bg-primary/10 transition-colors flex items-center gap-1.5"
            title="Export as MITRE ATT&CK Navigator JSON layer"
          >
            <Download className="h-3 w-3" /> Navigator Export
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 text-xs">
        <span className="text-muted-foreground">Heatmap:</span>
        {[
          { bg: "bg-muted/20", bd: "border-border/30", label: "None" },
          { bg: "bg-blue-500/15", bd: "border-blue-500/30", label: "Low" },
          { bg: "bg-yellow-500/20", bd: "border-yellow-500/30", label: "Medium" },
          { bg: "bg-orange-500/25", bd: "border-orange-500/30", label: "High" },
          { bg: "bg-red-500/30", bd: "border-red-500/30", label: "Critical" },
        ].map((l) => (
          <div key={l.label} className="flex items-center gap-1">
            <div className={cn("w-3 h-3 rounded border", l.bg, l.bd)} />
            <span className="text-muted-foreground">{l.label}</span>
          </div>
        ))}
      </div>

      {/* Matrix Grid */}
      <div className="overflow-x-auto pb-4">
        <div className="flex gap-1 min-w-max">
          {filteredTactics.map((tactic) => {
            const covPct =
              tactic.total > 0
                ? Math.round((tactic.mapped / tactic.total) * 100)
                : 0;
            return (
              <div
                key={tactic.tactic}
                className="flex flex-col w-[140px] shrink-0"
              >
                {/* Tactic header with coverage bar */}
                <div
                  className={cn(
                    "px-2 py-2 text-center rounded-t-md border border-border/30 cursor-pointer transition-colors",
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
                  <div className="text-[10px] font-semibold uppercase tracking-wider">
                    {tactic.label}
                  </div>
                  <div className="text-[9px] font-normal mt-0.5 opacity-70">
                    {tactic.mapped}/{tactic.total} mapped
                  </div>
                  {/* Per-tactic coverage bar */}
                  <div className="mt-1.5 h-1 rounded-full bg-muted/30 overflow-hidden">
                    <div
                      className={cn(
                        "h-full rounded-full transition-all duration-500",
                        covPct >= 50
                          ? "bg-emerald-500"
                          : covPct >= 25
                          ? "bg-amber-500"
                          : covPct > 0
                          ? "bg-orange-500"
                          : "bg-transparent"
                      )}
                      style={{ width: `${covPct}%` }}
                    />
                  </div>
                  <div className="text-[8px] mt-0.5 opacity-50">{covPct}%</div>
                </div>

                {/* Technique cells */}
                <div className="flex flex-col gap-0.5 mt-0.5">
                  {tactic.techniques.map((tech) => (
                    <div
                      key={`${tactic.tactic}-${tech.id}`}
                      className="relative group"
                      onMouseEnter={() => setHoveredCell(tech)}
                      onMouseLeave={() => setHoveredCell(null)}
                    >
                      <Link
                        href={`/techniques/${tech.id}`}
                        className={cn(
                          "block px-1.5 py-1 text-[10px] leading-tight rounded border border-transparent cursor-pointer transition-all duration-150",
                          cellColor(tech.count, tech.max_risk),
                          selectedCell?.id === tech.id &&
                            "ring-1 ring-primary border-primary/50"
                        )}
                        onClick={(e) => {
                          e.preventDefault();
                          setSelectedCell(
                            selectedCell?.id === tech.id ? null : tech
                          );
                        }}
                        onDoubleClick={() => {
                          window.location.href = `/techniques/${tech.id}`;
                        }}
                      >
                        <div className="font-mono text-[9px] opacity-60">
                          {tech.id}
                        </div>
                        <div className="truncate">{tech.name}</div>
                        {tech.count > 0 && (
                          <div
                            className={cn(
                              "text-[9px] font-semibold mt-0.5",
                              cellTextColor(tech.count, tech.max_risk)
                            )}
                          >
                            {tech.count} hit{tech.count !== 1 ? "s" : ""}
                          </div>
                        )}
                      </Link>

                      {/* Rich hover tooltip */}
                      {hoveredCell?.id === tech.id && tech.count > 0 && (
                        <div className="absolute z-50 left-full ml-2 top-0 pointer-events-none">
                          <div className="bg-popover border border-border/60 rounded-lg shadow-xl px-3 py-2 space-y-1.5 min-w-[160px]">
                            <div className="text-[10px] font-semibold truncate max-w-[180px]">
                              {tech.id}: {tech.name}
                            </div>
                            <div className="flex items-center gap-2 text-[9px] text-muted-foreground">
                              <span>
                                {tech.count} mapping
                                {tech.count !== 1 ? "s" : ""}
                              </span>
                              <span>•</span>
                              <span>Max risk: {tech.max_risk}</span>
                            </div>
                            {tech.severity_counts &&
                              Object.keys(tech.severity_counts).length > 0 && (
                                <SeverityMicroBar
                                  counts={tech.severity_counts}
                                />
                              )}
                            <div className="text-[8px] text-muted-foreground/60 pt-0.5">
                              Click to select • Double-click to view
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected technique detail panel */}
      {selectedCell && (
        <Card className="border-primary/30">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm flex items-center gap-2">
                <Badge variant="outline" className="font-mono text-xs">
                  {selectedCell.id}
                </Badge>
                {selectedCell.name}
              </CardTitle>
              <button
                onClick={() => setSelectedCell(null)}
                className="p-1 rounded hover:bg-muted/40 text-muted-foreground"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </CardHeader>
          <CardContent className="text-sm space-y-3">
            <div className="flex items-center gap-4 flex-wrap">
              <span className="text-muted-foreground">Intel Mappings:</span>
              <Badge
                variant={
                  selectedCell.count > 0 ? "default" : "secondary"
                }
              >
                {selectedCell.count}
              </Badge>
              <span className="text-muted-foreground">Max Risk:</span>
              <Badge
                variant={
                  selectedCell.max_risk >= 80
                    ? "destructive"
                    : selectedCell.max_risk >= 60
                    ? "default"
                    : "secondary"
                }
              >
                {selectedCell.max_risk}
              </Badge>
              {/* Severity breakdown inline */}
              {selectedCell.severity_counts &&
                Object.keys(selectedCell.severity_counts).length > 0 && (
                  <div className="flex items-center gap-2">
                    {(
                      [
                        ["critical", "bg-red-500", "text-red-500"],
                        ["high", "bg-orange-500", "text-orange-500"],
                        ["medium", "bg-yellow-500", "text-yellow-500"],
                        ["low", "bg-blue-500", "text-blue-500"],
                      ] as const
                    ).map(
                      ([sev, dot, txt]) =>
                        (selectedCell.severity_counts[sev] || 0) > 0 && (
                          <span
                            key={sev}
                            className="flex items-center gap-1 text-xs"
                          >
                            <span
                              className={cn(
                                "w-1.5 h-1.5 rounded-full",
                                dot
                              )}
                            />
                            <span className={cn("font-semibold", txt)}>
                              {selectedCell.severity_counts[sev]}
                            </span>
                          </span>
                        )
                    )}
                  </div>
                )}
            </div>
            <div className="flex items-center gap-4">
              <Link
                href={`/techniques/${selectedCell.id}`}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-primary text-primary-foreground text-xs font-medium hover:bg-primary/90 transition-colors"
              >
                <Eye className="h-3 w-3" /> View Full Details
              </Link>
              <a
                href={`https://attack.mitre.org/techniques/${selectedCell.id.replace(".", "/")}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center gap-1 text-xs"
              >
                <ExternalLink className="h-3 w-3" /> MITRE ATT&CK
              </a>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
