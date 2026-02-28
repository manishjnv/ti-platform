"use client";

import React, { useState, useMemo } from "react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import type { AttackMatrixResponse, AttackMatrixCell } from "@/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, ExternalLink, Eye, Filter, X } from "lucide-react";

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

export function ATTACKMatrix({ data }: ATTACKMatrixProps) {
  const [selectedCell, setSelectedCell] = useState<AttackMatrixCell | null>(null);
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [filterWithHits, setFilterWithHits] = useState(false);

  // Filtered tactics based on selected tactic and hits filter
  const filteredTactics = useMemo(() => {
    let tactics = data.tactics;
    if (selectedTactic) {
      tactics = tactics.filter((t) => t.tactic === selectedTactic);
    }
    if (filterWithHits) {
      tactics = tactics.map((t) => ({
        ...t,
        techniques: t.techniques.filter((tech) => tech.count > 0),
      })).filter((t) => t.techniques.length > 0);
    }
    return tactics;
  }, [data.tactics, selectedTactic, filterWithHits]);

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 text-xs">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-muted-foreground">Filter:</span>
        </div>
        <button
          onClick={() => { setSelectedTactic(null); setFilterWithHits(false); }}
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
            onClick={() => setSelectedTactic(selectedTactic === t.tactic ? null : t.tactic)}
            className={cn(
              "text-[10px] px-2 py-1 rounded-full border transition-colors",
              selectedTactic === t.tactic
                ? "bg-primary text-primary-foreground border-primary"
                : "border-border/40 text-muted-foreground hover:bg-muted/30"
            )}
          >
            {t.label}
            {t.techniques.filter((tc) => tc.count > 0).length > 0 && (
              <span className="ml-1 opacity-70">({t.techniques.filter((tc) => tc.count > 0).length})</span>
            )}
          </button>
        ))}
        {(selectedTactic || filterWithHits) && (
          <button
            onClick={() => { setSelectedTactic(null); setFilterWithHits(false); }}
            className="text-[10px] px-2 py-1 rounded-full border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-colors flex items-center gap-1"
          >
            <X className="h-2.5 w-2.5" /> Clear
          </button>
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 text-xs">
        <span className="text-muted-foreground">Heatmap:</span>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-muted/20 border border-border/30" />
          <span className="text-muted-foreground">None</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-blue-500/15 border border-blue-500/30" />
          <span className="text-muted-foreground">Low</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-yellow-500/20 border border-yellow-500/30" />
          <span className="text-muted-foreground">Medium</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-orange-500/25 border border-orange-500/30" />
          <span className="text-muted-foreground">High</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-red-500/30 border border-red-500/30" />
          <span className="text-muted-foreground">Critical</span>
        </div>
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
                  <Link
                    key={`${tactic.tactic}-${tech.id}`}
                    href={`/techniques/${tech.id}`}
                    className={cn(
                      "block px-1.5 py-1 text-[10px] leading-tight rounded border border-transparent cursor-pointer transition-all duration-150",
                      cellColor(tech.count, tech.max_risk),
                      selectedCell?.id === tech.id &&
                        "ring-1 ring-primary border-primary/50"
                    )}
                    onClick={(e) => {
                      // If just clicking (not navigating), show detail panel; hold Ctrl/Cmd to navigate
                      if (!e.ctrlKey && !e.metaKey) {
                        e.preventDefault();
                        setSelectedCell(
                          selectedCell?.id === tech.id ? null : tech
                        );
                      }
                    }}
                    title={`${tech.id}: ${tech.name} — ${tech.count} intel items mapped (max risk: ${tech.max_risk}). Click for details, Ctrl+Click to open.`}
                  >
                    <div className="font-mono text-[9px] opacity-60">{tech.id}</div>
                    <div className="truncate">{tech.name}</div>
                    {tech.count > 0 && (
                      <div className={cn("text-[9px] font-semibold mt-0.5", cellTextColor(tech.count, tech.max_risk))}>
                        {tech.count} hit{tech.count !== 1 ? "s" : ""}
                      </div>
                    )}
                  </Link>
                ))}
              </div>
            </div>
          ))}
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
            <div className="flex items-center gap-4">
              <span className="text-muted-foreground">Intel Mappings:</span>
              <Badge variant={selectedCell.count > 0 ? "default" : "secondary"}>
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
