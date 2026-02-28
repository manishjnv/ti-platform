"use client";

import React, { useState } from "react";
import { cn } from "@/lib/utils";
import type { AttackMatrixResponse, AttackMatrixCell } from "@/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, ExternalLink } from "lucide-react";

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
          {data.tactics.map((tactic) => (
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
                    onClick={() =>
                      setSelectedCell(
                        selectedCell?.id === tech.id ? null : tech
                      )
                    }
                    title={`${tech.id}: ${tech.name} — ${tech.count} intel items mapped (max risk: ${tech.max_risk})`}
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

      {/* Selected technique detail panel */}
      {selectedCell && (
        <Card className="border-primary/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Badge variant="outline" className="font-mono text-xs">
                {selectedCell.id}
              </Badge>
              {selectedCell.name}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm space-y-2">
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
            <a
              href={`https://attack.mitre.org/techniques/${selectedCell.id.replace(".", "/")}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline inline-flex items-center gap-1 text-xs"
            >
              <ExternalLink className="h-3 w-3" /> View on MITRE ATT&CK
            </a>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
