"use client";

import React from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Sparkles,
  Crosshair,
  Package,
  Skull,
  Wrench,
  Activity,
  Lightbulb,
} from "lucide-react";

/* ── Types ─────────────────────────────────────────────── */

export interface TimelineEntry {
  date: string;
  event: string;
}

export interface StructuredIntelData {
  /** Executive summary paragraph */
  summary?: string | null;
  /** Threat actor names / groups */
  threatActors?: string[];
  /** Affected product names (vendor:product or plain) */
  affectedProducts?: string[];
  /** Free-text description of known breaches or campaigns */
  knownBreaches?: string | null;
  /** Remediation / fix guidance */
  fixRemediation?: string | null;
  /** Chronological timeline entries */
  timeline?: TimelineEntry[];
  /** Key findings bullet points */
  keyFindings?: string[];
}

/* ── Compact variant props ─────────────────────────────── */

interface Props {
  data: StructuredIntelData;
  /** "full" = all sections, grid layout (detail pages).
   *  "compact" = smaller cards, no summary banner (inline / modals). */
  variant?: "full" | "compact";
  className?: string;
}

/* ── Component ─────────────────────────────────────────── */

export function StructuredIntelCards({ data, variant = "full", className = "" }: Props) {
  const {
    summary,
    threatActors = [],
    affectedProducts = [],
    knownBreaches,
    fixRemediation,
    timeline = [],
    keyFindings = [],
  } = data;

  const hasContent =
    summary ||
    threatActors.length > 0 ||
    affectedProducts.length > 0 ||
    knownBreaches ||
    fixRemediation ||
    timeline.length > 0 ||
    keyFindings.length > 0;

  if (!hasContent) return null;

  const isCompact = variant === "compact";

  // Text sizes
  const headerSize = isCompact ? "text-[9px]" : "text-[10px]";
  const bodySize = isCompact ? "text-[10px]" : "text-[11px]";
  const badgeSize = isCompact ? "text-[9px]" : "text-[10px]";
  const iconSize = isCompact ? "h-3 w-3" : "h-3.5 w-3.5";
  const padding = isCompact ? "py-2 px-2.5" : "py-2.5 px-3";

  return (
    <div className={`space-y-2 ${className}`}>
      {/* Summary Banner */}
      {summary && (
        <Card className="border-purple-500/30 bg-purple-500/5">
          <CardContent className={isCompact ? "py-2 px-3" : "py-3 px-4"}>
            <div className="flex items-start gap-2">
              <Sparkles className={`${isCompact ? "h-3.5 w-3.5" : "h-4 w-4"} text-purple-400 mt-0.5 shrink-0`} />
              <div>
                <p className={`${headerSize} font-semibold text-purple-300 mb-1`}>
                  {isCompact ? "Summary" : "AI Intelligence Summary"}
                </p>
                <p className={`${isCompact ? "text-[10px]" : "text-xs"} text-muted-foreground leading-relaxed`}>
                  {summary}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Grid: TA, Products, Breaches, Fix */}
      <div className={`grid ${isCompact ? "grid-cols-1" : "grid-cols-1 md:grid-cols-2"} gap-2`}>
        {/* Threat Actors */}
        {threatActors.length > 0 && (
          <Card className="border-orange-500/30 bg-orange-500/5">
            <CardContent className={padding}>
              <div className="flex items-center gap-1.5 mb-1.5">
                <Crosshair className={`${iconSize} text-orange-400`} />
                <span className={`${headerSize} font-semibold text-orange-300 uppercase tracking-wider`}>
                  Threat Actors
                </span>
              </div>
              <div className="flex flex-wrap gap-1">
                {threatActors.map((ta, i) => (
                  <Badge key={i} className={`bg-orange-500/20 text-orange-300 border-orange-500/30 ${badgeSize}`}>
                    {ta}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Affected Products */}
        {affectedProducts.length > 0 && (
          <Card className="border-cyan-500/30 bg-cyan-500/5">
            <CardContent className={padding}>
              <div className="flex items-center gap-1.5 mb-1.5">
                <Package className={`${iconSize} text-cyan-400`} />
                <span className={`${headerSize} font-semibold text-cyan-300 uppercase tracking-wider`}>
                  Affected Products
                </span>
              </div>
              <div className="flex flex-wrap gap-1">
                {affectedProducts.map((p, i) => (
                  <Badge key={i} className={`bg-cyan-500/20 text-cyan-200 border-cyan-500/30 ${badgeSize}`}>
                    {p}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Known Breaches */}
        {knownBreaches && (
          <Card className="border-red-500/30 bg-red-500/5">
            <CardContent className={padding}>
              <div className="flex items-center gap-1.5 mb-1.5">
                <Skull className={`${iconSize} text-red-400`} />
                <span className={`${headerSize} font-semibold text-red-300 uppercase tracking-wider`}>
                  Known Breaches
                </span>
              </div>
              <p className={`${bodySize} text-red-200/80 leading-relaxed`}>{knownBreaches}</p>
            </CardContent>
          </Card>
        )}

        {/* Fix / Remediation */}
        {fixRemediation && (
          <Card className="border-emerald-500/30 bg-emerald-500/5">
            <CardContent className={padding}>
              <div className="flex items-center gap-1.5 mb-1.5">
                <Wrench className={`${iconSize} text-emerald-400`} />
                <span className={`${headerSize} font-semibold text-emerald-300 uppercase tracking-wider`}>
                  Fix / Remediation
                </span>
              </div>
              <p className={`${bodySize} text-emerald-200/80 leading-relaxed`}>{fixRemediation}</p>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Timeline */}
      {timeline.length > 0 && (
        <Card className="border-blue-500/30 bg-blue-500/5">
          <CardContent className={padding}>
            <div className="flex items-center gap-1.5 mb-2">
              <Activity className={`${iconSize} text-blue-400`} />
              <span className={`${headerSize} font-semibold text-blue-300 uppercase tracking-wider`}>
                Event Timeline
              </span>
            </div>
            <div className={`relative ${isCompact ? "pl-3" : "pl-4"} space-y-${isCompact ? "1.5" : "2"} border-l border-blue-500/30`}>
              {timeline.map((ev, i) => (
                <div key={i} className="relative">
                  <div
                    className={`absolute ${isCompact
                      ? "-left-[calc(0.75rem+4px)] top-1 w-1.5 h-1.5"
                      : "-left-[calc(1rem+4.5px)] top-1 w-2 h-2"
                    } rounded-full bg-blue-400 ${isCompact ? "" : "border border-blue-300"}`}
                  />
                  <p className={`${isCompact ? "text-[9px]" : "text-[10px]"} font-mono text-blue-300`}>
                    {ev.date}
                  </p>
                  <p className={`${bodySize} text-muted-foreground leading-snug`}>{ev.event}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Key Findings */}
      {keyFindings.length > 0 && (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className={padding}>
            <div className="flex items-center gap-1.5 mb-1.5">
              <Lightbulb className={`${iconSize} text-amber-400`} />
              <span className={`${headerSize} font-semibold text-amber-300 uppercase tracking-wider`}>
                Key Findings
              </span>
            </div>
            <ul className={`space-y-${isCompact ? "0.5" : "1"}`}>
              {keyFindings.map((f, i) => (
                <li key={i} className={`${bodySize} text-muted-foreground leading-snug flex items-start gap-1.5`}>
                  <span className="text-amber-400 mt-0.5 shrink-0">•</span>
                  {f}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
