"use client";

import React, { useEffect, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { cn } from "@/lib/utils";
import * as api from "@/lib/api";
import type { ThreatBriefingSummary } from "@/types";
import {
  ScrollText,
  Loader2,
  Sparkles,
  Calendar,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Shield,
  Swords,
  Skull,
} from "lucide-react";

export default function BriefingsPage() {
  const [briefings, setBriefings] = useState<ThreatBriefingSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getBriefings(20);
      setBriefings(data);
    } catch (e) {
      console.error("Failed to load briefings", e);
    }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const resp = await api.generateBriefing(7) as Record<string, any>;
      const briefing = resp.briefing || resp;
      const b: ThreatBriefingSummary = {
        id: resp.id || "new",
        period: briefing.period || "weekly",
        period_start: briefing.period_start,
        period_end: briefing.period_end,
        title: briefing.title || "Weekly Threat Brief",
        executive_summary: briefing.executive_summary || "",
        key_campaigns: briefing.key_campaigns,
        key_vulnerabilities: briefing.key_vulnerabilities,
        key_actors: briefing.key_actors,
        recommendations: briefing.recommendations || [],
        stats: briefing.stats || resp.raw_data?.stats,
      };
      setBriefings((prev) => [b, ...prev]);
      setExpandedId(b.id);
    } catch (e) {
      console.error("Failed to generate briefing", e);
    }
    setGenerating(false);
  };

  if (loading && briefings.length === 0) return <Loading text="Loading threat briefings..." />;

  return (
    <div className="p-4 md:p-6 space-y-5 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <ScrollText className="h-5 w-5 text-primary" />
            Threat Briefings
          </h1>
          <p className="text-sm text-muted-foreground">
            AI-generated executive threat intelligence summaries
          </p>
        </div>
        <button
          onClick={handleGenerate}
          disabled={generating}
          className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-primary text-primary-foreground text-xs font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
        >
          {generating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
          Generate Weekly Briefing
        </button>
      </div>

      {/* Briefings List */}
      {briefings.length === 0 ? (
        <Card>
          <CardContent className="py-16 text-center text-muted-foreground">
            <ScrollText className="h-12 w-12 mx-auto mb-3 opacity-30" />
            <p className="text-lg">No briefings yet</p>
            <p className="text-sm mt-1">Click &ldquo;Generate Weekly Briefing&rdquo; to create your first AI-powered threat summary.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {briefings.map((b) => {
            const isExpanded = expandedId === b.id;
            return (
              <Card key={b.id} className="border-l-2 border-primary/30">
                <div
                  className="px-5 py-4 cursor-pointer hover:bg-muted/20 transition-colors"
                  onClick={() => setExpandedId(isExpanded ? null : b.id)}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="text-sm font-semibold">{b.title}</h3>
                        <Badge variant="outline" className="text-[9px]">{b.period}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground line-clamp-2">
                        {b.executive_summary}
                      </p>
                      <div className="flex items-center gap-3 mt-2 text-[10px] text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Calendar className="h-3 w-3" />
                          {b.period_start ? new Date(b.period_start).toLocaleDateString() : "—"} — {b.period_end ? new Date(b.period_end).toLocaleDateString() : "—"}
                        </span>
                        {b.stats && (
                          <>
                            <span>{b.stats.total_articles} articles</span>
                            <span>{b.stats.total_cves} CVEs</span>
                            <span>{b.stats.total_campaigns} campaigns</span>
                          </>
                        )}
                      </div>
                    </div>
                    {isExpanded ? (
                      <ChevronUp className="h-4 w-4 text-muted-foreground shrink-0 mt-1" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0 mt-1" />
                    )}
                  </div>
                </div>

                {isExpanded && (
                  <div className="px-5 pb-5 pt-1 border-t border-border/20 space-y-4">
                    {/* Executive Summary */}
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground mb-1">Executive Summary</h4>
                      <p className="text-sm leading-relaxed whitespace-pre-wrap">{b.executive_summary}</p>
                    </div>

                    {/* Key Campaigns */}
                    {b.key_campaigns && b.key_campaigns.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1">
                          <Swords className="h-3 w-3" /> Key Campaigns
                        </h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          {b.key_campaigns.map((c: any, i: number) => (
                            <div key={i} className="p-2.5 rounded-md border bg-violet-500/[0.03]">
                              <span className="text-xs font-semibold text-violet-400">{c.name || c}</span>
                              {c.description && <p className="text-[10px] text-muted-foreground mt-0.5">{c.description}</p>}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Key Vulnerabilities */}
                    {b.key_vulnerabilities && b.key_vulnerabilities.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1">
                          <AlertTriangle className="h-3 w-3" /> Key Vulnerabilities
                        </h4>
                        <div className="flex flex-wrap gap-1.5">
                          {b.key_vulnerabilities.map((v: any, i: number) => (
                            <Badge key={i} variant="outline" className="text-[10px] text-primary">
                              {typeof v === "string" ? v : v.cve_id || v.name}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Key Actors */}
                    {b.key_actors && b.key_actors.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1">
                          <Skull className="h-3 w-3" /> Key Threat Actors
                        </h4>
                        <div className="flex flex-wrap gap-1.5">
                          {b.key_actors.map((a: any, i: number) => (
                            <Badge key={i} variant="outline" className="text-[10px] text-red-400">
                              {typeof a === "string" ? a : a.name}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Recommendations */}
                    {b.recommendations && b.recommendations.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1">
                          <Shield className="h-3 w-3" /> Recommendations
                        </h4>
                        <ul className="space-y-1.5">
                          {b.recommendations.map((r: string, i: number) => (
                            <li key={i} className="flex items-start gap-2 text-xs">
                              <span className="text-primary font-bold shrink-0 mt-0.5">{i + 1}.</span>
                              <span className="text-muted-foreground">{r}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
