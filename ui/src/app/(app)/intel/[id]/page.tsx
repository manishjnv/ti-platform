"use client";

import React, { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAppStore } from "@/store";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loading } from "@/components/Loading";
import {
  cn,
  formatDate,
  severityColor,
  riskColor,
  riskBg,
} from "@/lib/utils";
import {
  ArrowLeft,
  ExternalLink,
  Shield,
  Clock,
  AlertTriangle,
  Tag,
  Globe,
  Lock,
  Zap,
  Cpu,
  FileText,
  TrendingUp,
  Crosshair,
  Users,
  Activity,
  CheckCircle,
  XCircle,
  Target,
  BookOpen,
  Flame,
  Package,
  Wrench,
  ChevronRight,
  Sparkles,
  BarChart3,
  Copy,
  Check,
  Server,
  Network,
  MapPin,
  ShieldAlert,
  Skull,
  Swords,
  Bug,
  Radio,
} from "lucide-react";
import type {
  IntelAttackLink,
  RelatedIntelItem,
  IntelEnrichment,
  RelatedIntelItemEnriched,
} from "@/types";
import * as api from "@/lib/api";
import type { IntelLinkedIOC } from "@/lib/api";
import { StructuredIntelCards, type StructuredIntelData } from "@/components/StructuredIntelCards";

export default function IntelDetailPage() {
  const params = useParams();
  const router = useRouter();
  const { selectedItem: item, selectedLoading, fetchItem, clearSelectedItem } = useAppStore();
  const id = params?.id as string;
  const [attackLinks, setAttackLinks] = useState<IntelAttackLink[]>([]);
  const [attackLoading, setAttackLoading] = useState(false);
  const [relatedItems, setRelatedItems] = useState<RelatedIntelItemEnriched[]>([]);
  const [relatedLoading, setRelatedLoading] = useState(false);
  const [enrichment, setEnrichment] = useState<IntelEnrichment | null>(null);
  const [enrichmentLoading, setEnrichmentLoading] = useState(false);
  const [linkedIOCs, setLinkedIOCs] = useState<IntelLinkedIOC[]>([]);
  const [iocsLoading, setIOCsLoading] = useState(false);
  const [addingToReport, setAddingToReport] = useState(false);
  const [reportMenuOpen, setReportMenuOpen] = useState(false);
  const [userReports, setUserReports] = useState<{ id: string; title: string }[]>([]);
  const [reportActionMsg, setReportActionMsg] = useState<string | null>(null);

  useEffect(() => {
    if (id) fetchItem(id);
    return () => clearSelectedItem();
  }, [id, fetchItem, clearSelectedItem]);

  useEffect(() => {
    if (!id) return;
    setAttackLoading(true);
    api.getIntelAttackLinks(id)
      .then(setAttackLinks)
      .catch(() => setAttackLinks([]))
      .finally(() => setAttackLoading(false));

    setRelatedLoading(true);
    api.getIntelRelated(id)
      .then(setRelatedItems)
      .catch(() => setRelatedItems([]))
      .finally(() => setRelatedLoading(false));

    setEnrichmentLoading(true);
    api.getIntelEnrichment(id)
      .then(setEnrichment)
      .catch(() => setEnrichment(null))
      .finally(() => setEnrichmentLoading(false));

    setIOCsLoading(true);
    api.getIntelIOCs(id)
      .then(setLinkedIOCs)
      .catch(() => setLinkedIOCs([]))
      .finally(() => setIOCsLoading(false));
  }, [id]);

  if (selectedLoading) return <Loading text="Loading intel item..." />;
  if (!item)
    return (
      <div className="p-6 text-center text-muted-foreground">
        Intel item not found
      </div>
    );

  const exploitInfo = enrichment?.exploitation_info;
  const remediation = enrichment?.remediation;

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-5xl mx-auto">
      {/* Back button + Actions */}
      <div className="flex items-center justify-between">
        <Button variant="ghost" onClick={() => router.back()} className="gap-2">
          <ArrowLeft className="h-4 w-4" /> Back
        </Button>
        <div className="relative">
          <Button
            variant="outline"
            size="sm"
            onClick={async () => {
              if (!reportMenuOpen) {
                try {
                  const data = await api.getReports({ page: 1, page_size: 20, status: "draft" });
                  setUserReports(data.reports.map((r) => ({ id: r.id, title: r.title })));
                } catch { setUserReports([]); }
              }
              setReportMenuOpen(!reportMenuOpen);
            }}
          >
            <FileText className="h-3.5 w-3.5 mr-1" />
            Add to Report
          </Button>
          {reportMenuOpen && (
            <div className="absolute right-0 top-full mt-1 w-64 border rounded-lg bg-popover shadow-lg z-50 p-1 max-h-60 overflow-y-auto">
              {userReports.length === 0 ? (
                <p className="text-xs text-muted-foreground p-2">No draft reports. Create one first.</p>
              ) : (
                userReports.map((r) => (
                  <button
                    key={r.id}
                    className="w-full text-left px-3 py-1.5 text-sm rounded hover:bg-accent/50 truncate"
                    onClick={async () => {
                      setAddingToReport(true);
                      setReportMenuOpen(false);
                      try {
                        await api.addReportItem(r.id, {
                          item_type: "intel",
                          item_id: item!.id,
                          item_title: item!.title,
                          item_metadata: {
                            severity: item!.severity,
                            risk_score: item!.risk_score,
                            source_name: item!.source_name,
                            feed_type: item!.feed_type,
                            cve_ids: item!.cve_ids,
                          },
                        });
                        setReportActionMsg(`Added to "${r.title}"`);
                      } catch {
                        setReportActionMsg("Already linked or error");
                      }
                      setAddingToReport(false);
                      setTimeout(() => setReportActionMsg(null), 3000);
                    }}
                  >
                    {r.title}
                  </button>
                ))
              )}
            </div>
          )}
          {reportActionMsg && (
            <div className="absolute right-0 top-full mt-1 px-3 py-1.5 rounded-md bg-primary/10 text-primary text-xs whitespace-nowrap z-50">
              {reportActionMsg}
            </div>
          )}
        </div>
      </div>

      {/* Header */}
      <div className="flex items-start gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <Badge variant={item.severity as any} className="text-sm">
              {item.severity.toUpperCase()}
            </Badge>
            {item.is_kev && (
              <Badge variant="destructive" className="gap-1">
                <AlertTriangle className="h-3 w-3" /> KEV
              </Badge>
            )}
            {item.exploit_available && (
              <Badge variant="outline" className="text-orange-500 border-orange-500 gap-1">
                <Zap className="h-3 w-3" /> Exploit Available
              </Badge>
            )}
            <Badge variant="outline">{item.feed_type}</Badge>
            <Badge variant="outline">{item.asset_type}</Badge>
            <Badge variant="outline">{item.tlp}</Badge>
          </div>
          <h1 className="text-xl font-bold leading-tight">{item.title}</h1>
        </div>

        <div
          className={cn(
            "flex flex-col items-center justify-center rounded-xl p-4 min-w-[80px]",
            riskBg(item.risk_score)
          )}
        >
          <span className={cn("text-4xl font-bold", riskColor(item.risk_score))}>
            {item.risk_score}
          </span>
          <span className="text-xs text-muted-foreground mt-1">RISK SCORE</span>
        </div>
      </div>

      {/* Quick Stats Row */}
      {(exploitInfo || enrichment) && !enrichmentLoading && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="rounded-lg border bg-card p-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
              <BarChart3 className="h-3 w-3" /> EPSS Estimate
            </div>
            <div className="text-lg font-bold">
              {exploitInfo?.epss_estimate != null
                ? `${(exploitInfo.epss_estimate * 100).toFixed(1)}%`
                : "N/A"}
            </div>
            <div className="text-[10px] text-muted-foreground">Exploitation probability</div>
          </div>

          <div className="rounded-lg border bg-card p-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
              <Flame className="h-3 w-3" /> Exploit Maturity
            </div>
            <div className="text-lg font-bold capitalize">
              {exploitInfo?.exploit_maturity || "Unknown"}
            </div>
            <div className="flex gap-1 mt-1">
              {["none", "poc", "weaponized"].map((level) => (
                <div
                  key={level}
                  className={cn(
                    "h-1.5 flex-1 rounded-full",
                    exploitInfo?.exploit_maturity === level
                      ? level === "weaponized"
                        ? "bg-red-500"
                        : level === "poc"
                        ? "bg-orange-500"
                        : "bg-green-500"
                      : "bg-muted"
                  )}
                />
              ))}
            </div>
          </div>

          <div className="rounded-lg border bg-card p-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
              <Wrench className="h-3 w-3" /> Remediation Priority
            </div>
            <div className={cn("text-lg font-bold capitalize", {
              "text-red-500": remediation?.priority === "critical",
              "text-orange-500": remediation?.priority === "high",
              "text-yellow-500": remediation?.priority === "medium",
              "text-green-500": remediation?.priority === "low",
            })}>
              {remediation?.priority || "N/A"}
            </div>
          </div>

          <div className="rounded-lg border bg-card p-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
              <Target className="h-3 w-3" /> Active Exploitation
            </div>
            <div className="flex items-center gap-2">
              {exploitInfo?.in_the_wild ? (
                <>
                  <XCircle className="h-5 w-5 text-red-500" />
                  <span className="text-lg font-bold text-red-500">Yes</span>
                </>
              ) : (
                <>
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  <span className="text-lg font-bold text-green-500">No</span>
                </>
              )}
            </div>
            {exploitInfo?.ransomware_use && (
              <Badge variant="destructive" className="text-[9px] mt-1">Ransomware</Badge>
            )}
          </div>
        </div>
      )}
      {enrichmentLoading && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[1,2,3,4].map(i => (
            <div key={i} className="rounded-lg border bg-card p-3 animate-pulse">
              <div className="h-3 bg-muted rounded w-20 mb-2" />
              <div className="h-6 bg-muted rounded w-12" />
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <Tabs defaultValue="overview">
        <TabsList className="flex-wrap">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="attack" className="gap-1">
            <Crosshair className="h-3 w-3" /> ATT&CK
            {(attackLinks.length > 0 || (enrichment?.attack_techniques?.length ?? 0) > 0) && (
              <Badge variant="secondary" className="text-[9px] ml-1 px-1 py-0">
                {attackLinks.length || enrichment?.attack_techniques?.length || 0}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
          <TabsTrigger value="remediation" className="gap-1">
            <Wrench className="h-3 w-3" /> Remediation
          </TabsTrigger>
          <TabsTrigger value="related">
            Related Intel
            {relatedItems.length > 0 && (
              <Badge variant="secondary" className="text-[9px] ml-1 px-1 py-0">
                {relatedItems.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="iocs" className="gap-1">
            <ShieldAlert className="h-3 w-3" /> IOCs
            {linkedIOCs.length > 0 && (
              <Badge variant="secondary" className="text-[9px] ml-1 px-1 py-0">
                {linkedIOCs.length}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        {/* ───── Overview Tab ───── */}
        <TabsContent value="overview" className="space-y-4 mt-4">
          {/* Executive Brief */}
          {enrichment?.executive_summary && (
            <Card className="border-blue-500/30 bg-blue-500/5">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-blue-400" /> Executive Brief
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm">{enrichment.executive_summary}</p>
              </CardContent>
            </Card>
          )}

          {/* AI Summary */}
          {item.ai_summary && (
            <Card className="border-purple-500/30 bg-purple-500/5">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-purple-400" /> AI Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm">{item.ai_summary}</p>
                {item.ai_summary_at && (
                  <p className="text-xs text-muted-foreground mt-2">
                    Generated {formatDate(item.ai_summary_at, { relative: true })}
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {/* Description */}
          {item.description && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <FileText className="h-4 w-4" /> Description
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm whitespace-pre-wrap">{item.description}</p>
              </CardContent>
            </Card>
          )}

          {/* Unified Structured Intel Snapshot */}
          {enrichment && (
            <StructuredIntelCards
              data={{
                summary: enrichment.executive_summary || item.ai_summary || undefined,
                threatActors: enrichment.threat_actors.map((ta) => ta.name),
                affectedProducts: item.affected_products?.length > 0
                  ? item.affected_products
                  : enrichment.affected_versions.map((av) => `${av.vendor}:${av.product}`),
                knownBreaches: enrichment.notable_campaigns.length > 0
                  ? enrichment.notable_campaigns.map((c) => `${c.name} (${c.date}): ${c.description}`).join(". ")
                  : null,
                fixRemediation: enrichment.remediation?.guidance?.length > 0
                  ? enrichment.remediation.guidance.join(". ")
                  : null,
                timeline: enrichment.timeline_events
                  .filter((e) => e.date)
                  .sort((a, b) => new Date(a.date!).getTime() - new Date(b.date!).getTime())
                  .map((e) => ({ date: e.date!, event: e.event })),
                keyFindings: [
                  ...(item.is_kev ? ["Listed in CISA Known Exploited Vulnerabilities (KEV)"] : []),
                  ...(item.exploit_available ? ["Active exploit code is available"] : []),
                  ...(exploitInfo?.ransomware_use ? ["Associated with ransomware campaigns"] : []),
                  ...(exploitInfo?.in_the_wild ? ["Actively exploited in the wild"] : []),
                  ...(item.exploitability_score != null && item.exploitability_score >= 7
                    ? [`High exploitability score: ${item.exploitability_score}`] : []),
                ],
              }}
              variant="full"
            />
          )}

          {/* Threat Actors — Enhanced */}
          {enrichment && enrichment.threat_actors.length > 0 && (
            <Card className="border-red-500/20 bg-red-500/[0.02]">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Skull className="h-4 w-4 text-red-400" /> Associated Threat Actors
                  <Badge variant="destructive" className="text-[9px] ml-auto">
                    {enrichment.threat_actors.length} Actor{enrichment.threat_actors.length > 1 ? "s" : ""}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {enrichment.threat_actors.map((ta, i) => {
                  const motivationIcon =
                    ta.motivation === "financial" ? "💰" :
                    ta.motivation === "espionage" ? "🕵️" :
                    ta.motivation === "hacktivism" ? "✊" :
                    ta.motivation === "destruction" ? "💥" : "❓";
                  const confidenceColor =
                    ta.confidence === "high" ? "text-red-400 border-red-400/40 bg-red-400/10" :
                    ta.confidence === "medium" ? "text-yellow-400 border-yellow-400/40 bg-yellow-400/10" :
                    "text-muted-foreground border-border/40 bg-muted/10";
                  return (
                    <div key={i} className="rounded-lg border border-red-500/20 bg-card overflow-hidden">
                      {/* Actor header */}
                      <div className="flex items-center gap-3 px-4 py-3 border-b border-border/20 bg-red-500/[0.03]">
                        <div className="h-10 w-10 rounded-full bg-gradient-to-br from-red-500/20 to-red-900/20 flex items-center justify-center shrink-0 text-lg">
                          {motivationIcon}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-bold">{ta.name}</span>
                            <Badge className={cn("text-[9px] capitalize border", confidenceColor)}>
                              {ta.confidence} confidence
                            </Badge>
                          </div>
                          {ta.aliases.length > 0 && (
                            <p className="text-[11px] text-muted-foreground mt-0.5">
                              Also known as: <span className="text-foreground/70">{ta.aliases.join(", ")}</span>
                            </p>
                          )}
                        </div>
                        <a
                          href={`/search?q=${encodeURIComponent(ta.name)}`}
                          className="text-[10px] text-primary hover:underline shrink-0 flex items-center gap-1"
                        >
                          <Crosshair className="h-3 w-3" /> Hunt
                        </a>
                      </div>
                      {/* Actor details */}
                      <div className="px-4 py-3 space-y-2">
                        <p className="text-xs leading-relaxed">{ta.description}</p>
                        <div className="flex items-center gap-3 flex-wrap text-[10px]">
                          <span className="flex items-center gap-1 text-muted-foreground">
                            <Swords className="h-3 w-3" /> Motivation:
                            <span className="text-foreground capitalize font-medium">{ta.motivation}</span>
                          </span>
                          {/* Show related ATT&CK techniques if any match */}
                          {enrichment.attack_techniques.length > 0 && (
                            <span className="flex items-center gap-1 text-muted-foreground">
                              <Crosshair className="h-3 w-3" />
                              <span className="text-foreground font-medium">
                                {enrichment.attack_techniques.length} technique{enrichment.attack_techniques.length > 1 ? "s" : ""}
                              </span>
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          )}

          {/* Notable Campaigns / Breaches — Enhanced */}
          {enrichment && enrichment.notable_campaigns.length > 0 && (
            <Card className="border-orange-500/20 bg-orange-500/[0.02]">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Flame className="h-4 w-4 text-orange-400" /> Notable Attacks & Breaches
                  <Badge variant="outline" className="text-[9px] text-orange-400 border-orange-400/40 ml-auto">
                    {enrichment.notable_campaigns.length} event{enrichment.notable_campaigns.length > 1 ? "s" : ""}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="relative border-l-2 border-orange-500/30 pl-5 space-y-4 ml-2">
                  {enrichment.notable_campaigns.map((c, i) => {
                    const severityLevel =
                      c.impact?.toLowerCase().includes("critical") || c.impact?.toLowerCase().includes("major") ? "critical" :
                      c.impact?.toLowerCase().includes("significant") || c.impact?.toLowerCase().includes("high") ? "high" :
                      "medium";
                    const dotColor =
                      severityLevel === "critical" ? "bg-red-500 shadow-red-500/50" :
                      severityLevel === "high" ? "bg-orange-500 shadow-orange-500/50" :
                      "bg-yellow-500 shadow-yellow-500/50";
                    return (
                      <div key={i} className="relative">
                        <div className={cn("absolute -left-[25px] top-1.5 h-3 w-3 rounded-full shadow-sm", dotColor)} />
                        <div className="rounded-lg border border-orange-500/15 bg-card p-3 space-y-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-bold">{c.name}</span>
                            <Badge variant="outline" className="text-[9px] text-orange-400 border-orange-400/30 font-mono">
                              {c.date}
                            </Badge>
                          </div>
                          <p className="text-xs leading-relaxed text-muted-foreground">{c.description}</p>
                          {c.impact && (
                            <div className="flex items-start gap-2 rounded-md bg-orange-500/[0.06] border border-orange-500/15 px-3 py-2">
                              <AlertTriangle className="h-3.5 w-3.5 text-orange-400 shrink-0 mt-0.5" />
                              <div>
                                <p className="text-[10px] font-semibold text-orange-300 uppercase tracking-wider mb-0.5">Impact Assessment</p>
                                <p className="text-xs text-orange-200/80">{c.impact}</p>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Affected Products & Fix Versions */}
          {enrichment && enrichment.affected_versions.length > 0 && (
            <Card className="border-cyan-500/20">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Package className="h-4 w-4 text-cyan-400" /> Affected Products & Fix Versions
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-xs text-muted-foreground border-b">
                        <th className="text-left py-2 pr-3">Product</th>
                        <th className="text-left py-2 pr-3">Vendor</th>
                        <th className="text-left py-2 pr-3">Affected Versions</th>
                        <th className="text-left py-2 pr-3">Fixed Version</th>
                        <th className="text-left py-2">Patch</th>
                      </tr>
                    </thead>
                    <tbody>
                      {enrichment.affected_versions.map((av, i) => (
                        <tr key={i} className="border-b border-border/20">
                          <td className="py-2 pr-3 font-medium">{av.product}</td>
                          <td className="py-2 pr-3 text-muted-foreground">{av.vendor}</td>
                          <td className="py-2 pr-3">
                            <Badge variant="outline" className="text-[10px] text-red-400 border-red-400/40">
                              {av.versions_affected}
                            </Badge>
                          </td>
                          <td className="py-2 pr-3">
                            {av.fixed_version ? (
                              <Badge variant="outline" className="text-[10px] text-green-400 border-green-400/40">
                                {av.fixed_version}
                              </Badge>
                            ) : (
                              <span className="text-xs text-muted-foreground">No fix yet</span>
                            )}
                          </td>
                          <td className="py-2">
                            {av.patch_url ? (
                              <a
                                href={av.patch_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-primary hover:underline inline-flex items-center gap-1 text-xs"
                              >
                                <ExternalLink className="h-3 w-3" /> Patch
                              </a>
                            ) : (
                              <span className="text-xs text-muted-foreground">—</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Source Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <Row label="Source" value={item.source_name} icon={Shield} />
                <Row label="Reliability" value={`${item.source_reliability}/100`} icon={TrendingUp} />
                <Row label="Confidence" value={`${item.confidence}%`} icon={Shield} />
                <Row label="Reference" value={item.source_ref || "N/A"} icon={FileText} />
                {item.source_url && (
                  <div>
                    <a
                      href={item.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center gap-1 text-sm"
                    >
                      <ExternalLink className="h-3 w-3" /> View Source
                    </a>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Timestamps</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <Row label="Published" value={formatDate(item.published_at)} icon={Clock} />
                <Row label="Ingested" value={formatDate(item.ingested_at)} icon={Clock} />
                <Row label="Updated" value={formatDate(item.updated_at)} icon={Clock} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Classification</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <Row label="TLP" value={item.tlp} icon={Lock} />
                <Row label="Asset Type" value={item.asset_type} icon={Cpu} />
                <Row label="Feed Type" value={item.feed_type} icon={FileText} />
                <Row label="Related IOCs" value={String(item.related_ioc_count)} icon={AlertTriangle} />
                {item.exploitability_score != null && (
                  <Row label="CVSS Score" value={String(item.exploitability_score)} icon={Zap} />
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Context</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                {item.cve_ids.length > 0 && (
                  <div>
                    <span className="text-muted-foreground block mb-1">CVE IDs</span>
                    <div className="flex flex-wrap gap-1">
                      {item.cve_ids.map((cve) => (
                        <Badge key={cve} variant="secondary">
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            {cve}
                          </a>
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {enrichment && enrichment.related_cves.length > 0 && (
                  <div>
                    <span className="text-muted-foreground block mb-1">Related CVEs</span>
                    <div className="flex flex-wrap gap-1">
                      {enrichment.related_cves
                        .filter((c) => !item.cve_ids.includes(c))
                        .map((cve) => (
                          <Badge key={cve} variant="outline" className="text-xs">
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              {cve}
                            </a>
                          </Badge>
                        ))}
                    </div>
                  </div>
                )}

                {item.tags.length > 0 && (
                  <div>
                    <span className="text-muted-foreground flex items-center gap-1 mb-1">
                      <Tag className="h-3 w-3" /> Tags
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {item.tags.map((tag) => (
                        <Badge key={tag} variant="outline" className="text-xs">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {item.geo.length > 0 && (
                  <div>
                    <span className="text-muted-foreground flex items-center gap-1 mb-1">
                      <Globe className="h-3 w-3" /> Geo
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {item.geo.map((g) => (
                        <Badge key={g} variant="outline" className="text-xs">
                          {g}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {item.affected_products.length > 0 && (
                  <div>
                    <span className="text-muted-foreground flex items-center gap-1 mb-1">
                      <Cpu className="h-3 w-3" /> Affected Products
                    </span>
                    <ul className="list-disc list-inside text-muted-foreground text-xs space-y-0.5">
                      {item.affected_products.map((p) => (
                        <li key={p} className="truncate">{p}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Exploitation Details */}
          {exploitInfo?.description && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Activity className="h-4 w-4 text-yellow-400" /> Exploitation Context
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm">{exploitInfo.description}</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ───── ATT&CK Tab ───── */}
        <TabsContent value="attack" className="mt-4 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Crosshair className="h-4 w-4 text-primary" /> MITRE ATT&CK Techniques
                {attackLinks.length > 0 && (
                  <Badge variant="secondary" className="text-[9px]">
                    {attackLinks.length} mapped
                  </Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {attackLoading ? (
                <div className="text-center py-4 text-sm text-muted-foreground">Loading...</div>
              ) : attackLinks.length === 0 && (enrichment?.attack_techniques?.length ?? 0) === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Shield className="h-8 w-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No ATT&CK techniques mapped to this item yet.</p>
                  <p className="text-xs mt-1">Auto-mapping runs periodically based on text analysis.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {attackLinks.map((link) => (
                    <div
                      key={link.technique_id}
                      className="flex items-center gap-3 rounded-md border border-border/30 px-3 py-2 hover:bg-muted/20 transition-colors"
                    >
                      <Badge variant="outline" className="font-mono text-[10px] shrink-0">
                        {link.technique_id}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <span className="text-sm font-medium">{link.technique_name}</span>
                        <span className="text-xs text-muted-foreground ml-2">
                          {link.tactic_label}
                        </span>
                      </div>
                      <Badge variant="secondary" className="text-[9px] shrink-0">
                        {link.mapping_type}
                      </Badge>
                      <Badge variant="outline" className="text-[9px] shrink-0">
                        {link.confidence}% conf
                      </Badge>
                      {link.url && (
                        <a
                          href={link.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-muted-foreground hover:text-primary"
                        >
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* AI-Inferred Techniques */}
          {enrichment && enrichment.attack_techniques.length > 0 && (
            <Card className="border-purple-500/20">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-purple-400" /> AI-Inferred Techniques
                  <Badge variant="outline" className="text-[9px] text-purple-400 border-purple-400/40">
                    AI Analysis
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {enrichment.attack_techniques.map((tech, i) => (
                  <div
                    key={i}
                    className="rounded-md border border-border/30 px-3 py-2"
                  >
                    <div className="flex items-center gap-3 mb-1">
                      <Badge variant="outline" className="font-mono text-[10px] shrink-0">
                        {tech.technique_id}
                      </Badge>
                      <span className="text-sm font-medium">{tech.technique_name}</span>
                      <Badge variant="secondary" className="text-[9px] capitalize">
                        {tech.tactic}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">{tech.description}</p>
                    {tech.mitigations.length > 0 && (
                      <div className="mt-2 pt-2 border-t border-border/20">
                        <span className="text-[10px] text-muted-foreground font-medium">Mitigations:</span>
                        <ul className="list-disc list-inside text-xs text-muted-foreground mt-0.5 space-y-0.5">
                          {tech.mitigations.map((m, j) => (
                            <li key={j}>{m}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {enrichmentLoading && (
            <Card>
              <CardContent className="py-6">
                <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
                  <div className="h-4 w-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  Analyzing with AI...
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ───── Timeline Tab ───── */}
        <TabsContent value="timeline" className="mt-4 space-y-4">
          {/* Timeline legend */}
          <div className="flex items-center gap-4 flex-wrap text-[10px] text-muted-foreground">
            <span className="font-semibold uppercase tracking-wider">Event Types:</span>
            {Object.entries(timelineTypeConfig).map(([type, cfg]) => (
              <span key={type} className="flex items-center gap-1.5 capitalize">
                <span className={cn("h-2 w-2 rounded-full", cfg.dot)} />
                {type}
              </span>
            ))}
          </div>

          <Card>
            <CardContent className="py-8">
              <div className="relative border-l-2 border-muted/50 pl-8 space-y-0 ml-4">
                {(() => {
                  // Collect all events, sort by date
                  const events: { date: string; title: string; description: string; type: string; source?: string }[] = [];

                  if (enrichment) {
                    enrichment.timeline_events
                      .filter((e) => e.date)
                      .forEach((evt) => events.push({
                        date: evt.date!, title: evt.event, description: evt.description, type: evt.type, source: "ai"
                      }));
                  }

                  if (item.published_at) {
                    events.push({ date: item.published_at, title: "Published", description: `Published by ${item.source_name}`, type: "publication", source: "system" });
                  }
                  events.push({ date: item.ingested_at, title: "Ingested by IntelWatch", description: "First seen by TI Platform", type: "update", source: "system" });
                  if (item.ai_summary_at) {
                    events.push({ date: item.ai_summary_at, title: "AI Analysis Complete", description: "Automated threat intelligence analysis", type: "advisory", source: "system" });
                  }
                  if (item.updated_at) {
                    events.push({ date: item.updated_at, title: "Last Updated", description: "Most recent data update", type: "update", source: "system" });
                  }

                  // Undated events
                  const undated = enrichment?.timeline_events.filter((e) => !e.date) ?? [];

                  // Sort by date
                  events.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

                  return (
                    <>
                      {events.map((evt, i) => (
                        <EnhancedTimelineEvent
                          key={`evt-${i}`}
                          date={evt.date}
                          title={evt.title}
                          description={evt.description}
                          type={evt.type}
                          isLast={i === events.length - 1 && undated.length === 0}
                          source={evt.source}
                        />
                      ))}
                      {undated.length > 0 && (
                        <div className="pt-4 border-t border-border/20 mt-4">
                          <p className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider mb-3">Undated Events</p>
                          {undated.map((evt, i) => (
                            <EnhancedTimelineEvent
                              key={`undated-${i}`}
                              date=""
                              title={evt.event}
                              description={evt.description}
                              type={evt.type}
                              isLast={i === undated.length - 1}
                            />
                          ))}
                        </div>
                      )}
                    </>
                  );
                })()}
              </div>

              {enrichmentLoading && (
                <div className="mt-4 flex items-center justify-center gap-2 text-sm text-muted-foreground">
                  <div className="h-4 w-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  Loading CVE timeline...
                </div>
              )}

              {!enrichmentLoading && !enrichment && (
                <div className="mt-4 text-center text-xs text-muted-foreground">
                  <Clock className="h-6 w-6 mx-auto mb-2 opacity-30" />
                  Timeline data is generated by AI enrichment analysis.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ───── Remediation Tab ───── */}
        <TabsContent value="remediation" className="mt-4 space-y-4">
          {enrichmentLoading ? (
            <Card>
              <CardContent className="py-8">
                <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
                  <div className="h-4 w-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  Generating remediation guidance...
                </div>
              </CardContent>
            </Card>
          ) : remediation && (remediation.guidance.length > 0 || remediation.workarounds.length > 0 || remediation.references.length > 0) ? (
            <>
              {remediation.priority && (
                <div className={cn("rounded-lg p-4 flex items-center gap-3", {
                  "bg-red-500/10 border border-red-500/30": remediation.priority === "critical",
                  "bg-orange-500/10 border border-orange-500/30": remediation.priority === "high",
                  "bg-yellow-500/10 border border-yellow-500/30": remediation.priority === "medium",
                  "bg-green-500/10 border border-green-500/30": remediation.priority === "low",
                })}>
                  <AlertTriangle className={cn("h-5 w-5", {
                    "text-red-500": remediation.priority === "critical",
                    "text-orange-500": remediation.priority === "high",
                    "text-yellow-500": remediation.priority === "medium",
                    "text-green-500": remediation.priority === "low",
                  })} />
                  <div>
                    <p className="text-sm font-semibold capitalize">
                      {remediation.priority} Priority Remediation
                    </p>
                    <p className="text-xs text-muted-foreground">
                      This vulnerability requires {remediation.priority === "critical" ? "immediate" : remediation.priority === "high" ? "urgent" : "scheduled"} attention
                    </p>
                  </div>
                </div>
              )}

              {remediation.guidance.length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-green-400" /> Remediation Steps
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ol className="list-decimal list-inside space-y-2 text-sm">
                      {remediation.guidance.map((step, i) => (
                        <li key={i} className="text-muted-foreground">
                          <span className="text-foreground">{step}</span>
                        </li>
                      ))}
                    </ol>
                  </CardContent>
                </Card>
              )}

              {remediation.workarounds.length > 0 && (
                <Card className="border-yellow-500/20">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Wrench className="h-4 w-4 text-yellow-400" /> Workarounds
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ul className="list-disc list-inside space-y-1.5 text-sm">
                      {remediation.workarounds.map((w, i) => (
                        <li key={i}>{w}</li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>
              )}

              {enrichment && enrichment.affected_versions.length > 0 && (
                <Card className="border-cyan-500/20">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Package className="h-4 w-4 text-cyan-400" /> Patch Availability
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {enrichment.affected_versions.map((av, i) => (
                        <div key={i} className="flex items-center justify-between rounded-md border border-border/30 px-3 py-2">
                          <div className="flex-1">
                            <span className="text-sm font-medium">{av.vendor} {av.product}</span>
                            <span className="text-xs text-muted-foreground ml-2">{av.versions_affected}</span>
                          </div>
                          {av.fixed_version ? (
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className="text-green-400 border-green-400/40 text-[10px]">
                                Fix: {av.fixed_version}
                              </Badge>
                              {av.patch_url && (
                                <a
                                  href={av.patch_url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-primary hover:underline text-xs flex items-center gap-1"
                                >
                                  <ExternalLink className="h-3 w-3" /> Download
                                </a>
                              )}
                            </div>
                          ) : (
                            <Badge variant="outline" className="text-red-400 border-red-400/40 text-[10px]">
                              No patch
                            </Badge>
                          )}
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {remediation.references.length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <BookOpen className="h-4 w-4" /> Vendor Advisories & References
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1.5">
                    {remediation.references.map((ref, i) => (
                      <a
                        key={i}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 text-sm text-primary hover:underline hover:bg-muted/20 rounded px-2 py-1 -mx-2"
                      >
                        <ExternalLink className="h-3 w-3 shrink-0" />
                        {ref.title}
                        <ChevronRight className="h-3 w-3 ml-auto text-muted-foreground" />
                      </a>
                    ))}
                  </CardContent>
                </Card>
              )}
            </>
          ) : (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                <Wrench className="h-8 w-8 mx-auto mb-2 opacity-30" />
                <p className="text-sm">No remediation guidance available yet.</p>
                <p className="text-xs mt-1">AI enrichment may be disabled or still processing.</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ───── Related Intel Tab ───── */}
        <TabsContent value="related" className="mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" /> Related Intelligence
              </CardTitle>
            </CardHeader>
            <CardContent>
              {relatedLoading ? (
                <div className="text-center py-4 text-sm text-muted-foreground">Loading…</div>
              ) : relatedItems.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Shield className="h-8 w-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No related intelligence found yet.</p>
                  <p className="text-xs mt-1">
                    Relationships are built automatically based on shared IOCs, CVEs and tags.
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  {relatedItems.map((rel) => (
                    <a
                      key={rel.id}
                      href={`/intel/${rel.id}`}
                      className="flex items-center gap-3 rounded-md border border-border/30 px-3 py-2 hover:bg-muted/20 transition-colors"
                    >
                      <Badge variant={rel.severity as any} className="text-[10px] shrink-0">
                        {rel.severity.toUpperCase()}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <span className="text-sm font-medium truncate block">{rel.title}</span>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5">
                          <span>{rel.source_name} · {rel.feed_type}</span>
                          {rel.shared_cves?.length > 0 && (
                            <span className="text-primary">
                              CVE: {rel.shared_cves.join(", ")}
                            </span>
                          )}
                        </div>
                      </div>
                      <Badge variant="secondary" className="text-[9px] shrink-0">
                        {rel.relationship_type.replace(/_/g, " ")}
                      </Badge>
                      <Badge variant="outline" className="text-[9px] shrink-0">
                        {rel.confidence}% conf
                      </Badge>
                      <span className="text-xs text-muted-foreground font-medium shrink-0">
                        {rel.risk_score}
                      </span>
                    </a>
                  ))}
                  <div className="pt-2 text-center">
                    <a
                      href={`/investigate?id=${id}&type=intel`}
                      className="text-xs text-primary hover:underline"
                    >
                      View full relationship graph →
                    </a>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ───── IOCs Tab ───── */}
        <TabsContent value="iocs" className="mt-4 space-y-4">
          {/* IOC Stats summary */}
          {linkedIOCs.length > 0 && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="rounded-lg border bg-card p-3">
                <p className="text-[10px] text-muted-foreground">Total IOCs</p>
                <p className="text-2xl font-bold">{linkedIOCs.length}</p>
              </div>
              <div className="rounded-lg border bg-card p-3">
                <p className="text-[10px] text-muted-foreground">IOC Types</p>
                <div className="flex flex-wrap gap-1 mt-1">
                  {Array.from(new Set(linkedIOCs.map(i => i.ioc_type))).map(t => (
                    <Badge key={t} variant="secondary" className="text-[9px]">
                      {t} ({linkedIOCs.filter(i => i.ioc_type === t).length})
                    </Badge>
                  ))}
                </div>
              </div>
              <div className="rounded-lg border bg-card p-3">
                <p className="text-[10px] text-muted-foreground">Countries</p>
                <div className="flex flex-wrap gap-1.5 mt-1">
                  {Array.from(new Set(linkedIOCs.filter(i => i.country_code).map(i => i.country_code!))).slice(0, 5).map(cc => (
                    <span key={cc} className="flex items-center gap-1 text-[10px]">
                      <img src={`https://flagcdn.com/16x12/${cc.toLowerCase()}.png`} alt={cc} className="h-2.5" onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }} />
                      {cc}
                    </span>
                  ))}
                  {linkedIOCs.filter(i => i.country_code).length === 0 && <span className="text-[10px] text-muted-foreground">—</span>}
                </div>
              </div>
              <div className="rounded-lg border bg-card p-3">
                <p className="text-[10px] text-muted-foreground">With Vulnerabilities</p>
                <p className="text-2xl font-bold text-red-400">
                  {linkedIOCs.filter(i => i.vulns.length > 0).length}
                </p>
              </div>
            </div>
          )}

          {/* IOC Table */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-primary" /> Linked Indicators of Compromise
              </CardTitle>
            </CardHeader>
            <CardContent>
              {iocsLoading ? (
                <div className="text-center py-8 text-sm text-muted-foreground">
                  <div className="h-4 w-4 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                  Loading IOCs...
                </div>
              ) : linkedIOCs.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <ShieldAlert className="h-8 w-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No IOCs linked to this intel item.</p>
                  <p className="text-xs mt-1">IOCs are extracted from ingested feeds and linked to intel items automatically.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {linkedIOCs.map((ioc) => (
                    <IOCDetailRow key={ioc.id} ioc={ioc} />
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function Row({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground flex items-center gap-1">
        <Icon className="h-3 w-3" /> {label}
      </span>
      <span className="font-medium text-right">{value}</span>
    </div>
  );
}

/* ── Timeline Config & Component ───────────────────────── */

const timelineTypeConfig: Record<string, { dot: string; icon: React.ReactNode; label: string; bg: string }> = {
  disclosure: {
    dot: "bg-yellow-500",
    icon: <AlertTriangle className="h-3 w-3 text-yellow-400" />,
    label: "Disclosure",
    bg: "border-yellow-500/20 bg-yellow-500/5",
  },
  publication: {
    dot: "bg-blue-500",
    icon: <FileText className="h-3 w-3 text-blue-400" />,
    label: "Publication",
    bg: "border-blue-500/20 bg-blue-500/5",
  },
  patch: {
    dot: "bg-green-500",
    icon: <CheckCircle className="h-3 w-3 text-green-400" />,
    label: "Patch",
    bg: "border-green-500/20 bg-green-500/5",
  },
  exploit: {
    dot: "bg-red-500",
    icon: <Zap className="h-3 w-3 text-red-400" />,
    label: "Exploit",
    bg: "border-red-500/20 bg-red-500/5",
  },
  kev: {
    dot: "bg-red-600",
    icon: <AlertTriangle className="h-3 w-3 text-red-500" />,
    label: "KEV",
    bg: "border-red-600/20 bg-red-600/5",
  },
  advisory: {
    dot: "bg-cyan-500",
    icon: <BookOpen className="h-3 w-3 text-cyan-400" />,
    label: "Advisory",
    bg: "border-cyan-500/20 bg-cyan-500/5",
  },
  update: {
    dot: "bg-primary",
    icon: <Clock className="h-3 w-3 text-primary" />,
    label: "Update",
    bg: "border-border/30 bg-muted/5",
  },
};

function EnhancedTimelineEvent({
  date,
  title,
  description,
  type = "update",
  isLast = false,
  source,
}: {
  date: string;
  title: string;
  description: string;
  type?: string;
  isLast?: boolean;
  source?: string;
}) {
  const cfg = timelineTypeConfig[type] || timelineTypeConfig.update;
  const relDate = date ? formatDate(date, { relative: true }) : "";
  const absDate = date ? formatDate(date) : "";

  return (
    <div className={cn("relative pb-6", isLast && "pb-0")}>
      {/* Dot */}
      <div className={cn("absolute -left-[33px] top-3 h-3.5 w-3.5 rounded-full ring-4 ring-background", cfg.dot)} />
      {/* Card */}
      <div className={cn("rounded-lg border p-3 ml-1", cfg.bg)}>
        <div className="flex items-center gap-2 flex-wrap">
          {cfg.icon}
          <span className="text-sm font-semibold">{title}</span>
          <Badge variant="outline" className={cn("text-[8px] capitalize px-1.5 py-0 h-4", type !== "update" && "font-medium")}>
            {cfg.label}
          </Badge>
          {source === "ai" && (
            <span className="ml-auto" title="AI-generated"><Sparkles className="h-3 w-3 text-purple-400" /></span>
          )}
        </div>
        <p className="text-xs text-muted-foreground mt-1">{description}</p>
        {date && (
          <div className="flex items-center gap-2 mt-1.5 text-[10px] text-muted-foreground">
            <Clock className="h-2.5 w-2.5" />
            <span>{absDate}</span>
            <span className="text-muted-foreground/50">({relDate})</span>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── IOC Detail Row Component ──────────────────────────── */

const IOC_TYPE_COLORS: Record<string, string> = {
  ip: "#3b82f6",
  domain: "#a855f7",
  url: "#f97316",
  hash_md5: "#ef4444",
  hash_sha1: "#dc2626",
  hash_sha256: "#b91c1c",
  email: "#ec4899",
  cve: "#22c55e",
  file: "#6366f1",
  other: "#6b7280",
};

function IOCDetailRow({ ioc }: { ioc: api.IntelLinkedIOC }) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const riskColor =
    ioc.risk_score >= 80 ? "text-red-400" :
    ioc.risk_score >= 60 ? "text-orange-400" :
    ioc.risk_score >= 40 ? "text-yellow-400" : "text-green-400";
  const riskBgClass =
    ioc.risk_score >= 80 ? "bg-red-500/10" :
    ioc.risk_score >= 60 ? "bg-orange-500/10" :
    ioc.risk_score >= 40 ? "bg-yellow-500/10" : "bg-green-500/10";

  const handleCopy = () => {
    navigator.clipboard.writeText(ioc.value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const hasEnrichment = ioc.ports.length > 0 || ioc.vulns.length > 0 || ioc.cpes.length > 0 || ioc.country_code || ioc.epss_score != null;

  return (
    <div className={cn("rounded-lg border transition-colors", expanded ? "border-primary/30 bg-primary/[0.02]" : "border-border/30 hover:border-border/50")}>
      {/* Main row */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-3 py-2.5 text-left"
      >
        {/* Risk score */}
        <div className={cn("flex items-center justify-center h-9 w-11 rounded-md text-xs font-bold shrink-0", riskBgClass, riskColor)}>
          {ioc.risk_score}
        </div>

        {/* IOC value & type */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <Badge
              variant="secondary"
              className="text-[9px] px-1.5 py-0 h-4 shrink-0"
              style={{
                background: (IOC_TYPE_COLORS[ioc.ioc_type] || "#6b7280") + "18",
                color: IOC_TYPE_COLORS[ioc.ioc_type] || "#6b7280",
              }}
            >
              {ioc.ioc_type}
            </Badge>
            <span className="font-mono text-[11px] truncate">{ioc.value}</span>
          </div>
          <div className="flex items-center gap-3 mt-0.5 text-[10px] text-muted-foreground">
            {ioc.source_names.length > 0 && <span>{ioc.source_names.join(", ")}</span>}
            <span>×{ioc.sighting_count} sightings</span>
            {ioc.country_code && (
              <span className="flex items-center gap-1">
                <img src={`https://flagcdn.com/16x12/${ioc.country_code.toLowerCase()}.png`} alt={ioc.country_code} className="h-2.5" onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }} />
                {ioc.country}
              </span>
            )}
            {ioc.vulns.length > 0 && (
              <span className="text-red-400 font-medium">{ioc.vulns.length} CVE{ioc.vulns.length > 1 ? "s" : ""}</span>
            )}
            {ioc.ports.length > 0 && (
              <span>{ioc.ports.length} port{ioc.ports.length > 1 ? "s" : ""}</span>
            )}
          </div>
        </div>

        {/* Actions */}
        <button onClick={(e) => { e.stopPropagation(); handleCopy(); }} className="p-1 rounded hover:bg-muted/40" title="Copy IOC value">
          {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5 text-muted-foreground/50" />}
        </button>
        <ChevronRight className={cn("h-4 w-4 text-muted-foreground/40 transition-transform", expanded && "rotate-90")} />
      </button>

      {/* Expanded detail */}
      {expanded && hasEnrichment && (
        <div className="px-3 pb-3 pt-1 space-y-3 border-t border-border/20">
          {/* Location & ASN */}
          {ioc.country_code && (
            <div className="rounded-md bg-muted/10 border border-border/20 p-2.5 space-y-1">
              <p className="text-[10px] font-semibold text-muted-foreground flex items-center gap-1">
                <Globe className="h-3 w-3" /> Geolocation & Network
              </p>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-muted-foreground">Country: </span>
                  <span className="font-medium">{ioc.country} ({ioc.country_code})</span>
                </div>
                {ioc.asn && (
                  <div>
                    <span className="text-muted-foreground">ASN: </span>
                    <span className="font-medium">{ioc.asn}</span>
                  </div>
                )}
                {ioc.as_name && (
                  <div className="col-span-2">
                    <span className="text-muted-foreground">Network: </span>
                    <span className="font-medium">{ioc.as_name}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* InternetDB: Ports */}
          {ioc.ports.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold text-muted-foreground mb-1 flex items-center gap-1">
                <Network className="h-3 w-3" /> Open Ports ({ioc.ports.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {ioc.ports.sort((a, b) => a - b).map(p => (
                  <Badge key={p} variant="outline" className="text-[9px] font-mono">{p}</Badge>
                ))}
              </div>
            </div>
          )}

          {/* InternetDB: Vulnerabilities */}
          {ioc.vulns.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold text-red-400 mb-1 flex items-center gap-1">
                <Bug className="h-3 w-3" /> Vulnerabilities ({ioc.vulns.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {ioc.vulns.map(v => (
                  <a key={v} href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" rel="noopener noreferrer">
                    <Badge variant="destructive" className="text-[9px] hover:opacity-80">{v}</Badge>
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* InternetDB: CPEs */}
          {ioc.cpes.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold text-muted-foreground mb-1 flex items-center gap-1">
                <Server className="h-3 w-3" /> Technologies ({ioc.cpes.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {ioc.cpes.map((cpe, i) => {
                  const parts = cpe.split(":");
                  const display = parts.length >= 5 ? `${parts[3]} ${parts[4]}` : cpe;
                  return (
                    <Badge key={i} variant="secondary" className="text-[9px]">{display}</Badge>
                  );
                })}
              </div>
            </div>
          )}

          {/* InternetDB: Hostnames */}
          {ioc.hostnames.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold text-muted-foreground mb-1">Hostnames</p>
              <div className="text-[11px] text-muted-foreground font-mono space-y-0.5">
                {ioc.hostnames.map(h => <div key={h}>{h}</div>)}
              </div>
            </div>
          )}

          {/* EPSS Score */}
          {ioc.epss_score != null && (
            <div className="rounded-md bg-purple-500/5 border border-purple-500/20 p-2.5">
              <p className="text-[10px] font-semibold text-purple-300 mb-1 flex items-center gap-1">
                <BarChart3 className="h-3 w-3" /> EPSS Score
              </p>
              <div className="flex items-center gap-4 text-xs">
                <div>
                  <span className="text-muted-foreground">Probability: </span>
                  <span className="font-bold text-purple-400">{(ioc.epss_score * 100).toFixed(2)}%</span>
                </div>
                {ioc.epss_percentile != null && (
                  <div>
                    <span className="text-muted-foreground">Percentile: </span>
                    <span className="font-bold">{(ioc.epss_percentile * 100).toFixed(1)}%</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tags */}
          {(ioc.tags.length > 0 || ioc.internetdb_tags.length > 0) && (
            <div className="flex flex-wrap gap-1">
              {ioc.tags.map(t => (
                <Badge key={t} variant="outline" className="text-[9px]">{t}</Badge>
              ))}
              {ioc.internetdb_tags.map(t => (
                <Badge key={`idb-${t}`} variant="secondary" className="text-[9px]">{t}</Badge>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
