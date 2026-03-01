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
} from "lucide-react";
import type {
  IntelAttackLink,
  RelatedIntelItem,
  IntelEnrichment,
  RelatedIntelItemEnriched,
} from "@/types";
import * as api from "@/lib/api";
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

          {/* Threat Actors */}
          {enrichment && enrichment.threat_actors.length > 0 && (
            <Card className="border-red-500/20">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Users className="h-4 w-4 text-red-400" /> Associated Threat Actors
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {enrichment.threat_actors.map((ta, i) => (
                  <div key={i} className="flex items-start gap-3 rounded-md border border-border/30 px-3 py-2">
                    <div className="h-8 w-8 rounded-full bg-red-500/10 flex items-center justify-center shrink-0 mt-0.5">
                      <Users className="h-4 w-4 text-red-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold">{ta.name}</span>
                        <Badge variant="outline" className="text-[9px] capitalize">
                          {ta.motivation}
                        </Badge>
                        <Badge variant="secondary" className="text-[9px]">
                          {ta.confidence} confidence
                        </Badge>
                      </div>
                      {ta.aliases.length > 0 && (
                        <p className="text-xs text-muted-foreground mt-0.5">
                          AKA: {ta.aliases.join(", ")}
                        </p>
                      )}
                      <p className="text-xs text-muted-foreground mt-1">{ta.description}</p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Notable Campaigns / Breaches */}
          {enrichment && enrichment.notable_campaigns.length > 0 && (
            <Card className="border-orange-500/20">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Flame className="h-4 w-4 text-orange-400" /> Notable Campaigns & Breaches
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {enrichment.notable_campaigns.map((c, i) => (
                  <div key={i} className="rounded-md border border-border/30 px-3 py-2">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{c.name}</span>
                      <Badge variant="outline" className="text-[9px]">{c.date}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{c.description}</p>
                    {c.impact && (
                      <p className="text-xs mt-1">
                        <span className="text-muted-foreground">Impact: </span>
                        <span className="text-orange-400">{c.impact}</span>
                      </p>
                    )}
                  </div>
                ))}
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
        <TabsContent value="timeline" className="mt-4">
          <Card>
            <CardContent className="py-8">
              <div className="relative border-l-2 border-muted pl-6 space-y-6 ml-4">
                {enrichment && enrichment.timeline_events.length > 0 && (
                  <>
                    {enrichment.timeline_events
                      .filter((e) => e.date)
                      .sort((a, b) => {
                        const da = new Date(a.date!).getTime();
                        const db = new Date(b.date!).getTime();
                        return da - db;
                      })
                      .map((evt, i) => (
                        <TimelineEvent
                          key={`enr-${i}`}
                          date={evt.date!}
                          title={evt.event}
                          description={evt.description}
                          type={evt.type}
                        />
                      ))}
                  </>
                )}

                {item.published_at && (
                  <TimelineEvent
                    date={item.published_at}
                    title="Published"
                    description={`Published by ${item.source_name}`}
                    type="publication"
                  />
                )}
                <TimelineEvent
                  date={item.ingested_at}
                  title="Ingested by IntelWatch"
                  description="First seen by TI Platform"
                  type="update"
                />
                {item.ai_summary_at && (
                  <TimelineEvent
                    date={item.ai_summary_at}
                    title="AI Summary Generated"
                    description="Analyzed by AI model"
                    type="update"
                  />
                )}
                <TimelineEvent
                  date={item.updated_at ?? ""}
                  title="Last Updated"
                  description="Most recent update"
                  type="update"
                />

                {enrichment && enrichment.timeline_events
                  .filter((e) => !e.date)
                  .map((evt, i) => (
                    <TimelineEvent
                      key={`nodate-${i}`}
                      date=""
                      title={evt.event}
                      description={evt.description}
                      type={evt.type}
                    />
                  ))}
              </div>

              {enrichmentLoading && (
                <div className="mt-4 flex items-center justify-center gap-2 text-sm text-muted-foreground">
                  <div className="h-4 w-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  Loading CVE timeline...
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

const timelineTypeColors: Record<string, string> = {
  disclosure: "border-yellow-500 bg-yellow-500",
  publication: "border-blue-500 bg-blue-500",
  patch: "border-green-500 bg-green-500",
  exploit: "border-red-500 bg-red-500",
  kev: "border-red-600 bg-red-600",
  advisory: "border-cyan-500 bg-cyan-500",
  update: "border-primary bg-primary",
};

function TimelineEvent({
  date,
  title,
  description,
  type = "update",
}: {
  date: string;
  title: string;
  description: string;
  type?: string;
}) {
  const dotColor = timelineTypeColors[type] || "border-primary bg-background";
  const isFilled = type !== "update";

  return (
    <div className="relative">
      <div
        className={cn(
          "absolute -left-[29px] top-1 h-3 w-3 rounded-full border-2",
          isFilled ? dotColor : "border-primary bg-background"
        )}
      />
      <div>
        <div className="flex items-center gap-2">
          <p className="text-sm font-medium">{title}</p>
          {type && type !== "update" && (
            <Badge variant="outline" className="text-[8px] capitalize px-1 py-0">
              {type}
            </Badge>
          )}
        </div>
        <p className="text-xs text-muted-foreground">{description}</p>
        {date && (
          <p className="text-xs text-muted-foreground mt-0.5">{formatDate(date)}</p>
        )}
      </div>
    </div>
  );
}
